package caddywaf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"go.uber.org/zap"
)

const (
	flushInterval      = time.Second
	pruneInterval      = 10 * time.Minute
	minimumRetention   = 30 * 24 * time.Hour
	persistenceTimeout = time.Second
)

var usageBucketName = []byte("usage-v1")

type quotaWindow struct {
	duration time.Duration
	limit    uint64
	label    string
}

type violation struct {
	window quotaWindow
	used   uint64
	retry  time.Duration
}

type usageBucket struct {
	second     int64
	bytes      uint64
	cumulative uint64
}

type prefixUsage struct {
	buckets []usageBucket
}

func (u *prefixUsage) add(second int64, amount uint64) uint64 {
	if len(u.buckets) == 0 || second > u.buckets[len(u.buckets)-1].second {
		cumulative := amount
		if len(u.buckets) > 0 {
			cumulative = saturatingAdd(u.buckets[len(u.buckets)-1].cumulative, amount)
		}
		u.buckets = append(u.buckets, usageBucket{second: second, bytes: amount, cumulative: cumulative})
		return amount
	}

	if second == u.buckets[len(u.buckets)-1].second {
		last := &u.buckets[len(u.buckets)-1]
		last.bytes = saturatingAdd(last.bytes, amount)
		last.cumulative = saturatingAdd(last.cumulative, amount)
		return last.bytes
	}

	index := sort.Search(len(u.buckets), func(i int) bool {
		return u.buckets[i].second >= second
	})
	if index < len(u.buckets) && u.buckets[index].second == second {
		u.buckets[index].bytes = saturatingAdd(u.buckets[index].bytes, amount)
	} else {
		u.buckets = append(u.buckets, usageBucket{})
		copy(u.buckets[index+1:], u.buckets[index:])
		u.buckets[index] = usageBucket{second: second, bytes: amount}
	}
	u.rebuildCumulative(index)
	return u.buckets[index].bytes
}

func (u *prefixUsage) rebuildCumulative(start int) {
	var cumulative uint64
	if start > 0 {
		cumulative = u.buckets[start-1].cumulative
	}
	for i := start; i < len(u.buckets); i++ {
		cumulative = saturatingAdd(cumulative, u.buckets[i].bytes)
		u.buckets[i].cumulative = cumulative
	}
}

func (u *prefixUsage) usageSince(cutoff int64) (uint64, int) {
	start := sort.Search(len(u.buckets), func(i int) bool {
		return u.buckets[i].second > cutoff
	})
	if start == len(u.buckets) {
		return 0, start
	}
	before := uint64(0)
	if start > 0 {
		before = u.buckets[start-1].cumulative
	}
	return u.buckets[len(u.buckets)-1].cumulative - before, start
}

func (u *prefixUsage) retryAfter(now int64, window quotaWindow) (uint64, time.Duration, bool) {
	durationSeconds := int64(window.duration / time.Second)
	used, start := u.usageSince(now - durationSeconds)
	if used < window.limit {
		return used, 0, false
	}

	before := uint64(0)
	if start > 0 {
		before = u.buckets[start-1].cumulative
	}
	needToExpire := used - window.limit + 1
	target := saturatingAdd(before, needToExpire)
	index := sort.Search(len(u.buckets)-start, func(i int) bool {
		return u.buckets[start+i].cumulative >= target
	}) + start
	if index >= len(u.buckets) {
		return used, time.Second, true
	}

	retrySeconds := u.buckets[index].second + durationSeconds - now
	if retrySeconds < 1 {
		retrySeconds = 1
	}
	return used, time.Duration(retrySeconds) * time.Second, true
}

func (u *prefixUsage) prune(cutoff int64) []int64 {
	end := sort.Search(len(u.buckets), func(i int) bool {
		return u.buckets[i].second > cutoff
	})
	if end == 0 {
		return nil
	}
	removed := make([]int64, end)
	for i := range end {
		removed[i] = u.buckets[i].second
	}
	copy(u.buckets, u.buckets[end:])
	u.buckets = u.buckets[:len(u.buckets)-end]
	u.rebuildCumulative(0)
	return removed
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

type usageManager struct {
	mu        sync.Mutex
	usage     map[string]*prefixUsage
	dirty     map[string]uint64
	deletions map[string]struct{}
	retention time.Duration
	lastNow   int64
	now       func() time.Time

	db                   *bolt.DB
	persistent           bool
	logger               *zap.Logger
	lastPersistenceError time.Time
	stop                 chan struct{}
	done                 chan struct{}
}

func newUsageManager(path string, retention time.Duration, logger *zap.Logger) *usageManager {
	if retention < minimumRetention {
		retention = minimumRetention
	}
	manager := &usageManager{
		usage:     make(map[string]*prefixUsage),
		dirty:     make(map[string]uint64),
		deletions: make(map[string]struct{}),
		retention: retention,
		lastNow:   time.Now().Unix(),
		now:       time.Now,
		logger:    logger,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}

	if err := manager.open(path); err != nil {
		logger.Error(
			"bandwidth quota persistence unavailable; using fresh in-memory state",
			zap.String("path", path),
			zap.Error(err),
		)
	}
	go manager.run()
	return manager
}

func (m *usageManager) open(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: persistenceTimeout})
	if err != nil {
		return fmt.Errorf("open state database: %w", err)
	}
	m.db = db
	if err := db.Update(func(tx *bolt.Tx) error {
		_, createErr := tx.CreateBucketIfNotExists(usageBucketName)
		return createErr
	}); err != nil {
		_ = db.Close()
		m.db = nil
		return fmt.Errorf("initialize state database: %w", err)
	}
	if err := m.load(); err != nil {
		_ = db.Close()
		m.db = nil
		m.usage = make(map[string]*prefixUsage)
		m.dirty = make(map[string]uint64)
		m.deletions = make(map[string]struct{})
		return fmt.Errorf("load state database: %w", err)
	}
	m.persistent = true
	m.logger.Info("bandwidth quota state loaded", zap.String("path", path), zap.Int("prefixes", len(m.usage)))
	return nil
}

func (m *usageManager) load() error {
	now := m.lastNow
	cutoff := now - int64(m.retention/time.Second)
	return m.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(usageBucketName)
		if bucket == nil {
			return errors.New("usage bucket is missing")
		}
		return bucket.ForEach(func(key, value []byte) error {
			prefix, second, err := decodeKey(key)
			if err != nil {
				return err
			}
			if len(value) != 8 {
				return fmt.Errorf("invalid usage value for %q", prefix)
			}
			if second <= cutoff {
				m.deletions[string(key)] = struct{}{}
				return nil
			}
			originalSecond := second
			if second > now {
				second = now
			}
			amount := binary.BigEndian.Uint64(value)
			state := m.usage[prefix]
			if state == nil {
				state = new(prefixUsage)
				m.usage[prefix] = state
			}
			bucketTotal := state.add(second, amount)
			if originalSecond != second {
				m.deletions[string(key)] = struct{}{}
				m.dirty[string(encodeKey(prefix, second))] = bucketTotal
			}
			return nil
		})
	})
}

func (m *usageManager) currentSecondLocked() int64 {
	now := m.now().Unix()
	if now < m.lastNow {
		return m.lastNow
	}
	m.lastNow = now
	return now
}

func (m *usageManager) record(prefix string, amount uint64) {
	if amount == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	second := m.currentSecondLocked()
	state := m.usage[prefix]
	if state == nil {
		state = new(prefixUsage)
		m.usage[prefix] = state
	}
	bucketTotal := state.add(second, amount)
	key := string(encodeKey(prefix, second))
	m.dirty[key] = bucketTotal
	delete(m.deletions, key)
}

func (m *usageManager) check(prefix string, windows []quotaWindow) []violation {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.currentSecondLocked()
	state := m.usage[prefix]
	if state == nil {
		return nil
	}
	violations := make([]violation, 0, len(windows))
	for _, window := range windows {
		used, retry, exceeded := state.retryAfter(now, window)
		if exceeded {
			violations = append(violations, violation{window: window, used: used, retry: retry})
		}
	}
	return violations
}

func (m *usageManager) run() {
	defer close(m.done)
	flushTicker := time.NewTicker(flushInterval)
	pruneTicker := time.NewTicker(pruneInterval)
	defer flushTicker.Stop()
	defer pruneTicker.Stop()
	for {
		select {
		case <-flushTicker.C:
			m.flush()
		case <-pruneTicker.C:
			m.prune()
		case <-m.stop:
			m.prune()
			m.flush()
			return
		}
	}
}

func (m *usageManager) flush() {
	if m.db == nil {
		return
	}
	m.mu.Lock()
	dirty := make(map[string]uint64, len(m.dirty))
	for key, value := range m.dirty {
		dirty[key] = value
	}
	deletions := make(map[string]struct{}, len(m.deletions))
	for key := range m.deletions {
		deletions[key] = struct{}{}
	}
	m.mu.Unlock()
	if len(dirty) == 0 && len(deletions) == 0 {
		return
	}

	err := m.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(usageBucketName)
		if bucket == nil {
			return errors.New("usage bucket is missing")
		}
		for key := range deletions {
			if err := bucket.Delete([]byte(key)); err != nil {
				return err
			}
		}
		for key, value := range dirty {
			encoded := make([]byte, 8)
			binary.BigEndian.PutUint64(encoded, value)
			if err := bucket.Put([]byte(key), encoded); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		m.logPersistenceError(err)
		return
	}

	m.mu.Lock()
	for key, value := range dirty {
		if current, exists := m.dirty[key]; exists && current == value {
			delete(m.dirty, key)
		}
	}
	for key := range deletions {
		if _, stillDeleted := m.deletions[key]; stillDeleted {
			delete(m.deletions, key)
		}
	}
	m.mu.Unlock()
}

func (m *usageManager) logPersistenceError(err error) {
	now := time.Now()
	if now.Sub(m.lastPersistenceError) < time.Minute {
		return
	}
	m.lastPersistenceError = now
	m.logger.Error("failed to persist bandwidth quota state", zap.Error(err))
}

func (m *usageManager) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.currentSecondLocked()
	cutoff := now - int64(m.retention/time.Second)
	for prefix, state := range m.usage {
		for _, second := range state.prune(cutoff) {
			key := string(encodeKey(prefix, second))
			delete(m.dirty, key)
			m.deletions[key] = struct{}{}
		}
		if len(state.buckets) == 0 {
			delete(m.usage, prefix)
		}
	}
}

func (m *usageManager) close() {
	close(m.stop)
	<-m.done
	if m.db != nil {
		if err := m.db.Close(); err != nil {
			m.logger.Error("failed to close bandwidth quota state", zap.Error(err))
		}
	}
}

func encodeKey(prefix string, second int64) []byte {
	key := make([]byte, len(prefix)+1+8)
	copy(key, prefix)
	binary.BigEndian.PutUint64(key[len(prefix)+1:], uint64(second))
	return key
}

func decodeKey(key []byte) (string, int64, error) {
	if len(key) < 10 || key[len(key)-9] != 0 {
		return "", 0, errors.New("invalid usage key")
	}
	prefix := string(key[:len(key)-9])
	second := int64(binary.BigEndian.Uint64(key[len(key)-8:]))
	return prefix, second, nil
}

var managerRegistry = struct {
	sync.Mutex
	managers map[string]*managerReference
}{managers: make(map[string]*managerReference)}

type managerReference struct {
	manager *usageManager
	refs    int
}

func acquireManager(path string, retention time.Duration, logger *zap.Logger) *usageManager {
	managerRegistry.Lock()
	defer managerRegistry.Unlock()
	if reference := managerRegistry.managers[path]; reference != nil {
		reference.refs++
		reference.manager.mu.Lock()
		if retention > reference.manager.retention {
			reference.manager.retention = retention
		}
		reference.manager.mu.Unlock()
		return reference.manager
	}
	manager := newUsageManager(path, retention, logger)
	managerRegistry.managers[path] = &managerReference{manager: manager, refs: 1}
	return manager
}

func releaseManager(path string, manager *usageManager) {
	managerRegistry.Lock()
	defer managerRegistry.Unlock()
	reference := managerRegistry.managers[path]
	if reference == nil || reference.manager != manager {
		return
	}
	reference.refs--
	if reference.refs == 0 {
		manager.close()
		delete(managerRegistry.managers, path)
	}
}
