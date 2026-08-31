package caddywaf

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestPrefixUsageRollingWindowsAndRetry(t *testing.T) {
	usage := new(prefixUsage)
	usage.add(100, 4)
	usage.add(110, 6)
	usage.add(120, 10)

	window := quotaWindow{duration: 20 * time.Second, limit: 10, label: "20s"}
	used, retry, blocked := usage.retryAfter(120, window)
	if !blocked || used != 16 || retry != 20*time.Second {
		t.Fatalf("at t=120 got used=%d retry=%s blocked=%v", used, retry, blocked)
	}

	used, retry, blocked = usage.retryAfter(130, window)
	if !blocked || used != 10 || retry != 10*time.Second {
		t.Fatalf("at t=130 got used=%d retry=%s blocked=%v", used, retry, blocked)
	}

	used, retry, blocked = usage.retryAfter(140, window)
	if blocked || used != 0 || retry != 0 {
		t.Fatalf("at t=140 got used=%d retry=%s blocked=%v", used, retry, blocked)
	}
}

func TestLongestRetryCoversEveryViolatedWindow(t *testing.T) {
	violations := []violation{
		{retry: 5 * time.Hour},
		{retry: 7 * 24 * time.Hour},
		{retry: 30 * 24 * time.Hour},
	}
	if got := longestRetry(violations); got != 30*24*time.Hour {
		t.Fatalf("longest retry = %s", got)
	}
}

func TestPrefixUsagePruneRebasesCumulativeTotals(t *testing.T) {
	usage := new(prefixUsage)
	usage.add(100, 100)
	usage.add(200, 5)
	usage.add(300, 7)
	usage.prune(100)
	used, _ := usage.usageSince(0)
	if used != 12 {
		t.Fatalf("usage after prune = %d, want 12", used)
	}
}

func TestUsageManagerPersistsSecondBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.db")
	now := time.Now().Truncate(time.Second)
	manager := newUsageManager(path, minimumRetention, zap.NewNop())
	manager.mu.Lock()
	manager.lastNow = now.Unix()
	manager.now = func() time.Time { return now }
	manager.mu.Unlock()
	manager.record("192.0.2.0/24", 7)
	manager.record("192.0.2.0/24", 5)
	manager.close()

	reloaded := newUsageManager(path, minimumRetention, zap.NewNop())
	reloaded.mu.Lock()
	reloaded.lastNow = now.Unix()
	reloaded.now = func() time.Time { return now }
	reloaded.mu.Unlock()
	violations := reloaded.check("192.0.2.0/24", []quotaWindow{{
		duration: time.Hour,
		limit:    12,
		label:    "1h",
	}})
	if len(violations) != 1 || violations[0].used != 12 {
		t.Fatalf("reloaded violations = %#v", violations)
	}
	reloaded.close()
}

func TestUsageManagerFailsOpenWithoutPersistentState(t *testing.T) {
	manager := newUsageManager("/proc/caddy-quota/state.db", minimumRetention, zap.NewNop())
	if manager.persistent || manager.db != nil {
		t.Fatal("manager unexpectedly opened persistent state")
	}
	manager.record("2001:db8::/64", 10)
	violations := manager.check("2001:db8::/64", []quotaWindow{{
		duration: time.Hour,
		limit:    10,
		label:    "1h",
	}})
	if len(violations) != 1 {
		t.Fatalf("in-memory enforcement did not work: %#v", violations)
	}
	manager.close()
}
