// BandwidthQuota implements persistent rolling download-byte quotas for Caddy.
package caddywaf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const accountingChunkSize = 1 << 20

func init() {
	caddy.RegisterModule(new(BandwidthQuota))
	httpcaddyfile.RegisterHandlerDirective("bandwidth_quota", parseBandwidthQuotaCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("bandwidth_quota", httpcaddyfile.Before, "encode")
}

// BandwidthQuotaWindow configures one rolling downloaded-byte quota.
type BandwidthQuotaWindow struct {
	Duration caddy.Duration `json:"duration"`
	Bytes    uint64         `json:"bytes"`
}

// BandwidthQuota enforces rolling downloaded-byte quotas for repository requests.
type BandwidthQuota struct {
	StatePath     string                 `json:"state_path"`
	WhitelistFile string                 `json:"whitelist_file,omitempty"`
	IPv4Prefix    int                    `json:"ipv4_prefix"`
	IPv6Prefix    int                    `json:"ipv6_prefix"`
	Windows       []BandwidthQuotaWindow `json:"windows"`

	manager       *usageManager
	windows       []quotaWindow
	whitelist     []netip.Prefix
	logger        *zap.Logger
	metrics       quotaMetrics
	registryPath  string
	logMu         sync.Mutex
	lastBlockLogs map[string]time.Time
}

var (
	_ caddy.Module                = (*BandwidthQuota)(nil)
	_ caddy.Provisioner           = (*BandwidthQuota)(nil)
	_ caddy.Validator             = (*BandwidthQuota)(nil)
	_ caddy.CleanerUpper          = (*BandwidthQuota)(nil)
	_ caddyfile.Unmarshaler       = (*BandwidthQuota)(nil)
	_ caddyhttp.MiddlewareHandler = (*BandwidthQuota)(nil)
)

// CaddyModule returns the Caddy module information.
func (*BandwidthQuota) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.bandwidth_quota",
		New: func() caddy.Module { return new(BandwidthQuota) },
	}
}

func parseBandwidthQuotaCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(BandwidthQuota)
	if err := handler.UnmarshalCaddyfile(helper.Dispenser); err != nil {
		return nil, err
	}
	return handler, nil
}

// UnmarshalCaddyfile parses a bandwidth_quota block.
func (h *BandwidthQuota) UnmarshalCaddyfile(dispenser *caddyfile.Dispenser) error {
	dispenser.Next()
	if dispenser.NextArg() {
		return dispenser.ArgErr()
	}
	for nesting := dispenser.Nesting(); dispenser.NextBlock(nesting); {
		switch dispenser.Val() {
		case "state_path":
			if !dispenser.NextArg() {
				return dispenser.ArgErr()
			}
			h.StatePath = dispenser.Val()
			if dispenser.NextArg() {
				return dispenser.ArgErr()
			}
		case "whitelist_file":
			if !dispenser.NextArg() {
				return dispenser.ArgErr()
			}
			h.WhitelistFile = dispenser.Val()
			if dispenser.NextArg() {
				return dispenser.ArgErr()
			}
		case "ipv4_prefix":
			value, err := parseIntegerArgument(dispenser)
			if err != nil {
				return err
			}
			h.IPv4Prefix = value
		case "ipv6_prefix":
			value, err := parseIntegerArgument(dispenser)
			if err != nil {
				return err
			}
			h.IPv6Prefix = value
		case "window":
			arguments := dispenser.RemainingArgs()
			if len(arguments) != 2 {
				return dispenser.Err("window requires a duration and byte limit")
			}
			duration, err := time.ParseDuration(arguments[0])
			if err != nil {
				return dispenser.Errf("invalid window duration %q: %v", arguments[0], err)
			}
			bytes, err := humanize.ParseBytes(arguments[1])
			if err != nil {
				return dispenser.Errf("invalid window byte limit %q: %v", arguments[1], err)
			}
			h.Windows = append(h.Windows, BandwidthQuotaWindow{Duration: caddy.Duration(duration), Bytes: bytes})
		default:
			return dispenser.Errf("unrecognized bandwidth_quota option: %s", dispenser.Val())
		}
	}
	return nil
}

func parseIntegerArgument(dispenser *caddyfile.Dispenser) (int, error) {
	if !dispenser.NextArg() {
		return 0, dispenser.ArgErr()
	}
	value, err := strconv.Atoi(dispenser.Val())
	if err != nil {
		return 0, dispenser.Errf("invalid integer %q: %v", dispenser.Val(), err)
	}
	if dispenser.NextArg() {
		return 0, dispenser.ArgErr()
	}
	return value, nil
}

// Validate validates quota configuration without opening persistent state.
func (h *BandwidthQuota) Validate() error {
	if h.StatePath == "" {
		return errors.New("bandwidth_quota state_path is required")
	}
	if h.IPv4Prefix < 0 || h.IPv4Prefix > 32 {
		return fmt.Errorf("bandwidth_quota ipv4_prefix must be between 0 and 32, got %d", h.IPv4Prefix)
	}
	if h.IPv6Prefix < 0 || h.IPv6Prefix > 128 {
		return fmt.Errorf("bandwidth_quota ipv6_prefix must be between 0 and 128, got %d", h.IPv6Prefix)
	}
	if len(h.Windows) == 0 {
		return errors.New("bandwidth_quota requires at least one window")
	}
	seenDurations := make(map[time.Duration]struct{}, len(h.Windows))
	for _, window := range h.Windows {
		duration := time.Duration(window.Duration)
		if duration <= 0 || duration%time.Second != 0 {
			return fmt.Errorf("bandwidth_quota window duration must be a positive whole number of seconds, got %s", duration)
		}
		if duration > minimumRetention {
			return fmt.Errorf("bandwidth_quota window duration must not exceed %s, got %s", minimumRetention, duration)
		}
		if window.Bytes == 0 {
			return errors.New("bandwidth_quota window byte limit must be positive")
		}
		if _, duplicate := seenDurations[duration]; duplicate {
			return fmt.Errorf("bandwidth_quota window duration %s is duplicated", duration)
		}
		seenDurations[duration] = struct{}{}
	}
	return nil
}

// Provision loads exemptions and acquires the process-local shared usage manager.
func (h *BandwidthQuota) Provision(context caddy.Context) error {
	h.logger = context.Logger(h)
	if err := h.Validate(); err != nil {
		return err
	}
	statePath, err := filepath.Abs(h.StatePath)
	if err != nil {
		return fmt.Errorf("resolve bandwidth quota state path: %w", err)
	}
	h.registryPath = statePath

	if h.WhitelistFile != "" {
		h.whitelist, err = loadWhitelist(h.WhitelistFile)
		if err != nil {
			return err
		}
	}

	h.windows = make([]quotaWindow, 0, len(h.Windows))
	retention := time.Duration(0)
	for _, configured := range h.Windows {
		duration := time.Duration(configured.Duration)
		if duration > retention {
			retention = duration
		}
		h.windows = append(h.windows, quotaWindow{
			duration: duration,
			limit:    configured.Bytes,
			label:    duration.String(),
		})
	}
	h.manager = acquireManager(statePath, retention, h.logger)
	h.metrics, err = registerMetrics(context.GetMetricsRegistry())
	if err != nil {
		releaseManager(h.registryPath, h.manager)
		h.manager = nil
		return err
	}
	h.lastBlockLogs = make(map[string]time.Time)
	h.logger.Info(
		"bandwidth quota enabled",
		zap.String("state_path", statePath),
		zap.Bool("persistent", h.manager.persistent),
		zap.Int("ipv4_prefix", h.IPv4Prefix),
		zap.Int("ipv6_prefix", h.IPv6Prefix),
		zap.Int("windows", len(h.windows)),
		zap.Int("whitelist_entries", len(h.whitelist)),
	)
	return nil
}

// Cleanup releases the shared usage manager.
func (h *BandwidthQuota) Cleanup() error {
	if h.manager != nil {
		releaseManager(h.registryPath, h.manager)
		h.manager = nil
	}
	return nil
}

// ServeHTTP enforces quota before forwarding and accounts successful bytes as they stream.
func (h *BandwidthQuota) ServeHTTP(writer http.ResponseWriter, request *http.Request, next caddyhttp.Handler) error {
	manager := h.manager
	if request.Method != http.MethodGet || manager == nil {
		return next.ServeHTTP(writer, request)
	}
	address, err := remoteAddress(request.RemoteAddr)
	if err != nil {
		h.logger.Warn("bandwidth quota skipped request with invalid remote address", zap.String("remote_addr", request.RemoteAddr), zap.Error(err))
		return next.ServeHTTP(writer, request)
	}
	if h.isWhitelisted(address) {
		return next.ServeHTTP(writer, request)
	}
	prefix := h.clientPrefix(address)
	prefixKey := prefix.String()
	violations := manager.check(prefixKey, h.windows)
	if len(violations) > 0 {
		retry := longestRetry(violations)
		writer.Header().Set("Cache-Control", "private, no-store")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Retry-After", strconv.FormatInt(int64(retry/time.Second), 10))
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(writer, "download quota exceeded; retry later\n")
		h.metrics.blocked.Inc()
		h.logBlock(prefixKey, violations, retry)
		return nil
	}

	accounting := &accountingResponseWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: writer},
		record: func(bytes uint64) {
			manager.record(prefixKey, bytes)
			h.metrics.countedBytes.Add(float64(bytes))
		},
	}
	err = next.ServeHTTP(accounting, request)
	accounting.flushAccount()
	return err
}

func (h *BandwidthQuota) clientPrefix(address netip.Addr) netip.Prefix {
	address = address.Unmap()
	bits := h.IPv6Prefix
	if address.Is4() {
		bits = h.IPv4Prefix
	}
	return netip.PrefixFrom(address, bits).Masked()
}

func (h *BandwidthQuota) isWhitelisted(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range h.whitelist {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (h *BandwidthQuota) logBlock(prefix string, violations []violation, retry time.Duration) {
	now := time.Now()
	h.logMu.Lock()
	last := h.lastBlockLogs[prefix]
	if now.Sub(last) < time.Minute {
		h.logMu.Unlock()
		return
	}
	h.lastBlockLogs[prefix] = now
	h.logMu.Unlock()

	fields := []zap.Field{
		zap.String("client_prefix", prefix),
		zap.Duration("retry_after", retry),
	}
	for _, item := range violations {
		field := strings.ReplaceAll(item.window.label, ".", "_")
		fields = append(
			fields,
			zap.Uint64("used_bytes_"+field, item.used),
			zap.Uint64("limit_bytes_"+field, item.window.limit),
		)
	}
	h.logger.Warn("repository download quota exceeded", fields...)
}

func remoteAddress(remote string) (netip.Addr, error) {
	if addressPort, err := netip.ParseAddrPort(remote); err == nil {
		return addressPort.Addr().Unmap(), nil
	}
	address, err := netip.ParseAddr(strings.Trim(remote, "[]"))
	if err != nil {
		return netip.Addr{}, err
	}
	return address.Unmap(), nil
}

func loadWhitelist(path string) ([]netip.Prefix, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bandwidth quota whitelist %q: %w", path, err)
	}
	var prefixes []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for number, raw := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			address, addressErr := netip.ParseAddr(line)
			if addressErr != nil {
				return nil, fmt.Errorf("parse bandwidth quota whitelist %s:%d: %w", path, number+1, err)
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		} else if prefix.Addr().Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				return nil, fmt.Errorf("parse bandwidth quota whitelist %s:%d: mapped IPv4 prefix is broader than /96", path, number+1)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		}
		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func longestRetry(violations []violation) time.Duration {
	longest := time.Second
	for _, item := range violations {
		if item.retry > longest {
			longest = item.retry
		}
	}
	return longest
}

type accountingResponseWriter struct {
	*caddyhttp.ResponseWriterWrapper
	status      int
	wroteHeader bool
	record      func(uint64)
	pending     uint64
}

func (writer *accountingResponseWriter) WriteHeader(status int) {
	if status >= 100 && status <= 199 && status != http.StatusSwitchingProtocols {
		writer.ResponseWriterWrapper.WriteHeader(status)
		return
	}
	if writer.wroteHeader {
		return
	}
	writer.status = status
	writer.wroteHeader = true
	writer.ResponseWriterWrapper.WriteHeader(status)
}

func (writer *accountingResponseWriter) Write(contents []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	written, err := writer.ResponseWriterWrapper.Write(contents)
	writer.account(written)
	return written, err
}

func (writer *accountingResponseWriter) ReadFrom(source io.Reader) (int64, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	var total int64
	for {
		limited := &io.LimitedReader{R: source, N: accountingChunkSize}
		written, err := writer.ResponseWriterWrapper.ReadFrom(limited)
		total += written
		writer.account(int(written))
		if err != nil {
			return total, err
		}
		if limited.N > 0 {
			return total, nil
		}
		if written == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func (writer *accountingResponseWriter) Flush() {
	_ = writer.FlushError()
}

func (writer *accountingResponseWriter) FlushError() error {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(writer.ResponseWriterWrapper).Flush()
}

func (writer *accountingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(writer.ResponseWriterWrapper).Hijack()
}

func (writer *accountingResponseWriter) account(written int) {
	if written <= 0 || writer.status < 200 || writer.status >= 300 {
		return
	}
	writer.pending = saturatingAdd(writer.pending, uint64(written))
	if writer.pending >= accountingChunkSize {
		writer.record(writer.pending)
		writer.pending = 0
	}
}

func (writer *accountingResponseWriter) flushAccount() {
	if writer.pending > 0 {
		writer.record(writer.pending)
		writer.pending = 0
	}
}

type quotaMetrics struct {
	countedBytes prometheus.Counter
	blocked      prometheus.Counter
}

func registerMetrics(registry *prometheus.Registry) (quotaMetrics, error) {
	if registry == nil {
		return quotaMetrics{}, errors.New("bandwidth quota metrics registry is unavailable")
	}
	countedBytes, err := registerCounter(registry, prometheus.CounterOpts{
		Namespace: "caddy",
		Subsystem: "bandwidth_quota",
		Name:      "counted_bytes_total",
		Help:      "Successful repository GET response bytes counted toward bandwidth quotas.",
	})
	if err != nil {
		return quotaMetrics{}, err
	}
	blocked, err := registerCounter(registry, prometheus.CounterOpts{
		Namespace: "caddy",
		Subsystem: "bandwidth_quota",
		Name:      "blocked_requests_total",
		Help:      "Repository GET requests rejected because a bandwidth quota was exhausted.",
	})
	if err != nil {
		return quotaMetrics{}, err
	}
	return quotaMetrics{countedBytes: countedBytes, blocked: blocked}, nil
}

func registerCounter(registry *prometheus.Registry, options prometheus.CounterOpts) (prometheus.Counter, error) {
	counter := prometheus.NewCounter(options)
	if err := registry.Register(counter); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Counter)
			if !ok {
				return nil, fmt.Errorf("metric %s already registered with incompatible type", options.Name)
			}
			return existing, nil
		}
		return nil, fmt.Errorf("register bandwidth quota metric %s: %w", options.Name, err)
	}
	return counter, nil
}
