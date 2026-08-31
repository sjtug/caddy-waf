package caddywaf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
bandwidth_quota {
 state_path /tmp/quota.db
 whitelist_file /tmp/whitelist.txt
 ipv4_prefix 24
 ipv6_prefix 64
 window 5h 10GiB
 window 168h 200GiB
 window 720h 500GiB
}
`)
	handler := new(BandwidthQuota)
	if err := handler.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatal(err)
	}
	if err := handler.Validate(); err != nil {
		t.Fatal(err)
	}
	if handler.IPv4Prefix != 24 || handler.IPv6Prefix != 64 || len(handler.Windows) != 3 {
		t.Fatalf("unexpected config: %#v", handler)
	}
	if handler.Windows[0].Bytes != 10*humanGiB {
		t.Fatalf("first byte limit = %d", handler.Windows[0].Bytes)
	}
}

const humanGiB = uint64(1024 * 1024 * 1024)

func TestValidateRejectsWindowBeyondPersistentRetention(t *testing.T) {
	handler := BandwidthQuota{
		StatePath:  "/tmp/quota.db",
		IPv4Prefix: 24,
		IPv6Prefix: 64,
		Windows: []BandwidthQuotaWindow{{
			Duration: caddy.Duration(31 * 24 * time.Hour),
			Bytes:    1,
		}},
	}
	if err := handler.Validate(); err == nil {
		t.Fatal("31-day window unexpectedly validated")
	}
}

func TestClientPrefix(t *testing.T) {
	handler := BandwidthQuota{IPv4Prefix: 24, IPv6Prefix: 64}
	ipv4, _ := remoteAddress("192.0.2.129:443")
	if got := handler.clientPrefix(ipv4).String(); got != "192.0.2.0/24" {
		t.Fatalf("IPv4 prefix = %s", got)
	}
	ipv6, _ := remoteAddress("[2001:db8:abcd:1234::99]:443")
	if got := handler.clientPrefix(ipv6).String(); got != "2001:db8:abcd:1234::/64" {
		t.Fatalf("IPv6 prefix = %s", got)
	}
}

func TestWhitelist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	contents := "# trusted NAT\n192.0.2.0/24\n2001:db8::1\n"
	if err := osWriteFile(path, contents); err != nil {
		t.Fatal(err)
	}
	prefixes, err := loadWhitelist(path)
	if err != nil {
		t.Fatal(err)
	}
	handler := BandwidthQuota{whitelist: prefixes}
	address, _ := remoteAddress("192.0.2.99:80")
	if !handler.isWhitelisted(address) {
		t.Fatal("IPv4 address was not exempt")
	}
	address, _ = remoteAddress("[2001:db8::1]:80")
	if !handler.isWhitelisted(address) {
		t.Fatal("IPv6 host was not exempt")
	}
}

func osWriteFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}

func TestHandlerCountsSuccessfulBytesAndBlocksNextRequest(t *testing.T) {
	now := time.Unix(10_000, 0)
	manager := testUsageManager(now)
	handler := testHandler(manager, []quotaWindow{{duration: time.Hour, limit: 10, label: "1h"}})

	first := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://mirror.test/repo/file", nil)
	request.RemoteAddr = "192.0.2.4:1234"
	err := handler.ServeHTTP(first, request, caddyhttp.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) error {
		writer.WriteHeader(http.StatusPartialContent)
		_, writeErr := io.WriteString(writer, "0123456789")
		return writeErr
	}))
	if err != nil || first.Code != http.StatusPartialContent {
		t.Fatalf("first response code=%d err=%v", first.Code, err)
	}

	second := httptest.NewRecorder()
	request.RemoteAddr = "192.0.2.250:5678" // Same configured /24 as the first request.
	err = handler.ServeHTTP(second, request, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("blocked request reached downstream handler")
		return nil
	}))
	if err != nil || second.Code != http.StatusTooManyRequests {
		t.Fatalf("second response code=%d err=%v", second.Code, err)
	}
	if second.Header().Get("Retry-After") != "3600" {
		t.Fatalf("Retry-After = %q", second.Header().Get("Retry-After"))
	}
	if second.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("Cache-Control = %q", second.Header().Get("Cache-Control"))
	}
}

func TestHandlerExemptsWhitelistedAddressFromGroupQuota(t *testing.T) {
	now := time.Unix(15_000, 0)
	manager := testUsageManager(now)
	handler := testHandler(manager, []quotaWindow{{duration: time.Hour, limit: 1, label: "1h"}})
	handler.whitelist = []netip.Prefix{netip.MustParsePrefix("192.0.2.99/32")}
	manager.record("192.0.2.0/24", 1)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://mirror.test/repo/file", nil)
	request.RemoteAddr = "192.0.2.99:1234"
	err := handler.ServeHTTP(recorder, request, caddyhttp.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) error {
		_, writeErr := io.WriteString(writer, "exempt")
		return writeErr
	}))
	if err != nil || recorder.Code != http.StatusOK || recorder.Body.String() != "exempt" {
		t.Fatalf("exempt response code=%d body=%q err=%v", recorder.Code, recorder.Body.String(), err)
	}
}

func TestHandlerDoesNotCountErrorsOrHead(t *testing.T) {
	now := time.Unix(20_000, 0)
	manager := testUsageManager(now)
	handler := testHandler(manager, []quotaWindow{{duration: time.Hour, limit: 1, label: "1h"}})

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, "http://mirror.test/repo/file", nil)
		request.RemoteAddr = "198.51.100.9:1234"
		err := handler.ServeHTTP(recorder, request, caddyhttp.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) error {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, "not found")
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	if violations := manager.check("198.51.100.0/24", handler.windows); len(violations) != 0 {
		t.Fatalf("unexpected usage: %#v", violations)
	}
}

func TestAccountingReadFromRecordsInChunks(t *testing.T) {
	var recorded uint64
	recorder := httptest.NewRecorder()
	writer := &accountingResponseWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: recorder},
		record: func(amount uint64) {
			recorded += amount
		},
	}
	contents := strings.Repeat("x", accountingChunkSize+17)
	written, err := writer.ReadFrom(strings.NewReader(contents))
	writer.flushAccount()
	if err != nil || written != int64(len(contents)) || recorded != uint64(len(contents)) {
		t.Fatalf("written=%d recorded=%d err=%v", written, recorded, err)
	}
}

func testUsageManager(now time.Time) *usageManager {
	return &usageManager{
		usage:     make(map[string]*prefixUsage),
		dirty:     make(map[string]uint64),
		deletions: make(map[string]struct{}),
		retention: minimumRetention,
		lastNow:   now.Unix(),
		now:       func() time.Time { return now },
		logger:    zap.NewNop(),
	}
}

func testHandler(manager *usageManager, windows []quotaWindow) *BandwidthQuota {
	return &BandwidthQuota{
		IPv4Prefix:    24,
		IPv6Prefix:    64,
		manager:       manager,
		windows:       windows,
		logger:        zap.NewNop(),
		lastBlockLogs: make(map[string]time.Time),
		metrics: quotaMetrics{
			countedBytes: prometheus.NewCounter(prometheus.CounterOpts{Name: "test_counted_bytes_total"}),
			blocked:      prometheus.NewCounter(prometheus.CounterOpts{Name: "test_blocked_requests_total"}),
		},
	}
}
