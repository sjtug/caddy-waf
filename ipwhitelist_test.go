package caddywaf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestBuildIPWhitelist(t *testing.T) {
	t.Run("private_ranges expands to Caddy's set", func(t *testing.T) {
		_, expanded, err := buildIPWhitelist([]string{PrivateRangesToken})
		require.NoError(t, err)
		assert.ElementsMatch(t, privateRanges, expanded)
	})

	t.Run("accepts bare IPs, CIDRs and the token together", func(t *testing.T) {
		trie, _, err := buildIPWhitelist([]string{"private_ranges", "203.0.113.4", "198.51.100.0/24", "2001:db8::1"})
		require.NoError(t, err)
		m := &Middleware{logger: zap.NewNop(), ipWhitelist: trie}
		for _, tc := range []struct {
			addr    string
			exempt  bool
			comment string
		}{
			{"10.1.2.3:5000", true, "inside 10/8 via private_ranges"},
			{"192.168.1.10:443", true, "inside 192.168/16"},
			{"127.0.0.1:8080", true, "loopback"},
			{"[::1]:443", true, "IPv6 loopback"},
			{"203.0.113.4:1", true, "bare IP"},
			{"198.51.100.77:1", true, "inside the /24"},
			{"[2001:db8::1]:443", true, "bare IPv6"},
			{"8.8.8.8:53", false, "public, not listed"},
			{"198.51.101.1:1", false, "just outside the /24"},
		} {
			assert.Equalf(t, tc.exempt, m.isIPWhitelisted(tc.addr), "%s (%s)", tc.addr, tc.comment)
		}
	})

	t.Run("an unparseable entry fails rather than being skipped", func(t *testing.T) {
		_, _, err := buildIPWhitelist([]string{"203.0.113.0/33"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid whitelist_ip entry")

		_, _, err = buildIPWhitelist([]string{"not-an-ip"})
		require.Error(t, err)
	})

	t.Run("no whitelist configured exempts nobody", func(t *testing.T) {
		m := &Middleware{logger: zap.NewNop()}
		assert.False(t, m.isIPWhitelisted("10.0.0.1:1"))
	})
}

func TestIPWhitelistFileCombinesWithInlineEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip-whitelist.txt")
	require.NoError(t, os.WriteFile(path, []byte(`
# Managed allowlist
198.51.100.0/24
2001:db8::1
private_ranges
`), 0o600))

	m := &Middleware{
		logger:          zap.NewNop(),
		IPWhitelist:     []string{"203.0.113.4"},
		IPWhitelistFile: path,
	}
	require.NoError(t, m.loadIPWhitelist())

	assert.True(t, m.isIPWhitelisted("203.0.113.4:443"), "inline entry")
	assert.True(t, m.isIPWhitelisted("198.51.100.77:443"), "file CIDR")
	assert.True(t, m.isIPWhitelisted("[2001:db8::1]:443"), "file IPv6")
	assert.True(t, m.isIPWhitelisted("10.1.2.3:443"), "file private_ranges token")
	assert.False(t, m.isIPWhitelisted("198.51.101.1:443"))
}

func TestReloadIPWhitelistRetainsLastKnownGoodState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip-whitelist.txt")
	require.NoError(t, os.WriteFile(path, []byte("198.51.100.4\n"), 0o600))

	m := &Middleware{logger: zap.NewNop(), IPWhitelistFile: path}
	require.NoError(t, m.loadIPWhitelist())
	assert.True(t, m.isIPWhitelisted("198.51.100.4:443"))

	require.NoError(t, os.WriteFile(path, []byte("not-an-ip\n"), 0o600))
	require.Error(t, m.ReloadIPWhitelist())
	assert.True(t, m.isIPWhitelisted("198.51.100.4:443"),
		"a malformed update must not replace the active trie")

	require.NoError(t, os.WriteFile(path, []byte("203.0.113.9\n"), 0o600))
	require.NoError(t, m.ReloadIPWhitelist())
	assert.False(t, m.isIPWhitelisted("198.51.100.4:443"))
	assert.True(t, m.isIPWhitelisted("203.0.113.9:443"))
}

func TestIPWhitelistWatcherHandlesAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	// The callback is selected by configuration category, not by guessing from
	// the filename; "rule" here must not route this event to ReloadRules.
	path := filepath.Join(dir, "rule-ip-whitelist.txt")
	require.NoError(t, os.WriteFile(path, []byte("198.51.100.4\n"), 0o600))

	m := &Middleware{logger: zap.NewNop(), IPWhitelistFile: path}
	require.NoError(t, m.loadIPWhitelist())

	ctx, cancel := context.WithCancel(context.Background())
	m.startFileWatcher(ctx, []string{path}, "IP whitelist", m.ReloadIPWhitelist)
	defer func() {
		cancel()
		m.watcherWG.Wait()
	}()

	replacement := filepath.Join(dir, "ip-whitelist.new")
	require.NoError(t, os.WriteFile(replacement, []byte("203.0.113.9\n"), 0o600))
	require.NoError(t, os.Rename(replacement, path))

	require.Eventually(t, func() bool {
		return !m.isIPWhitelisted("198.51.100.4:443") && m.isIPWhitelisted("203.0.113.9:443")
	}, 5*time.Second, 10*time.Millisecond)
}

// TestWhitelistIgnoresForwardedHeaders is the security property of this feature.
//
// The blacklist checks the peer address AND the forwarded chain, because
// checking more can only block more. The whitelist must do the opposite: if it
// honoured X-Forwarded-For, anyone could send "X-Forwarded-For: 10.0.0.1" and
// exempt themselves from the blacklist, the country filter and the ASN filter
// in a single header.
func TestWhitelistIgnoresForwardedHeaders(t *testing.T) {
	trie, _, err := buildIPWhitelist([]string{PrivateRangesToken})
	require.NoError(t, err)
	m := &Middleware{logger: zap.NewNop(), ipWhitelist: trie}

	assert.True(t, m.isIPWhitelisted("10.0.0.5:1234"), "a genuinely private peer is exempt")

	// Same helper, but the private address is only claimed in a header.
	r := httptest.NewRequest(http.MethodGet, testURL, nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.5")
	assert.False(t, m.isIPWhitelisted(r.RemoteAddr),
		"a forged X-Forwarded-For must never grant an exemption")
}

func TestWhitelistEndToEnd(t *testing.T) {
	logger := zap.NewNop()

	blFile, err := os.CreateTemp(t.TempDir(), "ipbl*.txt")
	require.NoError(t, err)
	_, err = blFile.WriteString("10.0.0.5\n203.0.113.9\n")
	require.NoError(t, err)
	require.NoError(t, blFile.Close())

	newMW := func(t *testing.T, whitelist []string) *Middleware {
		t.Helper()
		m := &Middleware{
			logger:           logger,
			blacklistLoader:  NewBlacklistLoader(logger),
			AnomalyThreshold: 5,
			ruleCache:        NewRuleCache(),
			ipBlacklist:      iptrie.NewTrie(),
			dnsBlacklist:     map[string]struct{}{},
			ruleHitsByPhase:  map[int]int64{},
			// A phase-1 rule that must still apply to whitelisted clients.
			Rules: map[int][]Rule{1: {{
				ID: "attack", Pattern: "attackpayload", Targets: []string{"URI"},
				Phase: 1, Score: 10, Action: "block", regex: regexp.MustCompile("attackpayload"),
			}}},
			requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		}
		require.NoError(t, m.loadIPBlacklist(blFile.Name(), m.ipBlacklist))
		if whitelist != nil {
			trie, _, err := buildIPWhitelist(whitelist)
			require.NoError(t, err)
			m.ipWhitelist = trie
		}
		return m
	}

	probe := func(t *testing.T, m *Middleware, remote, target string, header map[string]string) (int, bool) {
		t.Helper()
		reached := false
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			reached = true
			_, err := w.Write([]byte("UPSTREAM"))
			return err
		})
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = remote
		for k, v := range header {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		require.NoError(t, m.ServeHTTP(w, req, next))
		return w.Code, reached
	}

	t.Run("without a whitelist the blacklisted private IP is blocked", func(t *testing.T) {
		m := newMW(t, nil)
		code, reached := probe(t, m, "10.0.0.5:1234", testURL+"/", nil)
		assert.Equal(t, http.StatusForbidden, code)
		assert.False(t, reached)
	})

	t.Run("whitelisting private_ranges takes precedence over the IP blacklist", func(t *testing.T) {
		m := newMW(t, []string{PrivateRangesToken})
		code, reached := probe(t, m, "10.0.0.5:1234", testURL+"/", nil)
		assert.Equal(t, http.StatusOK, code)
		assert.True(t, reached, "the whitelisted peer must reach the upstream")
	})

	t.Run("a file-backed whitelist takes precedence over the IP blacklist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ip-whitelist.txt")
		require.NoError(t, os.WriteFile(path, []byte("10.0.0.5\n"), 0o600))
		m := newMW(t, nil)
		m.IPWhitelistFile = path
		require.NoError(t, m.loadIPWhitelist())

		code, reached := probe(t, m, "10.0.0.5:1234", testURL+"/", nil)
		assert.Equal(t, http.StatusOK, code)
		assert.True(t, reached, "the file-whitelisted peer must reach the upstream")
	})

	t.Run("a whitelisted peer is still subject to the rule engine", func(t *testing.T) {
		m := newMW(t, []string{PrivateRangesToken})
		code, reached := probe(t, m, "10.0.0.5:1234", testURL+"/?q=attackpayload", nil)
		assert.Equal(t, http.StatusForbidden, code,
			"the exemption covers IP reputation, not the rules")
		assert.False(t, reached)
	})

	t.Run("a public peer cannot claim an exemption with a header", func(t *testing.T) {
		m := newMW(t, []string{PrivateRangesToken})
		code, reached := probe(t, m, "203.0.113.9:1234", testURL+"/",
			map[string]string{"X-Forwarded-For": "10.0.0.1"})
		assert.Equal(t, http.StatusForbidden, code,
			"203.0.113.9 is blacklisted and must stay blocked despite the header")
		assert.False(t, reached)
	})
}

func TestIPWhitelistFileJSON(t *testing.T) {
	var m Middleware
	require.NoError(t, json.Unmarshal([]byte(`{
		"ip_whitelist_file": "/etc/caddy/ip-whitelist.txt",
		"ip_whitelist": ["203.0.113.4"]
	}`), &m))
	assert.Equal(t, "/etc/caddy/ip-whitelist.txt", m.IPWhitelistFile)
	assert.Equal(t, []string{"203.0.113.4"}, m.IPWhitelist)
}

func TestParseIPWhitelistFileDirective(t *testing.T) {
	t.Run("configures and creates the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ip-whitelist.txt")
		cfg := fmt.Sprintf("waf {\n rule_file rules.json\n ip_whitelist_file %s\n}", path)
		m := &Middleware{}
		err := NewConfigLoader(zap.NewNop()).UnmarshalCaddyfile(caddyfile.NewTestDispenser(cfg), m)
		require.NoError(t, err)
		assert.Equal(t, path, m.IPWhitelistFile)
		_, err = os.Stat(path)
		require.NoError(t, err)
	})

	t.Run("requires exactly one path", func(t *testing.T) {
		for _, directive := range []string{"ip_whitelist_file", "ip_whitelist_file one two"} {
			m := &Middleware{}
			err := NewConfigLoader(zap.NewNop()).UnmarshalCaddyfile(
				caddyfile.NewTestDispenser("waf {\n rule_file rules.json\n "+directive+"\n}"), m)
			require.Error(t, err)
		}
	})
}

func TestParseWhitelistIPDirective(t *testing.T) {
	for _, tc := range []struct {
		name, cfg string
		wantErr   bool
		want      []string
	}{
		{
			"token plus entries", "waf {\n rule_file rules.json\n whitelist_ip private_ranges 203.0.113.4\n}", false,
			[]string{"private_ranges", "203.0.113.4"},
		},
		{
			"repeatable", "waf {\n rule_file rules.json\n whitelist_ip 10.0.0.0/8\n whitelist_ip 203.0.113.4\n}", false,
			[]string{"10.0.0.0/8", "203.0.113.4"},
		},
		{"no arguments is an error", "waf {\n rule_file rules.json\n whitelist_ip\n}", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Middleware{}
			err := NewConfigLoader(zap.NewNop()).UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.cfg), m)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, m.IPWhitelist)
		})
	}
}
