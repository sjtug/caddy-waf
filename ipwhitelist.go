package caddywaf

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/phemmer/go-iptrie"
	"go.uber.org/zap"
)

// PrivateRangesToken is the shorthand accepted by the whitelist_ip directive.
// It expands to privateRanges below, matching the set Caddy uses for its own
// private_ranges placeholder, so an operator does not have to remember two
// different definitions of "private".
const PrivateRangesToken = "private_ranges"

// privateRanges mirrors Caddy's private_ranges. Deliberately identical rather
// than "improved": a WAF and the server in front of it disagreeing about which
// addresses are private is the kind of subtle mismatch that produces a bypass.
var privateRanges = []string{
	"192.168.0.0/16",
	"172.16.0.0/12",
	"10.0.0.0/8",
	"127.0.0.1/8",
	"fd00::/8",
	"::1",
}

// buildIPWhitelist compiles the configured entries into a prefix trie.
//
// Entries may be a bare IP, a CIDR range, or PrivateRangesToken. An
// unparseable entry is an error rather than a warning: a whitelist that
// silently drops an entry fails in the dangerous direction for the operator
// (their address is not exempt) and there is no reason to guess.
func buildIPWhitelist(entries []string) (*iptrie.Trie, []string, error) {
	trie := iptrie.NewTrie()
	var expanded []string

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, PrivateRangesToken) {
			expanded = append(expanded, privateRanges...)
			continue
		}
		expanded = append(expanded, entry)
	}

	for _, entry := range expanded {
		cidr := entry
		if !strings.Contains(cidr, "/") {
			cidr = appendCIDR(cidr)
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid whitelist_ip entry %q: %w", entry, err)
		}
		trie.Insert(prefix, nil)
	}

	return trie, expanded, nil
}

// readIPWhitelistFile reads one bare IP, CIDR range, or private_ranges token
// per line. Its syntax intentionally matches the IP blacklist files: blank
// lines and lines beginning with # are ignored.
func readIPWhitelistFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open IP whitelist file %q: %w", path, err)
	}
	defer file.Close()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read IP whitelist file %q: %w", path, err)
	}
	return entries, nil
}

// loadIPWhitelist builds the complete whitelist from the inline entries and
// the optional file, then atomically replaces the active trie. Building first
// means a malformed or unreadable update leaves the last known-good whitelist
// in service.
func (m *Middleware) loadIPWhitelist() error {
	entries := append([]string(nil), m.IPWhitelist...)
	if m.IPWhitelistFile != "" {
		fileEntries, err := readIPWhitelistFile(m.IPWhitelistFile)
		if err != nil {
			return err
		}
		entries = append(entries, fileEntries...)
	}

	trie, expanded, err := buildIPWhitelist(entries)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.ipWhitelist = trie
	m.mu.Unlock()

	m.logger.Info("IP whitelist loaded",
		zap.String("path", m.IPWhitelistFile),
		zap.Int("entries", len(expanded)),
	)

	for _, entry := range entries {
		if strings.EqualFold(strings.TrimSpace(entry), PrivateRangesToken) {
			m.logger.Warn("IP whitelist includes private_ranges: requests whose PEER address is private are exempt from the IP blacklist, country filter and ASN filter. This is only what you want if caddy-waf is the edge. Behind another proxy the peer is that proxy, which would exempt all traffic.")
			break
		}
	}
	return nil
}

// ReloadIPWhitelist re-reads the configured whitelist file and atomically
// installs it together with any inline whitelist_ip entries.
func (m *Middleware) ReloadIPWhitelist() error {
	m.logger.Info("Reloading IP whitelist", zap.String("file", m.IPWhitelistFile))
	if err := m.loadIPWhitelist(); err != nil {
		return fmt.Errorf("failed to reload IP whitelist: %w", err)
	}
	return nil
}

// isIPWhitelisted reports whether addr is exempt from the IP-reputation checks.
//
// It takes ONLY the peer address, never X-Forwarded-For, and that asymmetry
// with the blacklist is deliberate. For blocking, consulting extra addresses
// can only ever block more, so the forwarded chain is fair game. For allowing,
// the opposite holds: honouring a client-supplied header would let anyone send
// "X-Forwarded-For: 10.0.0.1" and exempt themselves from the blacklist, the
// country filter and the ASN filter in one move. The peer address is the only
// value a client cannot forge, so it is the only one trusted here.
func (m *Middleware) isIPWhitelisted(remoteAddr string) bool {
	m.mu.RLock()
	trie := m.ipWhitelist
	m.mu.RUnlock()

	if trie == nil {
		return false
	}

	ip := extractIP(remoteAddr)
	parsed, err := netip.ParseAddr(ip)
	if err != nil {
		m.logger.Debug("Failed to parse peer address for whitelist check",
			zap.String("ip", ip), zap.Error(err))
		return false
	}

	return trie.Contains(parsed)
}
