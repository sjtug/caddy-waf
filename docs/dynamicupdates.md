# Dynamic Updates

The WAF reloads selected configuration files in place, without restarting Caddy. This document describes exactly which paths trigger a reload, what each reload covers, and what it does not cover.

Implementation: `startFileWatcher`, `ReloadRules`, `ReloadConfig` in [`caddywaf.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/caddywaf.go).

## Watched files

After initial provisioning succeeds, file watchers are registered for:

- Every path listed in `rule_file` directives.
- The `ip_blacklist_file` path (if configured).
- The `dns_blacklist_file` path (if configured).
- The `ip_whitelist_file` path (if configured).

For each path, a separate `fsnotify` watcher goroutine observes its parent directory and filters events to that exact file. Files that are inaccessible at startup are skipped with an ERROR log. Watchers stop when the Caddy module shuts down.

## Trigger

Each watcher reacts to `fsnotify.Write` and `fsnotify.Create` events for the configured path. This covers both in-place writes and the common safe-update pattern of writing a temporary file and atomically renaming it over the target.

## Reload routing

`Provision` assigns a reload callback by file category rather than inferring it from the filename:

| Changed file | Action invoked | Effect |
|---|---|---|
| Any `rule_file` | `ReloadRules` | Re-parses every configured rule file, re-validates each rule, re-uses cached compiled regex by ID, and atomically replaces the in-memory rule map. |
| `ip_blacklist_file` or `dns_blacklist_file` | `ReloadConfig` | Re-loads the IP blacklist into a new prefix trie, re-loads the DNS blacklist into a new map, and re-runs `loadRules`. |
| `ip_whitelist_file` | `ReloadIPWhitelist` | Re-reads the file, combines it with inline `whitelist_ip` entries, validates every entry, and atomically replaces the whitelist trie. |

IP whitelist and blacklist reloaders build replacement tries before taking the middleware mutex for the swap. Rule loading uses its own synchronization while it re-parses the configured files.

## What a reload covers

| Setting | Reloads on file change? |
|---|---|
| `rule_file` contents | Yes (atomic). |
| `ip_blacklist_file` contents | Yes (atomic). |
| `dns_blacklist_file` contents | Yes (atomic). |
| `ip_whitelist_file` contents | Yes (atomic; inline `whitelist_ip` entries are retained). |
| Inline `whitelist_ip` values | No; run `caddy reload`. |
| `anomaly_threshold` | No. |
| `metrics_endpoint` | No. |
| `log_severity` / `log_path` / `log_json` / `log_buffer` | No. |
| `rate_limit { ... }` | No. The limiter is built once during `Provision`. |
| `block_countries` / `whitelist_countries` / `block_asns` (paths and ISO codes) | No. |
| `tor { ... }` settings | No. The fetcher schedule is set once during `Provision`. |
| `custom_response` definitions | No. |
| `redact_sensitive_data` | No. |
| `max_request_body_size` | No. |
| `max_response_body_size` | No. |
| `geoip_fail_open` (JSON-only) | No. |

For any "No" above, run `caddy reload` so Caddy re-parses the configuration and re-runs `Provision` on the WAF module.

## Tor exit-node updates

The Tor fetcher runs on its own schedule (`tor.update_interval`, default `24h`). On each tick it fetches the current exit-node list and writes it to `tor.tor_ip_blacklist_file`. To make those addresses effective in the IP blacklist, configure `ip_blacklist_file` to point at the same path (or merge the Tor file into your IP blacklist out-of-band). See [configuration.md](configuration.md) for details on the `tor` block.

## Reload via the Caddy admin API

Configuration changes that fall outside the file-watcher scope are applied through the Caddy admin API:

```bash
caddy reload --config Caddyfile
# or
curl -X POST http://localhost:2019/load \
     -H 'Content-Type: application/json' \
     -d @caddy.json
```

A `caddy reload` re-runs `Provision` on every module, including the WAF. The previous module instance is shut down (closing GeoIP databases, stopping the rate-limiter cleanup goroutine, and draining the log channel) before the new one is provisioned.

## Failure handling

- **Invalid JSON in a rule file**: the file is skipped with an ERROR log; rules from other files continue to load. If no valid rules remain across all files (and at least one path was provided), the reload returns an error.
- **Invalid individual rule**: dropped with a WARN log; the rest of the file continues.
- **Duplicate rule ID**: dropped with a WARN log; the first occurrence wins.
- **Invalid regex**: rule dropped with a WARN log.
- **Invalid IP/CIDR line in the IP blacklist**: line skipped, counted in `invalid_entries`.
- **Invalid IP-whitelist entry** (anything other than an IP, CIDR, or `private_ranges`): the entire whitelist update is rejected and the active trie is retained.
- **Unreadable IP whitelist file**: the update is rejected and the active trie is retained.

Replacement structures are swapped only after their loader succeeds, so a failed reload does not replace that component's last successfully-loaded state.

## Practical workflow

```bash
# Add a rule
$EDITOR rules.json

# Save the file (an in-place write triggers fsnotify on the watched path).
# The WAF logs:
#   "Detected configuration change. Reloading..."  {"file":"rules.json"}
#   "WAF rules loaded successfully" {"total_rules":34, ...}

# Add an IP to the blacklist
echo "203.0.113.99" >> ip_blacklist.txt

# Replace a generated IP whitelist atomically
printf '198.51.100.0/24\n2001:db8:1234::/48\n' > ip_whitelist.new
mv ip_whitelist.new ip_whitelist.txt

# Confirm the reload happened
tail -f debug.json
```

## Tips

- Prefer writing to a temp file in the same directory and renaming it over the target; the directory watcher follows atomic replacement.
- Keep large rule sets in modular files under `rules/` — a reload re-parses every file, so smaller files mean faster reloads.
- Watch the `total_rules` and `rule_counts` log fields after each reload to confirm the expected count was loaded.
