# Download bandwidth quotas

The fork adds a second Caddy HTTP handler, `http.handlers.bandwidth_quota`, for
persistent rolling response-byte quotas. It is independent of
`http.handlers.waf`; a site can use either or both handlers.

## Caddyfile

```caddyfile
@downloads {
    method GET
    path /repo-a/* /repo-b/*
}

bandwidth_quota @downloads {
    state_path /data/bandwidth-quota.db
    whitelist_file /etc/caddy/quota-whitelist.txt
    ipv4_prefix 24
    ipv6_prefix 64
    window 5h 10GiB
    window 168h 200GiB
    window 720h 500GiB
}
```

| Sub-directive | Meaning |
|---|---|
| `state_path` | bbolt database shared by every handler instance using this absolute path. |
| `whitelist_file` | Optional file of exempt IP addresses or CIDRs, one per line. `#` comments and blank lines are accepted. Changes require a Caddy reload. |
| `ipv4_prefix` | IPv4 grouping prefix length, from `0` through `32`. |
| `ipv6_prefix` | IPv6 grouping prefix length, from `0` through `128`. |
| `window` | Rolling duration and binary/decimal byte limit. Repeat for independent windows. Durations must be whole seconds and no longer than 30 days. |

The handler uses the direct peer from `RemoteAddr`; it does not trust
`X-Forwarded-For`. Place it at the network edge or ensure an upstream proxy
preserves the intended peer address.

## Enforcement

Before forwarding a matching `GET`, the handler sums the client prefix's usage
in every configured rolling window. If any sum is at least its limit, it returns:

- `429 Too Many Requests`;
- `Retry-After` set to the first second when every exhausted window will be
  below its limit;
- `Cache-Control: private, no-store`.

Otherwise, response bytes successfully written under status `200` through
`299` are counted as they stream, including `206 Partial Content`. Accounting
is buffered by less than 1 MiB per in-flight response. Existing transfers
continue after a limit is crossed; newly admitted requests are refused.

Directive order controls which byte representation is counted. Place
`bandwidth_quota` before `encode` to count encoded bytes written toward the
client.

## Persistence and availability

Usage is aggregated into one-second prefix buckets. Dirty buckets flush to
bbolt once per second and data older than 30 days is pruned. Handler instances
in one process share an in-memory manager for each `state_path`, so host aliases
and routes contribute to the same quota.

Persistence is fail-open. If the database cannot be opened or loaded, Caddy
logs an error and starts with fresh in-memory accounting. A hard shutdown may
lose up to one second of flushed state plus less than 1 MiB per in-flight
response.

## Metrics

The handler registers two counters in Caddy's Prometheus registry:

- `caddy_bandwidth_quota_counted_bytes_total`;
- `caddy_bandwidth_quota_blocked_requests_total`.
