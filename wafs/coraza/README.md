# Coraza (Go) + OWASP CRS v4

Small Go reverse proxy that wraps a Coraza WAF around `net/http/httputil`, loading CRS v4 from the [`coraza-coreruleset`](https://github.com/corazawaf/coraza-coreruleset) embedded FS — same ruleset as ModSecurity, fair comparison.

## Files

- `main.go` — entrypoint (~70 lines)
- `go.mod` — pins `coraza/v3` and `coraza-coreruleset`
- `Dockerfile` — two-stage build, static binary on Alpine

## Env

| Env var | Default | Notes |
|---|---|---|
| `BACKEND` | `http://whoami:80` | Upstream URL |
| `LISTEN_ADDR` | `:80` | Proxy bind |
| `CORAZA_EXTRA_DIRECTIVES` | `""` | Appended after CRS setup; used by `paranoia-high` profile to raise `tx.blocking_paranoia_level` |

## Paranoia-high override

Handled by the compose `coraza-ph` service — passes a `SecAction` that sets `tx.blocking_paranoia_level=4` after CRS setup.

## Rule-ID fingerprinting on blocks

The proxy doesn't use stock `corazahttp.WrapHandler`; it drives the Coraza transaction directly (see `wrapWAFWithRuleIDs` + `feedRequestToTx` in `main.go`) so it can inspect `tx.MatchedRules()` at interrupt time and stamp the result onto the response:

| Response header | Meaning |
|---|---|
| `X-Waflab-Waf` | `coraza` (same self-ID as the other lab proxies) |
| `X-Coraza-Action` | `deny` / `drop` / `redirect` — from the interruption |
| `X-Coraza-Interrupt-Rule` | The single rule ID that tripped the 403 (usually `949110`, the inbound-anomaly threshold) |
| `X-Coraza-Rules-Matched` | Comma-joined attack-detection rule IDs that incremented the anomaly score (CRS range `[910000, 990000)`). Init/setup rules are filtered out — they fire on every request. |

The engine's `_capture_waf_headers` picks all four up automatically, so each `VerdictRecord.waf_route.waf_headers` on a Coraza block carries the rule-ID breakdown, and the dashboard's Payload Explorer drilldown renders it as a key/value table.

Response-phase processing (CRS phase 3/4) is intentionally not wired here — the upstream `WrapHandler`'s response interceptor buffers bodies for outbound inspection and complicates header-stamping on phase-3 blocks. The lab's corpus is entirely request-side, so the request-only wrapper covers the signal we care about.
