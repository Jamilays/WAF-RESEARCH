# Shadow Daemon

Shadow Daemon is architecturally different from the other three WAFs: it's
a **language-level** WAF. Official connectors exist only for PHP, Perl, and
Python — there is no upstream nginx/Apache reverse-proxy connector.

## Topology

| Service | Image | Purpose |
|---|---|---|
| `shadowd-db` | `zecure/shadowd_database:12.4` | Postgres schema + rule store |
| `shadowd`    | `zecure/shadowd:2.2.0` | Analysis daemon, TCP :9115 |
| `shadowd-<target>` | built from `./proxy/` | Python async reverse proxy that sits in front of an arbitrary HTTP target |

`GET /healthz` on the proxy always returns 200 (does not round-trip to the
shadowd daemon — health must not depend on the analyzer's verdict).

## Blocking behaviour (post-Phase-6 audit)

The proxy enforces a block when **either** of two signals fires:

1. **shadowd daemon verdict `status=1`** — the intended path. Requires a
   provisioned DB profile + HMAC-signed wire protocol. Not yet bootstrapped
   in this lab (see "Future work" below). Until then the daemon returns no
   verdict for unprovisioned profiles.
2. **In-proxy fallback detector** — regex rules for SQLi / XSS / cmdi / LFI
   run over the URL path, query parameters, and request body when
   `SHADOWD_ENFORCE=true` and `SHADOWD_FALLBACK_BLOCK=true`.

Without the fallback, `SHADOWD_ENFORCE=true` silently became a no-op (the
daemon's analysis never completed), which produced a spurious 100% bypass
rate in every comparison against the other WAFs.

Env toggles:

| Var | Default | Meaning |
|---|---|---|
| `SHADOWD_ENFORCE` | `true` | Translate verdicts into 403s (vs. observer-only) |
| `SHADOWD_FALLBACK_BLOCK` | `true` | Let the proxy block on its own regex match if shadowd has no verdict |
| `SHADOWD_TIMEOUT` | `0.5s` | Analyzer roundtrip budget — exceeded → treated as "no verdict" |

The fallback detector **only scans user-controllable slots** (path, query,
body). Headers like `User-Agent` and `Cookie` are intentionally ignored so
legitimate values (`curl/8.1.2`, session cookies) don't false-positive.
Context-displacement mutators that relocate payloads into custom `X-*`
headers are only caught by the real shadowd path.

## Whitelist experiments (opt-in)

The default profile (see `init/bootstrap.sql`) is blacklist-only — that
matches the 120-filter library the paper tested. Shadow Daemon's other
two engines are exercisable via opt-in scripts that flip the profile
without disturbing the headline research corpus:

- **Whitelist** — `make shadowd-whitelist` (or `bash tests/shadowd_whitelist.sh`)
  seeds a small hand-crafted rule set for DVWA's /vulnerabilities/sqli/
  endpoint (`GET|id` must be numeric ≤10 digits, etc.), flips
  `whitelist_enabled=1, blacklist_enabled=0`, runs benign vs. attack
  probes, and restores the canonical blacklist-only profile on exit.
  Hand-crafted rather than learned because the daemon's learning mode
  *records* observed inputs for human review — it does not auto-promote
  them to rules. See `init/whitelist-seed.sql` for the rule template.
- **Integrity** (hash-based) — *not a reverse-proxy feature*. Shadow
  Daemon's integrity engine is for detecting web-app source-code
  tamper: the language-level connectors (PHP / Perl / Python) hash
  application files at startup and ship those digests with every
  request. The lab runs shadowd behind a language-agnostic HTTP proxy
  (`wafs/shadowdaemon/proxy/proxy.py`) which has no application source
  to hash — `"hashes": {}` ships empty, and there's no meaningful way
  to exercise the engine without dropping one of the language
  connectors into the vulnerable targets themselves (DVWA's PHP,
  WebGoat's Java — the latter has no upstream connector). Out of scope
  for the current research harness.
