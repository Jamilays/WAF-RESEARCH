# WAF Evasion Research Lab

Reproducible black-box lab for evaluating Web Application Firewalls under modern payload obfuscation. Four open-source WAFs, three deliberately vulnerable apps, a pluggable mutation engine, seven obfuscation strategies, and a live dashboard — all behind a single reverse proxy so every WAF sees the same request stream.

This is the companion repository to the Bachelor's thesis:

> Yusifova, J. *Black-Box Testing of Web Application Firewalls (WAFs): Analysis of Advanced Payload Evasion Techniques to Bypass WAFs.* Baku Higher Oil School, 2026.

> ⚠ **Authorized use only.** The lab contains intentionally vulnerable apps and an offensive payload engine. Do not point it at systems you do not own or have explicit written authorization to test. All services bind to `127.0.0.1`.

---

## What's measured

| Axis | Coverage |
|---|---|
| WAFs | **ModSecurity v3 + CRS 4.25**, **Coraza + CRS 4.25**, **Shadow Daemon 2.2**, **open-appsec** (ML), plus PL4 paranoia variants and a no-WAF baseline |
| Targets | **DVWA**, **WebGoat**, **OWASP Juice Shop** — all routed via Traefik by `Host:` header |
| Attack corpus | **297 payloads** across **12 vulnerability classes**: SQLi, XSS, command injection, LFI, SSTI, XXE, NoSQL, LDAP, SSRF, JNDI/Log4Shell, GraphQL, CRLF |
| Benign corpus | **15 realistic requests** used for false-positive measurement |
| Mutators | **lexical**, **encoding**, **structural**, **context_displacement**, **multi_request**, **adaptive** (rank-6 pair composer), **adaptive3** (rank-7 triple composer) |
| Statistics | Wilson 95 % confidence intervals; cells with n < 5 are suppressed |
| Reproducibility | Every external image pinned by SHA-256 digest; engine + analyser + reporter are pure Python; every result ships with a manifest containing git SHA, image digests, and run config |

---

## Headline findings

Pooled bypass rate on OWASP Juice Shop (waf_view lens, all classes pooled):

| WAF | Bypass | Benign FPR |
|---|---:|---:|
| `modsec` (PL1) | 37.6 % | 0 % |
| `coraza` (PL1) | 40.5 % | 0 % |
| `shadowd` | **76.0 %** | 0 % |
| `openappsec` (ML, critical) | 40.9 % | 0 % |
| `modsec-ph` (PL4 via env var) | 37.6 % — **identical to `modsec`** | 0 % |
| `coraza-ph` (PL4 directives) | **6.6 %** | **81 %** |

Three takeaways the lab is designed to surface:

1. **Architecture matters more than tuning.** The bypass range across stock open-source WAF families on identical input spans an 11.5× gap.
2. **The PL4 trap.** Coraza PL4 buys the lowest bypass rate but blocks 81 % of benign traffic. ModSecurity PL4 via the upstream `PARANOIA_LEVEL` env var produces *zero* detection uplift for the rule families this study tested — the env path does not propagate to the JSON-SQL plugin rules. Operators must set CRS directives directly.
3. **Composition wins.** Triple-stacking obfuscations with the `adaptive3` mutator adds up to **+60 percentage points** over the best single mutator in cells where the base is tight. Single-mutator benchmarks systematically under-report real-world bypass.

The long tail of modern dialects (LDAP, NoSQL, SSRF, GraphQL, CRLF, SSTI, XXE) remains a **22–91 % bypass surface** across every WAF tested. CRS 4.x has measurably closed the historical SQLi gap (≈27 % → ≈5 %) but the tail is still open.

---

## Quickstart

Requirements: Docker 25+, Docker Compose v2, ~6 GB free RAM on first boot.

```bash
cp .env.example .env            # optional — override ports, paranoia, enforce flags

# Bring up the core matrix (3 targets + 9 WAF×target + baselines)
docker compose up -d --build --wait --wait-timeout 600

# Acceptance smoke test
bash tests/phase2.sh
```

The whole matrix is reachable through Traefik at **http://127.0.0.1:8000**, routed by `Host:` header — no `/etc/hosts` edits required:

```bash
# Baseline (no WAF)
curl -H 'Host: baseline-juiceshop.local' http://127.0.0.1:8000/

# Through a WAF — 403 means blocked, 200 + SQL error means bypass
curl -H 'Host: modsec-juiceshop.local'     "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: coraza-juiceshop.local'     "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: shadowd-juiceshop.local'    "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: openappsec-juiceshop.local' "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"   # needs --profile ml
```

Traefik dashboard (read-only, loopback): http://127.0.0.1:8088/dashboard/

### Optional profiles

```bash
docker compose --profile paranoia-high up -d --wait   # + modsec-ph-* + coraza-ph-* (6 services)
docker compose --profile ml          up -d --wait     # + open-appsec agent + 4 standalone sidecars
docker compose --profile dashboard   up -d --build --wait  # + FastAPI + React dashboard
```

With `--profile dashboard`:

- **Dashboard** — http://127.0.0.1:3000 — tabs: Live Run, Results, Cross-WAF, Hall of Fame, Payload Explorer, Compare Runs.
- **API** — http://127.0.0.1:8001 — `/docs` for OpenAPI.

Both mount `results/` read-only. Trigger a run with `make run` and watch the Live Run tab poll it.

---

## The matrix

**Default profile** (12 routes):

| WAF | dvwa | webgoat | juiceshop |
|---|---|---|---|
| baseline (no WAF) | `baseline-dvwa.local` | `baseline-webgoat.local` | `baseline-juiceshop.local` |
| ModSecurity | `modsec-dvwa.local` | `modsec-webgoat.local` | `modsec-juiceshop.local` |
| Coraza | `coraza-dvwa.local` | `coraza-webgoat.local` | `coraza-juiceshop.local` |
| Shadow Daemon | `shadowd-dvwa.local` | `shadowd-webgoat.local` | `shadowd-juiceshop.local` |

`--profile paranoia-high` adds six PL4 variants (`modsec-ph-*`, `coraza-ph-*`).
`--profile ml` adds three open-appsec routes — all served by one container that splits by `Host:` internally.

---

## Running experiments

```bash
# Full corpus × 5 base mutators × 3 targets × 4 WAFs (PL1) — ~30 min at MAX_CONCURRENCY=4
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 --name waflab-engine \
  engine run \
    --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
    --mutators lexical,encoding,structural,context_displacement,multi_request \
    --run-id "research-$(date -u +%Y%m%dT%H%M%SZ)"

# Paranoia-high comparison (modsec-ph + coraza-ph at PL4)
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 \
  engine run --wafs baseline,modsec-ph,coraza-ph \
    --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
    --mutators lexical,encoding,structural,context_displacement,multi_request \
    --run-id "paranoia-high-$(date -u +%Y%m%dT%H%M%SZ)"

# open-appsec only
docker compose --profile engine --profile ml run --rm -e MAX_CONCURRENCY=4 \
  engine run --wafs baseline,openappsec \
    --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
    --mutators lexical,encoding,structural,context_displacement,multi_request \
    --run-id "openappsec-$(date -u +%Y%m%dT%H%M%SZ)"

# Benign corpus (for FPR)
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 \
  engine run --classes benign --mutators noop \
    --run-id "benign-$(date -u +%Y%m%dT%H%M%SZ)"

# Adaptive composition — seeds on a prior attack run
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 \
  engine run --mutators adaptive,adaptive3 \
    -e ADAPTIVE_SEED_RUN=<previous-attack-run-id> \
    --run-id "adaptive-$(date -u +%Y%m%dT%H%M%SZ)"
```

Results land under `results/{raw,processed,figures,reports}/<run_id>/`. Each run produces CSVs, PNG/SVG figures, and `report.md` + `report.tex`.

### Reporters

```bash
# Single-run report
wafeval report --run-id <RUN_ID>

# Headline report fusing attack + adaptive + benign runs
wafeval report-headline \
  --attack-run-id   <attack-run-id> \
  --adaptive-run-id <adaptive-run-id> \
  --benign-run-id   <benign-run-id> \
  --out-id headline-$(date -u +%Y%m%d)

# Merge N runs into one cross-WAF report
wafeval report-combined --run-ids a,b,c --out-id combined
```

The headline reporter produces an 11-section Markdown report with the pooled WAF × target heatmap, the attack-vs-FPR table, mutator × WAF table anchored on Juice Shop, compositional uplift, paranoia ablation, WAF × class heatmap, latency-vs-bypass scatter, deduped Hall of Fame, and bibliography.

---

## Testing

```bash
bash tests/phase1.sh   # WAF liveness
bash tests/phase2.sh   # routing matrix
bash tests/phase3.sh   # engine core + lexical mutator end-to-end
bash tests/phase4.sh   # 5 mutators × corpus minima
bash tests/phase5.sh   # analyzer + reporter
bash tests/phase6.sh   # FastAPI + dashboard
bash tests/phase_paper.sh         # paper-replication subset
bash tests/shadowd_whitelist.sh   # shadowd whitelist-mode PoC
```

Engine unit tests (144 passing):

```bash
engine/.venv/bin/python -m pytest engine/tests -q
```

---

## Corpus

**12 vulnerability classes, 297 attack payloads** under `engine/src/wafeval/payloads/*.yaml`, plus a 15-entry benign corpus for FPR measurement:

| Class | # | Notes |
|---|---:|---|
| sqli | 42 | Classical + JSON-SQL (Team82) + Unicode + ODBC + scientific notation + hex/CHAR |
| xss | 35 | Script tag + handlers + Unicode + entity-split + mXSS + SVG animate + data-URI |
| cmdi | 15 | Pipe, semicolon, backtick, `$()`, `$IFS`, brace expansion |
| lfi | 15 | Path traversal + PHP wrappers + null byte + encoded |
| ssti | 25 | Jinja2, Twig, Freemarker, Velocity, ERB, Pug, Smarty, Mako, Handlebars, Tornado, JSP-EL, Spring SpEL |
| xxe | 25 | External entities, parameter entities, OOB exfil, XInclude, SOAP, SVG, OOXML, UTF-7/16, CDATA |
| nosql | 25 | MongoDB `$ne`/`$regex`/`$where`, form-encoded operators, `$function`, mapReduce, `$lookup` |
| ldap | 25 | Wildcard, OR/AND, AD-specific (sAMAccountName, OID matching), extensibleMatch |
| ssrf | 25 | AWS/GCP/Azure/DO/Alibaba metadata; decimal/hex/octal/mixed IP; IPv6 mapped; `file://`, `gopher://`, `dict://`, `ldap://`, URL userinfo trick |
| jndi | 25 | Log4Shell base + LDAPS/RMI/CORBA/IIOP + lower/upper/env/sys/date/marker lookups + base64 + URI-encoded |
| graphql | 25 | Introspection, typed/deep/directives, batch DoS, alias overload, fragment cycle, variable injection, nested SQLi/cmdi/JNDI/XXE smuggling |
| crlf | 25 | Response splitting, Set-Cookie smuggle, LF/CR-only, Content-Type confusion, CSP/CORS clobber, cache poisoning, chunked-trailer |
| **benign** | **15** | Realistic product searches, usernames, natural-English near-signal strings — paired with the `noop` mutator for clean FPR. Excluded from default runs (load via `--classes benign`). |

A 40-entry **paper-replication subset** (`payloads/paper_subset.yaml`) is also shipped — 20 SQLi + 20 XSS drawn from the same academic literature (PayloadsAllTheThings, OWASP WSTG, SecLists) — as a fixed point for comparable reproduction. Load with `wafeval run --corpus paper_subset`.

---

## Architecture

```
                127.0.0.1:8000
                      │
        ┌─────────────▼─────────────┐    routes by Host: header
        │          Traefik          │────────────────────────────┐
        └───────────────────────────┘                            │
            │       │       │       │                            │
            ▼       ▼       ▼       ▼                            ▼
        modsec-*  coraza-*  shadowd-*  openappsec-*          baseline-*
                                       (--profile ml,
                                        single container,
                                        Host-header split)
            │       │       │       │                            │
            │ BACKEND│ BACKEND│ BACKEND│ BACKEND                  │
            └───────┼───────┴───────┴────────────────────────────┘
                    ▼
              ┌─────┴─────┐
              │     │     │
            dvwa  webgoat juiceshop
           + db
```

Engine, analyser, and reporter are pure Python (`engine/src/wafeval/`). The dashboard is FastAPI + React/Vite. Full system design in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); developer onboarding in [docs/DEV.md](docs/DEV.md).

---

## Engine internals (worth knowing)

- **Verdict classifier** (`runner/verdict.py`) is baseline-first. If baseline didn't trigger, the row returns `BASELINE_FAIL` regardless of what the WAF did — so denominators are comparable across WAFs.
- **Three-way verdict split**: `BLOCKED` (hard deny — 403/406/501 or 5xx + WAF marker), `BLOCKED_SILENT` (2xx with the exploit marker stripped), `ALLOWED` (real bypass). Both block verdicts count as WAF wins in the denominator and never in the numerator.
- **Per-route `httpx.AsyncClient`** — one client per (waf, target) route to avoid cookie-jar leaks.
- **WAF-header fingerprint capture** — `x-coraza-*`, `x-modsec-*`, `x-shadowd-*`, `x-waflab-*` response headers are stored on each `RouteResult`, so "why was this blocked?" can be answered without a separate audit-log parse.
- **Adaptive mutator** (`mutators/adaptive.py`, rank 6) stacks two string-body base mutators per variant; with `ADAPTIVE_SEED_RUN=<run_id>` it ranks pairs by `rate(A) × rate(B)` from the seed run.
- **Adaptive3 mutator** (rank 7) — same idea, three layers, ordered by per-WAF gain.
- **Noop mutator** (`mutators/noop.py`) emits the payload byte-identical to the YAML — exclusively for benign-corpus FPR runs.
- **Reproducibility metadata** in `manifest.json`: random seed (if `--seed <int>` was passed), git SHA, docker digests, host platform, CPU model and count, memory, Python version, engine version.

### Two analysis lenses

- **`true_bypass`** — strict, baseline-confirmed, DVWA-anchored. Matches the paper methodology.
- **`waf_view`** — baseline-agnostic, counts a payload as a bypass whenever the WAF lets it through. Used on Juice Shop where triggers vary per payload and on classes with no working backend sink.

---

## WAF gotchas (operator notes)

| WAF | Gotcha |
|---|---|
| **ModSecurity v3** | `PARANOIA_LEVEL=N` env var on the upstream image does **not** activate the JSON-SQL plugin rules (942550 family). modsec-ph therefore shows the same bypass rate as modsec on JSON-SQL payloads at every PL — the env path is documented but inert for this rule family. Set CRS directives directly to actually raise enforcement. |
| **Coraza** | `@coraza.conf-recommended` defaults to `SecRuleEngine DetectionOnly` — blocks nothing. The lab forces `SecRuleEngine On` via `CORAZA_BLOCKING_MODE=on` (default). PL4 directive in compose **does** activate JSON-SQL rules, unlike modsec-ph. |
| **Shadow Daemon** | Verdict mode constants are counterintuitive: `MODE_ACTIVE=1`, `MODE_PASSIVE=2`, `MODE_LEARNING=3` — **lower number = stricter**. `server_ip = *` is converted by `prepare_wildcard()` to SQL `%`; storing literal `%` gets double-escaped. |
| **open-appsec** | Standalone profile requires 4 sidecars (`openappsec-smartsync`, `openappsec-shared-storage`, `openappsec-tuning`, `openappsec-db` on Postgres **16**, not 18). Agent takes 30-45 s to load policy. Healthcheck probes `/healthz` which the nginx default_server handles before the agent attachment. |

---

## Runtime knobs

| Env / CLI flag | Default | Purpose |
|---|---|---|
| `MAX_CONCURRENCY` | 10 in compose, **4** for cmdi-heavy runs | Honour DVWA PHP-FPM pool limit |
| `REQUEST_TIMEOUT_S` | 30 | Per-request httpx timeout |
| `RESPONSE_SNIPPET_BYTES` | 65536 | Bytes of response body saved per record |
| `SHADOWD_ENFORCE` | `true` | Translate shadowd verdicts into 403s |
| `CORAZA_BLOCKING_MODE` | `on` | Force `SecRuleEngine On` — default-off means zero blocks |
| `OPENAPPSEC_DB_*` | `openappsec` / `openappsec_dev_only` | Postgres creds for the tuning service |
| `ADAPTIVE_SEED_RUN` | unset | Run-id used to rank adaptive composition pairs by prior bypass |
| `ADAPTIVE_TOP_K` | unset (= all pairs) | Cap the pair count for faster iteration |

---

## Safety & legality

- All host ports are bound to `127.0.0.1`. Never expose to the LAN.
- DVWA, WebGoat, and Juice Shop are intentionally vulnerable training apps.
- Default DB passwords end in `_dev_only`; rotate via `.env` before the disk leaves your machine.
- The payload loader rejects destructive patterns (`DROP TABLE`, `rm -rf`, fork bombs, `/etc/shadow`). The `multi_request` mutator re-audits every generated step.
- Every external image in [docker-compose.yml](docker-compose.yml) is pinned to a SHA-256 digest, including images that only ship `:latest` upstream. Refresh a pin with `docker pull <name>:<tag> && docker image inspect <name>:<tag> --format '{{index .RepoDigests 0}}'`.

---

## Host-OS notes

**NixOS**: `make` is not in PATH. Use `nix-shell -p make --run "make <target>"` or call the underlying commands directly. Python's numpy/pandas needs `libstdc++` + `zlib` on `LD_LIBRARY_PATH`; [scripts/with-nix-libs](scripts/with-nix-libs) wraps every host-venv target. No-op on non-NixOS hosts.

**Compose profile teardown**: `docker compose down` only stops services in the default profile. Use `docker compose --profile paranoia-high --profile ml --profile dashboard --profile engine --profile report down` to tear everything down.

---

## Citation

If this lab is useful in academic work, please cite the thesis:

```bibtex
@thesis{yusifova2026waf,
  author       = {Yusifova, Jamila},
  title        = {Black-Box Testing of Web Application Firewalls (WAFs):
                  Analysis of Advanced Payload Evasion Techniques to Bypass WAFs},
  school       = {Baku Higher Oil School},
  type         = {Bachelor's thesis},
  year         = {2026},
  address      = {Baku, Azerbaijan}
}
```

### Prior art and source material the corpus draws on

- [PayloadsAllTheThings — WAF Bypass collection](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Claroty Team82 — JS-ON: Security-OFF](https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf)
- [OWASP CRS — A new rule to prevent SQL in JSON](https://coreruleset.org/20230222/a-new-rule-to-prevent-sql-in-json/)
- [Demetrio et al., WAF-A-MoLE, SAC '20](https://dl.acm.org/doi/10.1145/3341105.3373962) — adversarial-ML evasion against a single signature WAF
- [Floris et al., ModSec-AdvLearn, IEEE TIFS 2025](https://ieeexplore.ieee.org/) — ML augmentation of ModSecurity rules
- [Qu et al., AdvSQLi, IEEE TIFS 2024](https://ieeexplore.ieee.org/) — learned SQLi mutation across multiple WAFs
- [open-appsec docker-compose deployment guide](https://docs.openappsec.io/getting-started/start-with-docker/deploy-with-docker-compose)
- [zecure/shadowd_python connector — wire protocol reference](https://github.com/zecure/shadowd_python/blob/master/shadowd/connector.py)

---

## License

Released for academic and authorized-testing use. See [docker-compose.yml](docker-compose.yml) for the third-party image licenses of bundled WAFs and target apps.
