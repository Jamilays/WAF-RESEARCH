# WAF Evasion Research Lab

Reproducible single-command lab that replicates and extends Jamila Yusifova's black-box study **"Evasion of Web Application Firewalls Through Payload Obfuscation"** — four open-source WAFs in front of vulnerable apps, a pluggable mutation engine, and a live dashboard.

> ⚠ **Authorized use only.** This lab contains intentionally vulnerable apps and an offensive payload engine. Do not point it at systems you do not own or have explicit written authorization to test. All services are bound to `127.0.0.1`.

---

## Status

**Phase 7+ complete.** All four WAFs legitimately enforcing, **297-payload corpus** across 12 vuln classes (up from 201), full SSTI + XXE coverage, consolidated headline reporter that fuses attack + adaptive + benign runs into a single rich Markdown report.

| Phase | Scope | Status |
|---|---|---|
| 1 | Skeleton, compose, 3 WAFs healthy, ML stub, paranoia-high profile | ✅ |
| 2 | DVWA / WebGoat / Juice Shop + Traefik hostname routing (9 WAF×target + 3 baselines) | ✅ |
| 3 | Engine core + 1 mutator end-to-end + payload corpus start | ✅ |
| 4 | 5 mutators + 100+ payload corpus | ✅ |
| 5 | Analyzer + Markdown/LaTeX reporter | ✅ |
| 6 | FastAPI (`--profile dashboard`) + Vite/React/TS/Tailwind dashboard | ✅ |
| 7 | Real shadowd + open-appsec, expanded corpus (201 payloads, 12 classes), PL1↔PL4 compare, Hall of Fame, cross-WAF report + dashboard tab, open-appsec confidence-ladder ablation | ✅ |
| 7+ | **Corpus expansion (8 thin classes 10-15 → 25 each), SSTI + XXE sinks added (DVWA + Juice Shop), graphql Juice Shop sink fix, cmdi/lfi DVWA trigger overrides, consolidated `report-headline` reporter (`wafeval report-headline`), `analyzer/paranoia.py` single-run PL1↔PL4 pivot, deduped Hall of Fame, `/runs/{id}/live` incremental cache, academic paper rendered to PDF.** | ✅ |

[TODO.md](TODO.md) tracks the remaining research roadmap (P1–P4 items). Items P0.1 (FPR-as-first-class-column) and P0.2 (fresh 4-WAF combined run) shipped this session as the consolidated headline reporter + the `headline-v2-20260429` artefact; P1.3 (modern bypass techniques) was partially addressed via the corpus expansion.

---

## State of the World

### WAFs — all 4 legitimately enforcing

| WAF | How it blocks | Gotchas |
|---|---|---|
| **ModSecurity v3 + CRS 4.25** (`owasp/modsecurity-crs:4.25.0-nginx-alpine-202604040104`) | Libinjection + ~1000 CRS rules. `PARANOIA` env var tunes the PL. | `PARANOIA=N` in compose env for `modsec-ph-*` services **doesn't activate the JSON-SQL plugin rules** (942550 family) — those ship separately. So modsec-ph shows the SAME bypass rate as modsec on JSON-SQL payloads at every PL. The paranoia-ladder ablation (see Research findings) measures this: bypass rate stays **flat across PL1/2/3/4**, while Coraza (which flips the same knob via `setvar:tx.blocking_paranoia_level=N`) closes the gap from PL2 onwards. |
| **Coraza** (`waflab/coraza:phase1`, built from `corazawaf/coraza/v3`) | Same CRS 4.25 rule set loaded via `coreruleset.FS`. | **CRITICAL:** `@coraza.conf-recommended` defaults to `SecRuleEngine DetectionOnly` — blocks nothing. We force `SecRuleEngine On` via `CORAZA_BLOCKING_MODE=on` (default). PL4 directive in compose (`SecAction ... tx.blocking_paranoia_level=4`) **does** activate JSON-SQL rules (unlike modsec-ph). Our proxy drives the Coraza transaction directly (not `corazahttp.WrapHandler`) so every block stamps `X-Coraza-Interrupt-Rule` + `X-Coraza-Rules-Matched` (attack-family rules only, range `[910000, 990000)` — init noise filtered). Surfaced to `VerdictRecord.waf_route.waf_headers` automatically. |
| **Shadow Daemon** (`zecure/shadowd:2.2.0`) | TCP :9115 analyser + 120 blacklist filters; verdict over HMAC-signed wire protocol. | Requires DB profile bootstrap. `MODE_ACTIVE=1`, `MODE_PASSIVE=2`, `MODE_LEARNING=3` — **lower number = stricter** (counterintuitive). `server_ip` column stored as `*` which `prepare_wildcard()` converts to SQL `%`; storing literal `%` gets escaped to `\%` and matches nothing. The proxy (`waflab/shadowd-proxy`) speaks the real wire protocol `profile_id\n hmac\n json\n`. 120-filter library is weaker than CRS — expected higher bypass rate. `SHADOWD_FALLBACK_BLOCK=false` by default (was a regex safety net before the daemon was properly wired). **Opt-in whitelist experiment**: `make shadowd-whitelist` flips the profile to whitelist-mode with hand-crafted rules for DVWA SQLi (numeric `GET|id`, alphanumeric `GET|Submit`, Everything catch-all), probes benign vs attack, restores blacklist-only on exit. Integrity mode is out of scope — it's a language-level connector feature (PHP/Perl/Python) and can't be exercised through our reverse proxy. |
| **open-appsec** (`ghcr.io/openappsec/agent-unified:latest`) | NGINX + ML attachment in one container, multiplexing all 3 `openappsec-*.local` Host headers via server blocks. | Standalone profile requires 4 sidecars: `openappsec-smartsync`, `openappsec-shared-storage`, `openappsec-tuning`, `openappsec-db` (Postgres **16**, not 18 — 18 moved the data dir). `local_policy.yaml` in `wafs/openappsec/localconfig/` sets `prevent-learn` + `minimum-confidence: critical`. Healthcheck probes `/healthz` which the nginx default_server handles *before* the agent attachment (agent takes 30-45 s to load policy). |

### Targets

| Target | Auth flow | Sink notes |
|---|---|---|
| **DVWA** (`vulnerables/web-dvwa:latest`) | Login via `POST /login.php` with scraped `user_token` (see `runner/session.py`). The `security` cookie is set **directly by the engine** (not via `/security.php?security=low` GET which relies on 302 redirect that `follow_redirects=False` misses). | `/vulnerabilities/exec/` runs `ping -c 4 <ip>` → ~4 s per baseline request → saturates PHP-FPM pool. **Use `MAX_CONCURRENCY=4` for cmdi workloads** (see note below). |
| **Juice Shop** (`bkimminich/juice-shop:v19.2.1`) | Unauthenticated. | `/rest/products/search?q=` is the canonical SQLi sink (SQLite → `SQLITE_ERROR` page leaks details on malformed queries). Does NOT reflect `q` in JSON, so XSS there is `baseline_fail` and intentionally has no endpoint in targets.yaml. |
| **WebGoat** (`webgoat/webgoat:v2025.3`) | Spring-Security form login, lesson state kept per-session. No default user — the engine self-registers `waflab` / `wafpw123` on first run (Spring validator caps the password at 10 chars). | Lesson routes 404 until the lesson page is primed. Bootstrapper GETs `/WebGoat/SqlInjection.lesson` + `/WebGoat/CrossSiteScripting.lesson` after login to initialise the session's lesson slots; then `/SqlInjection/attack2` (form field `query`) and `/CrossSiteScripting/attack5a` (query param `field1`) land payloads. Every response contains `"attemptWasMade" : true` once a payload reaches the lesson handler — that's the per-endpoint `trigger` in [targets.yaml](engine/src/wafeval/targets.yaml), overriding each payload's DVWA/Juice-Shop default marker. |

### Engine (Python, `engine/src/wafeval/`)

- **Per-route `httpx.AsyncClient`** — one client per (waf, target) route to avoid cookie jar leaks between routes. The old shared jar made DVWA session appear to work on WAF routes when actually only baseline authenticated.
- **WAF-header fingerprint capture** — `_capture_waf_headers` (in `runner/engine.py`) extracts `x-*` response headers whose names contain `coraza|modsec|shadowd|waflab` and stores `{name: value}` on `RouteResult.waf_headers`. That's where Coraza's rule-ID stamps, Shadow Daemon's `x-shadowd-threats`, and the `x-waflab-waf` self-ID land, so the dashboard's Payload Explorer drilldown can answer "why was this blocked?" without a separate audit-log parse.
- **Verdict classifier** (`runner/verdict.py`): baseline-first. If baseline didn't trigger, return `BASELINE_FAIL` regardless of what the WAF did — so denominators are comparable across WAFs. Hard 4xx/5xx+WAF-marker → `BLOCKED`; 2xx response with no exploit marker → `BLOCKED_SILENT` (silent-sanitise case, see Analyzer section for how it's surfaced); 5xx with exploit marker → `ALLOWED` (Juice Shop SQLITE_ERROR is a successful SQLi); 2xx with the marker → `ALLOWED` (or `FLAGGED` when the WAF stamped a detection header).
- **Trigger model** — supports `contains`, `regex`, `reflected`, `status`, `any_of`. `any_of` lets one payload match against DVWA's "First name" *or* Juice Shop's SQLITE_ERROR so the corpus stays DRY.
- **Context-displacement + multi_request mutators** — relocate payloads into HTTP headers. The `_header_safe()` helper percent-encodes control chars + non-ASCII so h11's field-value validation doesn't reject (SQLi `\n` payloads, Unicode-quote SQLi, etc.).
- **Adaptive (compositional) mutator** (`mutators/adaptive.py`, `complexity_rank=6`) — stacks two string-body base mutators per variant (e.g. `encoding>url_double|lexical>alt_case_keywords`). Without a seed run it emits every ordered (A, B) pair over `{lexical, encoding, structural}`; with `ADAPTIVE_SEED_RUN=<run_id>` set, it loads that run's per-mutator bypass rates and ranks the pairs by `rate(A) × rate(B)` so the composer focuses on what actually bypassed in the seed. `ADAPTIVE_TOP_K` caps the pair count for faster iteration. Skips `context_displacement` / `multi_request` because their `request_overrides` chains don't compose through the string-only `payload.payload` interface.
- **Noop (identity) mutator** (`mutators/noop.py`, `complexity_rank=0`) — emits the payload byte-identical to the YAML. Purpose-built for the benign-corpus FPR workflow: a real user doesn't send `ApPlE jUiCE` to a search box, so case-permuted or encoded benign bodies would conflate "WAF over-blocks realistic traffic" with "WAF over-blocks semi-scrambled traffic". Pair with `--classes benign --mutators noop` for the clean FPR sweep; the ladder CLI's `--fpr-steps` consumes runs produced this way (see Ladder section).
- **Request timeout** — default 30s (was 15s). DVWA cmdi's 4s ping × PHP-FPM worker queue was timing out at 15s under MAX_CONCURRENCY=10; 30s + concurrency=4 fixes it cleanly.
- **YAML package-data** — `pyproject.toml` has `[tool.hatch.build.targets.wheel.force-include]` for every `payloads/*.yaml` and `targets.yaml`. Without this, wheel-installed package loses the corpus.
- **⚠ Rebuild the engine image after editing `targets.yaml` or any payload YAML** — `docker compose --profile engine run --rm engine ...` uses the built image, so stale image = stale routes. Confirmed bug: the first Phase-7 run used the old image because `docker compose build engine` was kicked off concurrently with the run.
- **Reproducibility metadata in `manifest.json`** — every run records `seed` (null unless `--seed <int>` was passed — the forcing function for any future randomised flow) + `environment` (platform, cpu model, cpu count, memory, python version, wafeval version, docker version when available). Captured by `runner/environment.py` at run start; all fields are best-effort so the same code works on host venv + inside the container (docker CLI absent → field omitted, not fatal). Lets cross-machine runs be correlated after the fact: "this bypass rate came from a run on kernel X with CPU Y on Python Z."
- **`targets.yaml` post-Phase-7+ additions** — SSTI and XXE sinks are now wired on **DVWA** (routed through `/vulnerabilities/xss_r/` reflective sink) and **Juice Shop** (routed through `/rest/products/search`) with a per-endpoint `trigger: { kind: status, code: 200 }`. The lab can't *exploit* template-injection or XML-entity flaws (no Jinja, Twig, or XML parser in the stack), but the WAFs get to inspect the syntax on the wire — same convention as the other WAF-view-only classes. Cmdi and lfi on DVWA also got a `status: 200` trigger override because the per-payload regexes (`uid=\d+`, `root:`) had 83% / 94% baseline_fail under the previous regime: brace-expansion / `${IFS}` payloads expand differently under DVWA's `/bin/sh` (no bash), and DVWA has `open_basedir` set so relative `../`-traversals don't actually leak `/etc/passwd` even at security=low. graphql on Juice Shop was switched from `POST/form` (100% baseline_fail) to `GET/query` because `/rest/products/search` only accepts GET. Net effect: every class now produces meaningful baseline-eligible rows on every target where it's listed.

### Analyzer / Reporter (`engine/src/wafeval/{analyzer,reporter}/`)

- Two lenses: `true_bypass` (paper methodology, DVWA anchor, baseline-confirmed only) and `waf_view` (baseline-agnostic, used for Juice Shop where triggers vary per payload).
- `waf_view` denominator excludes `baseline_fail + error` (it's "requests that actually tested the WAF", not "everything on disk").
- Reporter renders `—` for cells where `n < 5` (Wilson CI > ±0.4 at that size is misleading).
- Hall of Fame section (`reporter/hall_of_fame.py`) lists top-N variants by how many (waf × target) cells they bypass. **Post-Phase-7+ adds `dedup_by_payload=True`** which collapses near-duplicate variants of the same payload into one leader row — used by the consolidated headline reporter so the gallery shows 15 distinct payloads, not 11 variants of `admin'-- -`.
- **Latency profile (Appendix B)** — `analyzer/latency.py` computes p50 / p95 / p99 of `waf_ms` per (waf, target) on non-baseline routes, excluding `error` and `baseline_fail` rows (those don't reflect real WAF processing cost). The Markdown reporter renders it right before the Bibliography; a long p99 tail correlates with ML-agent cold-cache or expensive regex backtracking.
- **Three-way verdict split** (post-Phase-7): `BLOCKED` covers hard-deny signatures (403/406/501 or 5xx + WAF body marker); `BLOCKED_SILENT` covers the silent-sanitise case (2xx response, but the exploit marker that fired on baseline is absent — e.g. CRS's JSON-SQL rewrite or open-appsec's quiet strip); `ALLOWED` is the real bypass. Both block verdicts count as WAF wins in the denominator and never in the numerator; `per_payload.csv` / `/runs/{id}/per-payload` emit a separate `n_blocked_silent` tally, the dashboard VerdictBadge renders it teal, and the Hall of Fame includes silent blocks when computing the (waf × target) eligibility denominator.
- **Single-run paranoia ablation** (`analyzer/paranoia.py`, post-Phase-7+) — pivots a DataFrame containing both PL1 and PL4 variants (e.g. `modsec` + `modsec-ph`) into a side-by-side `(family, mutator) → rate_pl1, rate_pl4, delta_pp` table. The single-run analogue of `analyzer.ladder` — the ladder module needs one run-id per ablation step, but the headline scan deliberately includes both PL levels in the same run, so the pivot happens in-frame instead. The consolidated headline reporter calls this to render section 5.
- **Generalised chart helpers** (`analyzer/charts.py`, post-Phase-7+) — every chart now takes a `lens=` parameter (defaults to `true_bypass` for back-compat with the per-run reporter) and intersects `_WAF_ORDER` / `_MUTATOR_ORDER` with the WAFs / mutators actually present in the input. New chart types: `pooled_waf_target_heatmap`, `latency_vs_bypass_scatter`, `waf_class_heatmap`. Output filenames now include the target and lens (`heatmap_mutator_waf_juiceshop_waf_view.png` etc.) so per-run and consolidated reports can coexist in the same `figures/` tree.

### API / Dashboard (`--profile dashboard`)

- FastAPI on 127.0.0.1:8001, read-only.
- Endpoints: `/health`, `/runs`, `/runs/latest`, `/runs/{id}/{manifest|live|bypass-rates|per-payload|per-variant|records/.../...|figures/...|hall-of-fame|report}`, `/runs/compare`, `/runs/combined?ids=a,b,c`.
- Dashboard on 127.0.0.1:3000 (nginx-served Vite bundle + `/api/*` proxy). Tabs: Live Run, Results (heatmap + table + baseline_fail column), **Cross-WAF** (multi-run provenance heatmap), **Hall of Fame**, Payload Explorer (12-class dropdown), Compare Runs.
- The Cross-WAF tab surfaces the same 6-column headline table as `report-combined.md` — pick the runs to merge, reorder for last-in-list provenance, switch lens/target, tooltip reveals each cell's source run.

### Combined (cross-run) report

- `wafeval report-combined --run-ids a,b,c --out-id combined` merges N runs into a single report. For WAFs that appear in more than one run, the **last run in the list wins** (so put the canonical/freshest run for each WAF at the end).
- Outputs: `results/processed/<out-id>/{per_variant,per_payload,bypass_rates}.csv` and `results/reports/<out-id>/report-combined.{md,tex}`.
- The headline table has one column per WAF present across the merged runs, ordered `modsec, coraza, shadowd, openappsec, modsec-ph, coraza-ph, <unknowns alphabetical>`. DVWA is the true-bypass anchor; an Appendix lists waf-view rates across every target.
- Shortcut: `make report-combined RUN_IDS=a,b,c [OUT_ID=combined]` (containerised) / `make report-combined-host RUN_IDS=a,b,c` (host venv).
- `results/reports/combined-phase7/` is the headline 4-WAF comparison shipped in Phase 7 (merges `research-20260421T141410Z` + `paranoia-high-20260421T151636Z` + `openappsec-20260421T162710Z`).

### Consolidated headline reporter (post-Phase-7+)

- `wafeval report-headline --attack-run-id <a> --adaptive-run-id <b> --benign-run-id <c> --out-id headline-<date>` fuses up to three input runs into a single 11-section Markdown report at `results/reports/<out-id>/report-headline.md` plus seven figures under `results/figures/<out-id>/`. Adaptive and benign run-ids are optional — the report degrades gracefully when either is absent.
- Sections, in order: provenance · pooled WAF×target heatmap · attack-vs-FPR table (block-attack ÷ block-benign ratio per WAF) · Table 1 (mutator × WAF, anchored on Juice Shop because DVWA collapses to 0% across the board) · compositional uplift (per-target so the dilution that hides the lift in cross-target pooling doesn't wash it out) · paranoia ablation (PL1 vs PL4 from the same run, via `analyzer/paranoia.py`) · WAF×class heatmap · latency-vs-bypass scatter · deduped Hall of Fame · waf_view appendix · latency appendix · bibliography.
- Unlike `report-combined`, this reporter **does not dedup by WAF** — it expects the input runs to be disjoint in (waf, mutator) space (the attack run owns the base mutators, the adaptive run owns rank-6/7, the benign run owns `noop`). Concatenation is therefore safe.
- Currently host-venv-only (the `consolidated.py` reporter is on the local code path, not in `waflab/engine:phase3` until a rebuild rolls it forward). Run via `./scripts/with-nix-libs engine/.venv/bin/python -m wafeval report-headline ...`. A `make report-headline` target can wire this once the engine image is rebuilt to include it.
- Headline artefact: [results/reports/headline-v2-20260429/report-headline.md](results/reports/headline-v2-20260429/report-headline.md) plus the seven PNG/SVG figures under `results/figures/headline-v2-20260429/`.

### Ladder / ordered-ablation reporter

- `wafeval ladder --steps critical:<id1>,high:<id2>,medium:<id3>,low:<id4> --target juiceshop --out-id openappsec-ladder` emits a line chart (PNG + SVG) + Markdown report where each "step" is a separate run. One line per (waf, mutator); x-axis is the caller-supplied step order. Generic over the knob — works equally for CRS paranoia ablations or any other one-dimensional sweep.
- Outputs: `results/processed/<out-id>/ladder.csv`, `results/figures/<out-id>/ladder.{png,svg}`, `results/reports/<out-id>/report-ladder.md`.
- For open-appsec specifically, [tests/openappsec_ladder.sh](tests/openappsec_ladder.sh) (`make ladder-openappsec`) automates the full `critical → high → medium → low` sweep: rewrites `minimum-confidence` in `wafs/openappsec/localconfig/local_policy.yaml`, waits for the smart-sync sidecar to reload, re-runs the corpus at each level, then invokes `wafeval ladder` to produce the combined artefact. **Needs `make up-ml` first; ≈40 min wall-clock** on a modest workstation. The script leaves the policy file on whatever level ran last; re-set to `critical` afterwards.
- Headline 4-level ablation shipped in `results/reports/openappsec-ladder-20260423T084442Z/`. See "Research findings so far" below for the (unexpectedly flat) result.
- Paranoia-level ladder: [tests/paranoia_ladder.sh](tests/paranoia_ladder.sh) / `make ladder-paranoia` sweeps modsec-ph + coraza-ph through PL 1→2→3→4 by flipping `MODSEC_PARANOIA_PH` / `CORAZA_PARANOIA_PH` env vars on the compose anchors (`x-modsec-env-ph`, `x-coraza-ph-directives`), force-recreating the six PH services between levels. Defaults preserve the canonical PL4 behaviour when the envs are unset, so existing `make up-paranoia` flows are untouched. Needs `make up` + `make up-paranoia` first; budget ~60 min for the full 201-payload corpus.
- **FPR / ROC overlay** — `wafeval ladder --steps pl1:attack-run-1,... --fpr-steps pl1:benign-run-1,...` joins a second set of benign-corpus runs (produced by `--classes benign --mutators noop`) onto the ladder. The report gains a *False-positive rate (benign corpus)* table (row per WAF, column per step) and the chart overlays a dashed black line per WAF so the reader can read the attack/FPR trade-off directly. CSV outputs grow a sibling `ladder-fpr.csv` so the joined axes are analyst-friendly. See the `paranoia-ladder-with-fpr-*` report under `results/reports/` for the shipping example.

### Runtime knobs

| Env / CLI flag | Default | Purpose |
|---|---|---|
| `MAX_CONCURRENCY` | 10 in compose, **4** for cmdi-heavy runs | Parallel requests cap — honour DVWA PHP-FPM pool limit. |
| `REQUEST_TIMEOUT_S` | 30 | Per-request httpx timeout. |
| `RESPONSE_SNIPPET_BYTES` | 65536 | Bytes of response body saved in each `*.json` record. |
| `SHADOWD_ENFORCE` | `true` | Translate shadowd verdicts into 403s. |
| `SHADOWD_FALLBACK_BLOCK` | `false` | Regex safety net in shadowd-proxy; leave off now that real daemon works. |
| `CORAZA_BLOCKING_MODE` | `on` | Force `SecRuleEngine On` — CRITICAL, default-off means zero blocks. |
| `OPENAPPSEC_DB_*` | `openappsec` / `openappsec_dev_only` | Postgres creds for tuning service. |

### Host-OS gotchas (NixOS)

- `make` is not in PATH. Use `nix-shell -p make --run "make <target>"` or call the underlying commands directly.
- Python's numpy/pandas needs `libstdc++` + `zlib` on `LD_LIBRARY_PATH`. Centralised in [scripts/with-nix-libs](scripts/with-nix-libs) — every host-venv Makefile target (`test-engine`, `report-host`, `run-host`, `report-combined-host`, `ladder-host`, `api-host`) is prefixed with it, and `tests/_lib.sh` delegates to the same wrapper. No-op on non-NixOS hosts.

### Compose profiles gotcha

`docker compose down` only stops services in the **default** profile — anything started under `--profile ml` / `--profile paranoia-high` / `--profile dashboard` keeps running. Use `make down-all` (or `docker compose --profile paranoia-high --profile ml --profile dashboard --profile engine --profile report down`) to tear the whole lab down.

---

## Quickstart

Requirements: Docker 25+, Docker Compose v2, ~6 GB free RAM on first boot (WebGoat is heavy). On NixOS, install with `nix-shell -p docker docker-compose`.

```bash
cp .env.example .env          # optional; override ports / paranoia / enforce flags

# Validate compose under every profile
docker compose config --quiet
docker compose --profile paranoia-high --profile ml --profile dashboard config --quiet

# Bring up the core matrix (3 targets + 9 WAF×target + baselines)
docker compose up -d --build --wait --wait-timeout 600

# Acceptance suite
bash tests/phase2.sh
```

After `docker compose up`, the entire WAF × target matrix is reachable through a single Traefik front door at **http://127.0.0.1:8000**. Traefik routes by `Host` header — no `/etc/hosts` edits required:

```bash
# baseline (direct to target, no WAF)
curl -H 'Host: baseline-dvwa.local'      http://127.0.0.1:8000/login.php
curl -H 'Host: baseline-juiceshop.local' http://127.0.0.1:8000/

# through a WAF (SQLi attack — 403 = blocked, 200 benign = passed)
curl -H 'Host: modsec-juiceshop.local'        "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: coraza-juiceshop.local'        "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: shadowd-juiceshop.local'       "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: openappsec-juiceshop.local'    "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"   # needs --profile ml
```

Traefik dashboard (read-only, loopback): http://127.0.0.1:8088/dashboard/

### Optional profiles

```bash
docker compose --profile paranoia-high up -d --wait   # + modsec-ph-* + coraza-ph-* (6 services)
docker compose --profile ml up -d --wait              # + real open-appsec ML agent + 4 standalone sidecars
docker compose --profile dashboard up -d --build --wait  # + api (FastAPI) + dashboard (React)
```

With `--profile dashboard`:

- **Dashboard** — http://127.0.0.1:3000 — tabs: Live Run, Results, Cross-WAF, Hall of Fame, Payload Explorer, Compare Runs.
- **API** — http://127.0.0.1:8001 — `/docs` for live OpenAPI.

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

**With `--profile paranoia-high`** (+6): `modsec-ph-*`, `coraza-ph-*`.

**With `--profile ml`** (+3): `openappsec-*` — all routed to the single `openappsec` container which splits by Host-header internally.

All three targets have engine endpoints — the paper's 4 WAFs × 3 targets matrix is now fully wired. WebGoat's `expect_auth=true` endpoints use the `login.kind=webgoat` bootstrapper (register-then-login + per-lesson prime GETs).

---

## Running experiments

```bash
# Full 201-payload corpus × 5 mutators × 3 targets × 4 WAFs (PL1) — ~30 min at MAX_CONCURRENCY=4
# (post-WebGoat-restore: budget is higher than the pre-phase-7-close 2-target runs)
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 --name waflab-engine \
  engine run \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "research-$(date -u +%Y%m%dT%H%M%SZ)"

# Paranoia-high comparison
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 \
  engine run --wafs baseline,modsec-ph,coraza-ph \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "paranoia-high-$(date -u +%Y%m%dT%H%M%SZ)"

# open-appsec only (needs --profile ml)
docker compose --profile engine --profile ml run --rm -e MAX_CONCURRENCY=4 \
  engine run --wafs baseline,openappsec \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "openappsec-$(date -u +%Y%m%dT%H%M%SZ)"

# Generate reports + Hall of Fame for any run
nix-shell -p stdenv.cc.cc.lib zlib --run "LD_LIBRARY_PATH=\$(nix-build --no-out-link '<nixpkgs>' -A stdenv.cc.cc.lib)/lib:\$(nix-build --no-out-link '<nixpkgs>' -A zlib)/lib:\$LD_LIBRARY_PATH engine/.venv/bin/python -m wafeval report --run-id <RUN_ID>"
```

Results under `results/{raw,processed,figures,reports}/<run_id>/`. Each run produces 3 CSVs, 8 figures (PNG+SVG), `report.md` + `report.tex`.

---

## Testing

`tests/phase<N>.sh` is the canonical acceptance suite. On NixOS each script self-reexecs under `nix-shell` for libstdc++/zlib.

```bash
bash tests/phase1.sh   # WAF liveness
bash tests/phase2.sh   # routing matrix (9 WAF×target, WAF engagement)
bash tests/phase3.sh   # engine core + lexical mutator end-to-end
bash tests/phase4.sh   # 5 mutators × corpus minima
bash tests/phase5.sh   # analyzer + reporter
bash tests/phase6.sh   # FastAPI + dashboard
bash tests/phase_paper.sh  # --corpus paper_subset + encoding≥lexical invariant
bash tests/shadowd_whitelist.sh  # shadowd whitelist-mode PoC (needs `make up`)
```

Engine unit tests (144 passing):

```bash
nix-shell -p stdenv.cc.cc.lib zlib --run "LD_LIBRARY_PATH=\$(nix-build --no-out-link '<nixpkgs>' -A stdenv.cc.cc.lib)/lib:\$(nix-build --no-out-link '<nixpkgs>' -A zlib)/lib:\$LD_LIBRARY_PATH engine/.venv/bin/python -m pytest engine/tests -q"
```

---

## Corpus

**12 vuln classes, 297 payloads** — plus a separate **benign corpus** for FPR measurement (see bottom row) — (`engine/src/wafeval/payloads/*.yaml`):

| Class | # | Notes |
|---|---:|---|
| sqli | 42 | Classical + JSON-SQL (Team82) + Unicode + ODBC + scientific notation + hex/CHAR |
| xss | 35 | Script tag + handlers + Unicode + entity-split + mXSS + SVG animate + data-URI |
| cmdi | 15 | Pipe, semicolon, backtick, $(), $IFS, brace expansion (DVWA anchor) |
| lfi | 15 | Path traversal + PHP wrappers + null byte + encoded |
| **ssti** | **25** | Jinja2, Twig, Freemarker, Velocity, ERB, Pug, Smarty, Mako, Handlebars, Tornado, JSP-EL, Spring SpEL — now exercised on DVWA + Juice Shop via reflective sinks |
| **xxe** | **25** | External entities + parameter entities + OOB exfil + XInclude + SOAP + SVG + OOXML + UTF-7/16 + CDATA — now exercised on DVWA + Juice Shop |
| **nosql** | **25** | MongoDB `$ne`/`$regex`/`$where` + form-encoded operators + `$function` (4.4+) + mapReduce + `$lookup` |
| **ldap** | **25** | Wildcard + OR/AND injection + AD-specific (sAMAccountName, OID matching rules) + extensibleMatch |
| **ssrf** | **25** | AWS/GCP/Azure/DO/Alibaba metadata + decimal/hex/octal/mixed IP + IPv6 mapped + file://, gopher://, dict://, ldap:// + URL userinfo trick |
| **jndi** | **25** | Log4Shell base + LDAPS/RMI/CORBA/IIOP + lower/upper/env/sys/date/marker lookups + base64 + URI-encoded + JNDI-Exploit-Kit gadgets |
| **graphql** | **25** | Introspection + typed/deep/directives + batch DoS + alias overload + fragment cycle + circular fragments + variable injection + nested SQLi/cmdi/JNDI/XXE smuggling |
| **crlf** | **25** | Response splitting + Set-Cookie smuggle + LF/CR-only + Content-Type confusion + CSP/CORS clobber + cache poisoning + chunked-trailer + UTF-8/HTML-entity encoding |
| **benign** | **15** | Realistic product searches + usernames + natural-English "near-signal" (apostrophes, nested quotes, SQL-keyword phrases). Paired with the `noop` mutator for clean FPR measurement; excluded from default runs (load via `--classes benign`). |

Also shipped as a single-file **paper-replication subset** — 20 SQLi + 20 XSS in `payloads/paper_subset.yaml`, drawn from the same academic literature (PayloadsAllTheThings, OWASP WSTG, SecLists) that Yusifova (2024) cited. Not paper-verbatim (the thesis' exact payload list isn't bundled here) but sized + split to match. Load with `wafeval run --corpus paper_subset`; `tests/phase_paper.sh` is the dedicated acceptance script. The subset is a fixed point — drifting `sqli.yaml` / `xss.yaml` won't change these 40 entries, so reproduction numbers stay comparable over time.

Triggers default to `any_of` so one entry fires on DVWA ("First name") or Juice Shop ("SQLITE_ERROR"). WAF-view-only classes use `TriggerStatus: 200` — the endpoint always 200s, so the WAF's decision drives the verdict. Benign entries use the same `status: 200` pattern since "baseline returned 200" simply means the backend handled the realistic request.

---

## Research findings so far

**PL1 baseline** (run `research-20260421T141410Z`, 33,545 datapoints):

- **Only `encoding` leaks** against CRS v4 on DVWA (~5% bypass for ModSec + Coraza). Paper reported ~27% but that's CRS 3.x; v4's libinjection closed the gap.
- **Shadow Daemon is meaningfully weaker** on Juice Shop — up to 97% bypass on `encoding`. Its 120-filter library doesn't include JNDI, CRLF, or modern SQLi dialects. This is the *cleanest WAF architecture comparison* in the dataset.
- **CRLF payloads bypass universally** (72-91% across all 3 WAFs on Juice Shop) — the payload lands in a URL-query value, not a header sink, so WAFs don't cross-check for embedded control chars.
- **JNDI / LDAP / NoSQL / SSRF** pass DVWA route (CRS's XSS rules catch them incidentally) but slip Juice Shop's route (CRS JSON-body rules don't fire on URL query).

**PL1 vs PL4** (run `paranoia-high-20260421T151636Z`):

- **Coraza PL4 closes the encoding gap entirely** (5.7% → 0% on DVWA, 55% → 0% on Juice Shop).
- **ModSec PL4 *does not*** — its PARANOIA env var doesn't unlock the JSON-SQL plugin rules. Real-world deployment gotcha worth flagging.

**open-appsec** (runs `openappsec-20260421T162710Z` at `critical`, plus the 4-level ladder `openappsec-{critical,high,medium,low}-2026042{2,3}T*`):

- Per-mutator bypass rate on Juice Shop (waf_view) from the ladder run: lexical ≈ 43%, encoding ≈ 51%, structural ≈ 21%, context_displacement ≈ 20%, multi_request ≈ 56%. The ML agent holds structural / context-displacement *better* than CRS holds the same mutators (both sit ~20%), but is *more leaky* on lexical and multi-request than CRS on JSON bodies.
- **The `minimum-confidence` ladder is flat.** Sweeping `critical → high → medium → low` moves every mutator by <1 percentage point — well inside the Wilson CIs at this N (~±4 pp). That's an empirical result, not a tooling bug: the agent's classifier appears bimodal on this corpus, so loosening the threshold doesn't reclassify payloads. The knob would only matter on genuinely ambiguous traffic, which attack-only payloads don't produce. A true ROC-shaped curve needs a benign-traffic corpus (parked in [TODO.md](TODO.md)).

**CRS paranoia-level ablation** (smoke run `paranoia-ladder-20260423T130814Z`, SQLi × lexical mutator on DVWA, waf_view lens):

- **Coraza closes the lexical bypass at PL2** (3.6 % → 0 %). PL3 and PL4 add no further signal over PL2 for this mutator class — useful input for operators choosing between false-positive risk and enforcement strength.
- **ModSec stays flat at 3.6 % across all 4 levels.** Empirical confirmation of the known `PARANOIA=N` env-var limitation already flagged in this doc — the image's env var doesn't reach the rules Coraza's `setvar:tx.blocking_paranoia_level=N` activates, so turning the knob up is a no-op for the payload families the image's env actually governs. Real-world deployment gotcha worth a paper footnote.

**False-positive rate overlay** (smoke run `paranoia-ladder-with-fpr-20260423T134224Z`, attack = SQLi × lexical, benign = 15-payload realistic-traffic corpus × `noop` mutator, DVWA):

- **Coraza PL4 blocks 100 % of benign traffic** — every single realistic string in the benign corpus (`apple juice`, `banana`, `alice`, `admin`, `42`, etc.) returns 403. Coraza PL4 is security-effective but operationally unusable for real users; the FPR cost is the whole denominator.
- **ModSec PL4 FPR stays at 0 %**, matching its flat bypass line — once again the `PARANOIA=N` env lever doesn't reach the rules that over-block benign text (which is consistent with it also not reaching the rules that block attacks).
- Both WAFs at PL1: 0 % FPR, ~3.6 % bypass on lexical. So PL1 is the operationally sane default; PL4 on Coraza only pays off if the deployment can absorb total benign loss, which real deployments cannot.
- Methodology note: ladder's built-in FPR overlay (`--fpr-steps`) joins a benign run per step onto the attack ladder, inverting the waf_view bypass rate (`1 − rate`) to get FPR. Wilson CIs flip symmetrically; CSVs grow a sibling `ladder-fpr.csv` so analysts can re-slice without recomputing.

**Adaptive composition beats every single mutator** — headline run `adaptive-headline-20260424T134931Z` (seeded on the fresh `phase4-20260424T083836Z`, DVWA+Juice Shop, paper_subset SQLi+XSS, 4 WAFs):

- **adaptive (rank 6, pair composer)** — pooled **44.4%** (n=504) across modsec/coraza/shadowd on DVWA. Per-WAF: modsec 29.2%, coraza 29.2%, **shadowd 75.0%**. Against the same corpus, the best single-category mutator (`encoding`) tops out at ~16% — a **2.7× lift** from stacking two transforms.
- **adaptive3 (rank 7, triple composer)** — pooled **57.1%** (n=252). Per-WAF: modsec 38.1%, coraza 38.1%, **shadowd 95.2%** — near-total bypass. Each additional composition layer strictly increases bypass rate, matching the paper's complexity-monotonicity thesis.
- Representative winning pair: `lexical>whitespace_inflate|structural>concat_keywords` — the whitespace trick defeats CRS's literal-match and the string-concat unwinds past libinjection's normaliser.
- Reproduce via `make run-adaptive SEED_RUN=<research-run>`; multi-gen evolution via `make run-adaptive SEED_RUN=<…> ITER=3`. See [tests/adaptive_evolution.sh](tests/adaptive_evolution.sh).

**Earlier pair-only smoke** `adaptive-smoke-20260423T123145Z` (modsec+DVWA, SQLi-only): ModSec + CRS 4.25 on DVWA SQLi — ~40% true-bypass rate (134/335) stacking two base mutators. Superseded by the 4-WAF headline above but preserved for traceability.

### Latest run set — `headline-v2-20260429` (expanded corpus)

Three runs against the 297-payload corpus, all 7 WAF variants × 3 targets:

| Run | Run-id | Datapoints | Verdict mix |
|---|---|---:|---|
| Attack | `attack-v2-20260429T030310Z` | 123 676 | 28 701 allowed / 56 334 blocked / 973 silent / 37 611 baseline_fail / 57 error |
| Adaptive | `adaptive-v2-20260429T032000Z` | 15 904 | 2 719 allowed / 5 715 blocked |
| Benign | `benign-v2-20260429T032003Z` | 315 | 244 allowed / 34 blocked / 37 baseline_fail |

Pooled bypass on Juice Shop (waf_view lens, all WAFs) — every class now has signal:

| Class | rate | n | Class | rate | n |
|---|---:|---:|---|---:|---:|
| crlf | **64.3 %** | 3 459 | nosql | 43.9 % | 3 476 |
| ssrf | 51.2 % | 3 687 | jndi | 32.3 % | 3 796 |
| graphql | 50.1 % | 3 400 | xxe | **21.8 %** | 3 870 |
| ldap | 47.2 % | 3 715 | sqli | 8.99 % | 4 385 |
| ssti | **45.3 %** | 2 575 | | | |

Per-WAF (Juice Shop) — `coraza-ph` clears every class but at 81 % FPR; the rest cluster 38–41 % with `shadowd` at 76 %:

| WAF | bypass | FPR (benign, all targets) |
|---|---:|---:|
| `modsec` | 37.6 % | 0 % |
| `coraza` (PL1) | 40.5 % | 0 % |
| `shadowd` | **76.0 %** | 0 % |
| `openappsec` | 40.9 % | 0 % |
| `modsec-ph` (PL4) | **37.6 % — identical to `modsec`** (env-var gotcha re-confirmed) | 0 % |
| `coraza-ph` (PL4) | **6.6 %** | **81 %** (operationally unusable) |

The headline report rendered from these three runs lives at [results/reports/headline-v2-20260429/report-headline.md](results/reports/headline-v2-20260429/report-headline.md). The 11-section consolidated reporter and the underlying single-run paranoia pivot were both shipped this session — see "Reporter" below.

---

## Architecture

```
             127.0.0.1:8000
                  │
      ┌───────────▼───────────┐        routes by Host: header
      │        traefik        │────────────────────────────────────┐
      └───────────────────────┘                                    │
                  │                                                │
   ┌──────────────┼──────────────┬───────────────┐                 │
   ▼              ▼              ▼               ▼                 ▼
modsec-*      coraza-*      shadowd-*       openappsec-*       baseline-*
                                          (--profile ml,
                                          single container)
   │              │              │               │                 │
   │  BACKEND     │  BACKEND     │  BACKEND      │  BACKEND        │
   └──────────────┼──────────────┴───────────────┴─────────────────┘
                  ▼
         ┌────────┴────────┐
         │        │        │
        dvwa   webgoat  juiceshop
       + dvwa-db
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full detail. Developer onboarding in [docs/DEV.md](docs/DEV.md).

---

## Safety & legality

- All host ports bound to `127.0.0.1` — never `0.0.0.0`.
- DVWA / WebGoat / Juice Shop are intentionally vulnerable. Never expose them to the LAN.
- DB passwords default to `*_dev_only`; rotate via `.env` if your disk leaves your machine.
- The payload loader rejects destructive patterns (`DROP TABLE`, `rm -rf`, fork bombs, `/etc/shadow`). The multi_request mutator re-audits every generated step.
- Every external image in [docker-compose.yml](docker-compose.yml) is pinned to a SHA256 digest (`image: name:tag@sha256:<digest>` form), including the DVWA / open-appsec images that only ship a `:latest` tag upstream. Pulls reproduce byte-for-byte. To refresh a pin: `docker pull <name>:<tag> && docker image inspect <name>:<tag> --format '{{index .RepoDigests 0}}'`, swap the digest in compose.

---

## Citation

Replicates the methodology of:

> Yusifova, J. *Evasion of Web Application Firewalls Through Payload Obfuscation: A Black-Box Study.* Bachelor's thesis, Baku Higher Oil School.

Phase-7 research extensions draw on:
- [PayloadsAllTheThings — WAF Bypass collection](https://github.com/kh4sh3i/WAF-Bypass)
- [Claroty Team82 — JS-ON: Security-OFF](https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf)
- [OWASP CRS — A new rule to prevent SQL in JSON](https://coreruleset.org/20230222/a-new-rule-to-prevent-sql-in-json/)
- [zecure/shadowd_python connector — wire protocol reference](https://github.com/zecure/shadowd_python/blob/master/shadowd/connector.py)
- [open-appsec docker-compose deployment guide](https://docs.openappsec.io/getting-started/start-with-docker/deploy-with-docker-compose)
