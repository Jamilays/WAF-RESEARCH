# Architecture

## Phase 6 — delivered

Everything through Phase 5, plus a read-only FastAPI backend and a Vite/React/TS/Tailwind dashboard. Both ship under `--profile dashboard` and reflect the bind-mounted `results/` tree without spawning engine runs themselves.

```
host                    bridge network `waflab`
────────────            ────────────────────────────────────────
127.0.0.1:3000 ──► dashboard (nginx)  ──► static Vite bundle
                           │
                           │ /api/*  (nginx reverse-proxy)
                           ▼
127.0.0.1:8001 ──► api (uvicorn + wafeval.api)
                           │ read-only
                           ▼
                  ./results/{raw,processed,figures,reports}/
```

API surface (all GET):

| Route | Purpose |
|---|---|
| `/health` | liveness + version |
| `/runs` | list runs, newest-first, with manifest summary |
| `/runs/latest` | latest run's manifest |
| `/runs/{id}` | full manifest |
| `/runs/{id}/live` | processed count, verdict histogram, tail of recent records (polling) |
| `/runs/{id}/bypass-rates` | Wilson-CI'd bypass rates, both lenses |
| `/runs/{id}/per-payload` | per-(payload×waf×target) rollup |
| `/runs/{id}/per-variant` | paginated, filterable datapoint dump |
| `/runs/{id}/records/{waf}/{target}/{payload}/{variant}` | one full `VerdictRecord` (Payload Explorer drilldown) |
| `/runs/{id}/figures` + `/runs/{id}/figures/{file}` | served analyzer PNG/SVG |
| `/runs/{id}/report` | `report.md` contents as JSON |
| `/runs/compare?a=&b=` | side-by-side bypass-rate diff |

Dashboard tabs mirror prompt.md §11: Live Run (polls `live`), Results (heatmap + table from `bypass-rates`), Payload Explorer (`per-variant` + `records/…`), Compare Runs (`compare`). No charting library — the heatmap is a CSS grid with a green→red interpolation. Bundle < 200 KB gzipped.

## Phase 2 — routing matrix

### Topology

```
host                            bridge network `waflab`
────────────                    ────────────────────────────────────────
127.0.0.1:8000 ──── traefik ────┬──► modsec-<target>  ──┐
127.0.0.1:8088 ──── traefik                             │
                                ├──► coraza-<target>  ──┤
                                │                       │
                                ├──► shadowd-<target> ──┼──► target
                                │                       │     (one of:
                                └──► direct (baseline) ─┘      dvwa,
                                                              webgoat,
                                                              juiceshop)

   + shadowd  ───► shadowd-db  (Postgres 12)         [daemon analyzer]
   + dvwa     ───► dvwa-db     (MySQL 5.7)
   + dvwa-init: one-shot curl bootstrap (create schema, verify login)
```

### Routing contract

Traefik listens on `:80` inside the container, mapped to `127.0.0.1:${TRAEFIK_PORT:-8000}` on the host. Dynamic config in `routing/dynamic/routes.yml` declares 18 routers total (12 default + 6 paranoia-high-gated + 3 ml-gated). Each router matches `Host(\`<name>.local\`)` and forwards to the named service.

Why `Host`-header routing, not path-prefix? Matches the paper's test bench and keeps the payload path unchanged — a mutation engine does not want `/<waf>/<target>/<path>` rewriting to interfere with the WAF's view of the request.

### Services (default profile)

| Service | Image | Internal port | Role |
|---|---|---|---|
| `traefik` | `traefik:v3.6.13` | 80, 8080 | Hostname-based routing for the whole matrix |
| `dvwa-db` | `mysql:5.7.44` | 3306 | DVWA's persistent data |
| `dvwa` | `vulnerables/web-dvwa:latest` | 80 | Target 1 |
| `dvwa-init` | `curlimages/curl:8.8.0` | — | One-shot schema bootstrapper |
| `webgoat` | `webgoat/webgoat:v2025.3` | 8080 | Target 2 |
| `juiceshop` | `bkimminich/juice-shop:v19.2.1` | 3000 | Target 3 |
| `shadowd-db` | `zecure/shadowd_database:12.4` | 5432 | Shadow Daemon analyzer storage |
| `shadowd` | `zecure/shadowd:2.2.0` | 9115 | Shadow Daemon analyzer |
| `modsec-{dvwa,webgoat,juiceshop}` | `owasp/modsecurity-crs:4.25.0-nginx-alpine-202604040104` | 8080 | Same ModSec+CRS, one instance per target |
| `coraza-{dvwa,webgoat,juiceshop}` | `waflab/coraza:phase1` (local) | 80 | Same Coraza+CRS, one instance per target |
| `shadowd-{dvwa,webgoat,juiceshop}` | `waflab/shadowd-proxy:phase1` (local) | 80 | Shadow Daemon JSON-protocol proxy, one per target |

Profile-gated extras:

- `--profile paranoia-high`: `modsec-ph-{dvwa,webgoat,juiceshop}` + `coraza-ph-{dvwa,webgoat,juiceshop}`
- `--profile ml`: `openappsec` (one agent-unified container — NGINX + Check Point's ML attachment module in a single process, multiplexing the 3 `openappsec-*.local` hostnames via Host-header-matched server blocks) + standalone sidecars (`openappsec-smartsync`, `openappsec-shared-storage`, `openappsec-tuning`, `openappsec-db` / Postgres 16)

### Why one WAF instance per target

Each of our WAFs (ModSec, Coraza, shadowd-proxy) takes a single `BACKEND` env var and proxies to it. Running one instance per target means:
- The paper's fairness criterion (identical CRS rules / same runtime settings, one backend each) is preserved.
- The compose file declaratively expresses the matrix — no runtime routing logic inside the WAF containers.
- Cost is low: each WAF instance is 20-50 MB RAM; 9 instances total ≈ 300 MB.

### Why Shadow Daemon needs a custom proxy

Shadow Daemon publishes only language-level connectors (PHP, Perl, Python). Putting it in front of arbitrary HTTP targets requires a small Python proxy that speaks the shadowd JSON wire protocol over TCP :9115 (see `wafs/shadowdaemon/proxy/proxy.py`). For DVWA, a Phase 3+ refinement will add the native PHP connector path for fairness with the paper.

### Why open-appsec is stubbed

Per the Phase 1 charter with the user. The stub keeps the `--profile ml` contract stable so the engine has predictable service names to target once the real agent is wired in.

## Future phases

- **7** — Test suite, doc polish, safety audit, real open-appsec wiring

## Safety — current footguns and mitigations

| Footgun | Mitigation |
|---|---|
| Intentionally vulnerable apps reachable from the LAN | All `ports:` entries bind to `127.0.0.1` explicitly (Traefik is the only host-exposed service) |
| Internal services (dvwa-db, shadowd-db, targets) accidentally exposed | No host `ports:` mapping; reachable only through the `waflab` Docker network |
| Destructive payloads in corpus (Phase 4+) | Mutators will reject any payload containing `DROP TABLE`/`rm -rf`/etc |
| Hard-coded DB credentials | `.env.example` names them `*_dev_only`; DBs are not host-exposed |
| Traefik dashboard unauth | Bound to loopback only (127.0.0.1:8088); still surfaces route topology, not secrets |
| Unpinned image tags | All images carry explicit version + digest-date tags; DVWA has no upstream versioning, so `:latest` is noted as an exception |
