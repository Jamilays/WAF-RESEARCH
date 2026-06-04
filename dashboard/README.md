# Dashboard — Phase 6

Vite + React + TypeScript + Tailwind. Read-only frontend for the engine's FastAPI
(see `engine/src/wafeval/api/`). Dark theme, no charting dependency — the heatmap
is a CSS grid with an interpolated color scale.

```
dashboard/
├── Dockerfile            # multi-stage: node build → nginx serve + /api proxy
├── nginx.conf            # SPA fallback + /healthz + /api/* → api:8001
├── package.json          # react 18, vite 5, tailwind 3
├── index.html            # mount point, <title>, tailwind body class
├── vite.config.ts        # dev proxy /api/* → 127.0.0.1:8001
├── tsconfig.json         # strict, bundler resolution
├── tailwind.config.js
├── postcss.config.js
└── src/
    ├── main.tsx, App.tsx, types.ts, api.ts, index.css
    ├── components/VerdictBadge.tsx
    └── tabs/{LiveRun,Results,CrossWAF,HallOfFame,PayloadExplorer,CompareRuns}.tsx
```

## Tabs

| Tab | Backend |
|---|---|
| **Live Run** | polls `/runs/{id}/live` every 2 s — progress bar, verdict histogram, last 30 records |
| **Results** | `/runs/{id}/bypass-rates`, lens switch (true_bypass / waf_view), heatmap + table |
| **Cross-WAF** | `/runs/combined?ids=…` — multi-run merge, reorderable provenance, lens/target switch, tooltip shows each cell's source run |
| **Hall of Fame** | `/runs/{id}/hall-of-fame?top_n=50` — variants ranked by (WAF × target) cells they bypassed |
| **Payload Explorer** | `/runs/{id}/per-variant` with filters → `/runs/{id}/records/...` drilldown. Detail pane renders `waf_route.waf_headers` as a name→value table when present (Coraza rule IDs, shadowd threat classes, etc.) |
| **Compare Runs** | `/runs/compare?a=&b=` — side-by-side delta, green/red color-coded |

## Dev

```bash
cd dashboard
npm install
npm run dev              # http://127.0.0.1:3000, proxies /api → :8001
# In another shell, start the API from the engine venv:
make api-host            # uvicorn at 127.0.0.1:8001
```

For production, the Dockerfile builds `vite build` output into an nginx image
and proxies `/api/*` to the `api` service inside the waflab network. `make
up-dashboard` starts both containers healthy-checked.

## Production build

```bash
make up-dashboard        # build + start api (port 8001) + dashboard (port 3000)
bash tests/phase6.sh     # acceptance test (API shapes + nginx proxy + HTML)
```
