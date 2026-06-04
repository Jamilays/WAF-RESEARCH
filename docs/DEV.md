# Developer onboarding (and future-AI-agent onboarding)

This file is the single stop for "how do I work on this repo?" — keep it current.

## Prerequisites

- Docker 25+ and Docker Compose v2
- GNU Make
- (For Coraza hacking) Go 1.23+
- (For Shadow Daemon proxy hacking) Python 3.12+
- ~4 GB free RAM, ~3 GB free disk for images

## Day-one flow

```bash
cp .env.example .env
make config          # validate compose across all 5 profiles
make up              # builds Coraza + shadowd-proxy, pulls the rest
make test-phase1     # runs the Phase 1 acceptance test suite
make test-phase6     # runs the full stack + FastAPI + dashboard acceptance
make up-dashboard    # bring up api + dashboard — http://127.0.0.1:3000
make api-host        # or run uvicorn from the host venv for rapid edit/reload
make logs SVC=modsecurity   # tail any service
make down            # stop everything (keeps volumes)
make clean           # nuke containers, volumes, and results/
```

### Three-run consolidated headline workflow (post-Phase-7+)

The richest report the lab can render fuses three runs — an attack
run, an adaptive-mutator run seeded on the attack run, and a benign
run for FPR — into a single Markdown report with seven figures. The
attack run takes ~20 minutes wall-clock at `MAX_CONCURRENCY=4`;
adaptive and benign each take under 2 minutes.

```bash
# 1) Attack run — 7 WAFs × 3 targets × 12 classes × 5 base mutators (~20min)
ATTACK="attack-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --profile engine run --rm --name waflab-engine-attack \
  -e MAX_CONCURRENCY=4 \
  engine run \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --max-concurrency 4 \
  --run-id "$ATTACK"

# 2) Adaptive run — rank-6 + rank-7 compositional, seeded on the attack run (~2min)
ADAPT="adaptive-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --profile engine run --rm --name waflab-engine-adapt \
  -e ADAPTIVE_SEED_RUN=$ATTACK -e MAX_CONCURRENCY=4 \
  engine run \
  --corpus paper_subset --classes sqli,xss \
  --mutators adaptive,adaptive3 --max-concurrency 4 \
  --run-id "$ADAPT"

# 3) Benign FPR run — classes=benign, mutators=noop (~1min)
BEN="benign-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --profile engine run --rm --name waflab-engine-benign \
  -e MAX_CONCURRENCY=4 \
  engine run --classes benign --mutators noop --max-concurrency 4 \
  --run-id "$BEN"

# 4) Render the consolidated headline report (host venv — needs the new
#    consolidated.py reporter that isn't in the engine image yet)
./scripts/with-nix-libs engine/.venv/bin/python -m wafeval report-headline \
  --attack-run-id "$ATTACK" \
  --adaptive-run-id "$ADAPT" \
  --benign-run-id "$BEN" \
  --anchor-target juiceshop \
  --out-id headline-$(date -u +%Y%m%d)
```

Output: `results/reports/headline-YYYYMMDD/report-headline.md` plus
seven figures under `results/figures/headline-YYYYMMDD/`. See
[results/reports/headline-v2-20260429/](../results/reports/headline-v2-20260429/) for the
shipping example.

### Building the academic paper PDF

The lab ships an end-to-end academic paper authored by Jamila Yusifova,
relocated to `RESEARCH/paper-yusifova-2026/` (was `results/reports/`).
PDF generation pipeline:

```bash
# 1) Render the architecture diagram from Mermaid source
cd RESEARCH/paper-yusifova-2026/figures
mmdc -i architecture.mmd -o architecture.png -w 2400 -H 1500 --backgroundColor white

# 2) Compile paper.md → paper.pdf via pandoc + xelatex
cd ..
docker run --rm -u 1000:100 -v "$(pwd):/data" -w /data pandoc/extra:latest paper.md \
  --bibliography=references.bib --citeproc \
  --toc --toc-depth=3 --number-sections \
  --pdf-engine=xelatex \
  -V geometry:margin=1in -V documentclass:report \
  -V linkcolor:blue -V urlcolor:blue \
  -o paper.pdf
```

The `pandoc/extra` image bundles xelatex with enough font coverage for
the corpus's special characters; the default `pdflatex` engine cannot
handle the curly quotes and em-dashes in the prose. Avoid `≤` / `≥`
in the source (use ASCII `<=` / `>=`) — even xelatex falls back to
the body Latin Modern font for those, which doesn't ship the glyphs.

### Building the AZTU conference deck

The 5-minute conference deliverables (slides + speech) live alongside the
paper. Reproduce both from the inline source in `RESEARCH/build/build.js`:

```bash
cd RESEARCH/build
npm install                      # one-time — installs pptxgenjs
node build.js                    # writes ../paper-yusifova-2026/presentation.pptx
soffice --headless --convert-to pdf \
  ../paper-yusifova-2026/presentation.pptx \
  --outdir ../paper-yusifova-2026/   # exports presentation.pdf

# Per-slide visual QA
pdftoppm -jpeg -r 100 \
  ../paper-yusifova-2026/presentation.pdf /tmp/slide
```

The deck is 19 slides — 8 content + 1 *Thank you* + appendix divider + 9
back-up slides for Q&A. Palette and typography are tokenised at the top of
`build.js`; every visual (architecture diagram, headline heatmap, mutator
example panel, compositional bar chart, recommendation quadrant grid) is
drawn from `pptxgenjs` primitives so the deck reproduces byte-for-byte
without external screenshots. Speaker script is at
[../RESEARCH/paper-yusifova-2026/speech.md](../RESEARCH/paper-yusifova-2026/speech.md)
with timing, stage directions, and Q&A flip-to map.

Requires Node 18+ and LibreOffice (`soffice`) for the PDF export. Poppler
(`pdftoppm`) is optional for the JPG QA loop. On NixOS:
`nix-shell -p nodejs libreoffice poppler_utils`.

### Frontend dev loop

```bash
cd dashboard
npm install
npm run dev          # Vite dev server on http://127.0.0.1:3000 (HMR)
# in another shell
make api-host        # uvicorn on 127.0.0.1:8001; Vite proxies /api/* to it
```

## Where things live

```
docker-compose.yml                 single source of truth for topology
Makefile                           UX wrapper around compose
.env.example                       ports + tunables
wafs/<waf>/                        each WAF owns its build context + README
  coraza/                          Go reverse proxy (main.go + Dockerfile)
  shadowdaemon/proxy/              Python async proxy (proxy.py + Dockerfile)
  modsecurity/                     config notes only (uses upstream image)
  openappsec/                      stub + real-enablement notes
targets/                           [Phase 2] vulnerable apps
routing/                           [Phase 2] Traefik / reverse-proxy config
engine/                            mutation + testing engine (Phases 3–5)
  src/wafeval/api/                 FastAPI read-only backend (Phase 6)
dashboard/                         Vite + React + TS + Tailwind UI (Phase 6)
results/                           bind-mounted output tree (raw/processed/figures/reports)
docs/                              architecture, dev, extension guides
tests/phase<N>.sh                  acceptance test per phase (phase1.sh … phase6.sh)
```

## Conventions

- **Ports**: all host bindings start `127.0.0.1:` — never `0.0.0.0`. If you add a new service, match this.
- **Image tags**: always pin to a specific tag including date/digest where the upstream supports it. `latest` is a bug.
- **Healthchecks**: every user-facing service has a healthcheck. `/healthz` is the standard path. Place it *before* the WAF if the WAF would otherwise block the UA (see `shadowd-proxy/proxy.py`'s dedicated route).
- **Compose profiles**: used for optional services (paranoia-high variants, ml agent). Never use profiles to smuggle prod/dev splits — that's what overrides are for.
- **Documentation**: if it changes the developer's mental model, update a doc. Prompts like "where does X live?" being ungoogleable in this repo is a fail.

## Adding a new WAF

1. Create `wafs/<name>/` with a `Dockerfile` (or use an upstream image directly) and a README that documents env vars + pinned tag.
2. Add a service block to `docker-compose.yml` following the `coraza` block as a template (healthcheck, depends_on: whoami, `ports: 127.0.0.1:${XYZ_PORT}:…`).
3. Add the port to `.env.example`.
4. Add `<waf>` to `tests/phase1.sh`'s `PORTS` map so the acceptance test covers it.
5. Document in `docs/ARCHITECTURE.md`.

## Testing philosophy

- Every phase ships a `tests/phase<N>.sh` that a CI or a human can run to verify acceptance.
- Unit tests for engine code land alongside code in `engine/tests/` (Phase 3+).
- The dashboard gets Playwright smoke tests (Phase 6+).

## Known gotchas

- The ModSecurity CRS image blocks `curl`'s default User-Agent at paranoia ≥ 2 via rule 913100. Healthchecks override the UA to `waflab-hc`.
- The Coraza runtime expects CRS to come from the embedded `coraza-coreruleset` FS, not a filesystem path — don't swap it for a tarball download.
- Shadow Daemon has no native Java/Node connectors; future DVWA integration uses its native PHP connector, but WebGoat and Juice Shop keep using `shadowd-proxy`.
