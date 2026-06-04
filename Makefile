SHELL := /usr/bin/env bash
COMPOSE := docker compose

.PHONY: help up up-paranoia up-ml up-dashboard down down-all run run-host run-adaptive report report-combined report-combined-host report-host report-pdf ladder ladder-host ladder-openappsec ladder-paranoia shadowd-whitelist clean reset-wafs shell-engine config test-phase1 test-phase2 test-phase3 test-phase4 test-phase5 test-phase6 test-engine logs ps curl-matrix build-engine build-dashboard api-host

help:
	@echo "WAF Evasion Lab — Make targets"
	@echo ""
	@echo "  make up            Start core stack (Traefik + 3 targets + 9 WAF×target)"
	@echo "  make up-paranoia   Start core + ModSec/Coraza paranoia-high variants"
	@echo "  make up-ml         Start core + open-appsec stubs (--profile ml)"
	@echo "  make up-dashboard  Start core + FastAPI + React dashboard (--profile dashboard)"
	@echo "  make down          Stop default-profile services (WAFs + targets + traefik)"
	@echo "  make down-all      Stop EVERYTHING across all profiles (paranoia-high, ml, dashboard, engine, report)"
	@echo "  make config        Validate docker-compose across all profiles"
	@echo "  make test-phase1   Run Phase 1 acceptance tests (WAF liveness)"
	@echo "  make test-phase2   Run Phase 2 acceptance tests (routing matrix)"
	@echo "  make test-phase3   Run Phase 3 acceptance tests (engine end-to-end)"
	@echo "  make test-phase4   Run Phase 4 acceptance tests (5 mutators × 100 payloads)"
	@echo "  make test-phase5   Run Phase 5 acceptance tests (analyzer + reporter)"
	@echo "  make test-phase6   Run Phase 6 acceptance tests (API + dashboard)"
	@echo "  make test-engine   Run engine unit tests (pytest)"
	@echo "  make curl-matrix   Probe every route through Traefik and print codes"
	@echo "  make ps            Show container status"
	@echo "  make logs SVC=<s>  Tail logs for service <s>"
	@echo "  make clean         Remove containers, volumes, and results"
	@echo "  make reset-wafs    Restart WAF services only"
	@echo "  make build-engine  Build the engine Docker image"
	@echo "  make run           Trigger an engine run (containerised)"
	@echo "  make run-host      Trigger an engine run from the host venv"
	@echo "  make shell-engine  Shell into a throw-away engine container"
	@echo "  make report        Regenerate MD/LaTeX report + CSVs + figures (containerised)"
	@echo "  make report-host   Same, but from the host venv"
	@echo "  make report-pdf    Compile report.tex → report.pdf via the latex sidecar"
	@echo "  make report-combined RUN_IDS=a,b,c [OUT_ID=combined]"
	@echo "                     Merge N runs into report-combined.md/.tex (containerised)"
	@echo "  make report-combined-host RUN_IDS=a,b,c [OUT_ID=combined]"
	@echo "                     Same, but from the host venv"
	@echo "  make ladder STEPS=label1:run-a,label2:run-b [TARGET=juiceshop] [OUT_ID=ladder]"
	@echo "                     Render an ordered-ablation line chart (containerised)"
	@echo "  make ladder-host STEPS=… [TARGET=… OUT_ID=…]"
	@echo "                     Same, but from the host venv"
	@echo "  make ladder-openappsec"
	@echo "                     Automate the open-appsec min-confidence critical→low sweep"
	@echo "                     (needs 'make up-ml' stack up; ≈40 min wall-clock)"
	@echo "  make ladder-paranoia"
	@echo "                     Sweep CRS paranoia-level 1→2→3→4 on modsec-ph + coraza-ph"
	@echo "                     (needs 'make up' + 'make up-paranoia'; ≈60 min for the full corpus)"
	@echo "  make shadowd-whitelist [CMD=enable|disable|probe|test]"
	@echo "                     Exercise Shadow Daemon's whitelist engine with hand-"
	@echo "                     crafted rules for DVWA SQLi (needs 'make up'; ~10s)"
	@echo "  make run-adaptive SEED_RUN=<run-id> [ITER=N]"
	@echo "                     Seed + run the adaptive (rank 6) + adaptive3 (rank 7)"
	@echo "                     compositional mutators on the paper_subset corpus."
	@echo "                     ITER=N wraps in an N-generation evolution loop."

up:
	$(COMPOSE) up -d --build --wait --wait-timeout 600 --remove-orphans

up-paranoia:
	$(COMPOSE) --profile paranoia-high up -d --build --wait --wait-timeout 600 --remove-orphans

up-ml:
	$(COMPOSE) --profile ml up -d --build --wait --wait-timeout 600 --remove-orphans

up-dashboard:
	$(COMPOSE) --profile dashboard up -d --build --wait --wait-timeout 600 --remove-orphans
	@echo ""
	@echo "Dashboard: http://127.0.0.1:$${DASHBOARD_PORT:-3000}"
	@echo "API:       http://127.0.0.1:$${API_PORT:-8001}/health"

down:
	$(COMPOSE) down

# Plain ``docker compose down`` only touches services in the default profile —
# anything started via ``--profile ml`` / ``--profile paranoia-high`` /
# ``--profile dashboard`` stays running. This target enumerates every profile
# the lab ships so a single command tears the whole lab down.
down-all:
	$(COMPOSE) --profile paranoia-high --profile ml --profile dashboard --profile engine --profile report down --remove-orphans

clean:
	$(COMPOSE) --profile paranoia-high --profile ml down -v --remove-orphans
	rm -rf results/raw/* results/processed/* results/figures/* results/reports/* 2>/dev/null || true

reset-wafs:
	$(COMPOSE) restart $$( $(COMPOSE) ps --services | grep -E '^(modsec|coraza|shadowd-)' )

config:
	@echo "[1/5] Default profile …"
	@$(COMPOSE) config --quiet && echo "    ok"
	@echo "[2/5] --profile paranoia-high …"
	@$(COMPOSE) --profile paranoia-high config --quiet && echo "    ok"
	@echo "[3/5] --profile ml …"
	@$(COMPOSE) --profile ml config --quiet && echo "    ok"
	@echo "[4/5] --profile engine …"
	@$(COMPOSE) --profile engine config --quiet && echo "    ok"
	@echo "[5/5] --profile dashboard …"
	@$(COMPOSE) --profile dashboard config --quiet && echo "    ok"

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=100 $(SVC)

test-phase1:
	bash tests/phase1.sh

test-phase2:
	bash tests/phase2.sh

test-phase3:
	bash tests/phase3.sh

test-phase4:
	bash tests/phase4.sh

test-phase5:
	bash tests/phase5.sh

test-phase6:
	bash tests/phase6.sh

test-engine:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	./scripts/with-nix-libs engine/.venv/bin/python -m pytest engine/tests -q

build-engine:
	$(COMPOSE) --profile engine build engine

build-dashboard:
	$(COMPOSE) --profile dashboard build api dashboard

api-host:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	API_HOST=127.0.0.1 API_PORT=$${API_PORT:-8001} ./scripts/with-nix-libs engine/.venv/bin/python -m wafeval.api

curl-matrix:
	@port=$${TRAEFIK_PORT:-8000}; \
	for waf in baseline modsec coraza shadowd; do \
	  for t in dvwa webgoat juiceshop; do \
	    code=$$(curl -sS -o /dev/null -w '%{http_code}' --max-time 6 \
	            -H "Host: $$waf-$$t.local" \
	            "http://127.0.0.1:$$port/"); \
	    printf '  %-28s → %s\n' "$$waf-$$t.local" "$$code"; \
	  done; \
	done

# ---- engine runners ----
# `run` executes the engine inside the waflab network so it resolves
# traefik by service name. `run-host` runs from a host venv against the
# loopback-published Traefik port — faster to iterate on mutator code.
run:
	$(COMPOSE) --profile engine run --rm engine run \
	  --classes $(CLASSES) --mutators $(MUTATORS) $(ENGINE_ARGS)

run-host:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	./scripts/with-nix-libs engine/.venv/bin/python -m wafeval run \
	  --traefik-url http://127.0.0.1:$${TRAEFIK_PORT:-8000} \
	  --classes $(CLASSES) --mutators $(MUTATORS) $(ENGINE_ARGS)

shell-engine:
	$(COMPOSE) --profile engine run --rm --entrypoint sh engine

# ---- Phase 5 reporter ----
# RUN_ID defaults to "latest under results/raw". Override with `RUN_ID=…` on CLI.
report:
	$(COMPOSE) --profile report run --rm reporter $(if $(RUN_ID),--run-id $(RUN_ID))

report-host:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	./scripts/with-nix-libs engine/.venv/bin/python -m wafeval report $(if $(RUN_ID),--run-id $(RUN_ID))

report-pdf:
	@if [ -z "$(RUN_ID)" ]; then \
	   echo "usage: make report-pdf RUN_ID=<run-id>"; exit 2; \
	fi
	$(COMPOSE) --profile report run --rm --entrypoint sh latex -c \
	  "cd $(RUN_ID) && pdflatex -interaction=nonstopmode report.tex && pdflatex -interaction=nonstopmode report.tex"

# ---- cross-run consolidated reporter ----
# RUN_IDS is a comma-separated list; later run_ids override earlier on WAF
# overlap (so put "canonical" runs for each WAF at the end). OUT_ID names
# the directory under processed/ and reports/ that the merged artefacts
# land under.
OUT_ID ?= combined
report-combined:
	@if [ -z "$(RUN_IDS)" ]; then \
	   echo "usage: make report-combined RUN_IDS=<a,b,c> [OUT_ID=combined]"; exit 2; \
	fi
	$(COMPOSE) --profile report run --rm --entrypoint wafeval reporter \
	  report-combined \
	  --run-ids $(RUN_IDS) --out-id $(OUT_ID) \
	  --results-root /results/raw \
	  --processed-dir /results/processed \
	  --reports-dir /results/reports

report-combined-host:
	@if [ -z "$(RUN_IDS)" ]; then \
	   echo "usage: make report-combined-host RUN_IDS=<a,b,c> [OUT_ID=combined]"; exit 2; \
	fi
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	./scripts/with-nix-libs engine/.venv/bin/python -m wafeval report-combined \
	  --run-ids $(RUN_IDS) --out-id $(OUT_ID)

# ---- ladder / ordered-ablation analyzer ----
TARGET ?= juiceshop
LADDER_OUT_ID ?= ladder
ladder:
	@if [ -z "$(STEPS)" ]; then \
	   echo "usage: make ladder STEPS=<label1:run-a,label2:run-b,…> [TARGET=juiceshop] [LADDER_OUT_ID=ladder]"; exit 2; \
	fi
	$(COMPOSE) --profile report run --rm --entrypoint wafeval reporter \
	  ladder --steps $(STEPS) --target $(TARGET) --out-id $(LADDER_OUT_ID) \
	  --results-root /results/raw \
	  --processed-dir /results/processed \
	  --figures-dir /results/figures \
	  --reports-dir /results/reports

ladder-host:
	@if [ -z "$(STEPS)" ]; then \
	   echo "usage: make ladder-host STEPS=<label1:run-a,label2:run-b,…> [TARGET=juiceshop] [LADDER_OUT_ID=ladder]"; exit 2; \
	fi
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	./scripts/with-nix-libs engine/.venv/bin/python -m wafeval ladder \
	  --steps $(STEPS) --target $(TARGET) --out-id $(LADDER_OUT_ID)

ladder-openappsec:
	bash tests/openappsec_ladder.sh

ladder-paranoia:
	bash tests/paranoia_ladder.sh

# ---- shadowd whitelist experiment (TODO #1) ----
# Targets the daemon's ``whitelist`` engine (vs the default ``blacklist``
# engine exercised by the main corpus). Hand-crafted rules for DVWA's
# /vulnerabilities/sqli/ endpoint — numeric id, alphanumeric Submit,
# wide-open catch-all elsewhere. ~10 seconds end-to-end against a
# live stack. Always resets to blacklist-only on the way out.
shadowd-whitelist:
	bash tests/shadowd_whitelist.sh $(if $(CMD),$(CMD),test)

# ---- adaptive-mutator headline run ----
# Seeds the adaptive + adaptive3 compositional mutators (rank 6 + 7) on
# an existing research run's per-mutator bypass rates, then re-runs the
# corpus so the stacked-mutator bypass numbers are directly comparable
# to the single-category baseline.
#
# Usage:
#   make run-adaptive SEED_RUN=<run-id>              # one generation
#   make run-adaptive SEED_RUN=<run-id> ITER=3       # 3-gen evolution
#   make run-adaptive SEED_RUN=<run-id> ADAPTIVE_CORPUS=paper_subset
#
# ITER=N wraps this target in tests/adaptive_evolution.sh which reseeds
# each generation on the previous generation's outcomes.
ADAPTIVE_CORPUS          ?= paper_subset
ADAPTIVE_CLASSES         ?= sqli,xss
ADAPTIVE_TARGETS         ?= dvwa,juiceshop
ADAPTIVE_WAFS            ?= baseline,modsec,coraza,shadowd
ADAPTIVE_MUTATORS        ?= adaptive,adaptive3
ADAPTIVE_MAX_CONCURRENCY ?= 4

run-adaptive:
	@if [ -z "$(SEED_RUN)" ]; then \
	  echo "usage: make run-adaptive SEED_RUN=<run-id> [ITER=<n>] [ADAPTIVE_CORPUS=…] [ADAPTIVE_TARGETS=…]"; exit 2; \
	fi
	@if [ -n "$(ITER)" ] && [ "$(ITER)" != "1" ]; then \
	  SEED_RUN=$(SEED_RUN) ITER=$(ITER) \
	  ADAPTIVE_CORPUS=$(ADAPTIVE_CORPUS) ADAPTIVE_CLASSES=$(ADAPTIVE_CLASSES) \
	  ADAPTIVE_TARGETS=$(ADAPTIVE_TARGETS) ADAPTIVE_WAFS=$(ADAPTIVE_WAFS) \
	  ADAPTIVE_MUTATORS=$(ADAPTIVE_MUTATORS) \
	  ADAPTIVE_MAX_CONCURRENCY=$(ADAPTIVE_MAX_CONCURRENCY) \
	  bash tests/adaptive_evolution.sh; \
	else \
	  RUN_ID=adaptive-headline-$$(date -u +%Y%m%dT%H%M%SZ); \
	  echo "[adaptive] seed=$(SEED_RUN) → run=$$RUN_ID"; \
	  $(COMPOSE) --profile engine run --rm \
	    -e ADAPTIVE_SEED_RUN=$(SEED_RUN) \
	    -e MAX_CONCURRENCY=$(ADAPTIVE_MAX_CONCURRENCY) \
	    engine run \
	    --corpus $(ADAPTIVE_CORPUS) \
	    --classes $(ADAPTIVE_CLASSES) \
	    --targets $(ADAPTIVE_TARGETS) \
	    --wafs $(ADAPTIVE_WAFS) \
	    --mutators $(ADAPTIVE_MUTATORS) \
	    --run-id $$RUN_ID; \
	fi

# ---- engine runner defaults ----
CLASSES  ?= sqli,xss
MUTATORS ?= lexical
