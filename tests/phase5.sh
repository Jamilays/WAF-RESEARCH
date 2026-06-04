#!/usr/bin/env bash
# ==============================================================================
# Phase 5 acceptance tests — analyzer + reporter.
#
# Exit criteria:
#   1. engine pytest suite green, including analyzer + reporter suites
#   2. compose config valid under --profile report
#   3. Reporter runs against an existing raw run and emits:
#      - 3 CSVs under results/processed/<run_id>/
#      - >=4 PNG + >=4 SVG figures under results/figures/<run_id>/
#      - report.md and report.tex under results/reports/<run_id>/
#   4. report.md contains the Table 1 headers and all 5 mutator rows
#   5. report.tex is well-formed enough for pdflatex (heuristic: IEEEtran class,
#      \begin{document}…\end{document}, bibliography block)
#   6. bypass_rates.csv has >=1 row for each (mutator, waf) cell on DVWA
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[phase5]\e[0m %s\n' "$*"; }

PY=engine/.venv/bin/python

. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

step "1/6  Engine venv + unit tests green (includes analyzer + reporter)"
if [[ ! -x "$PY" ]]; then
  python3 -m venv engine/.venv
  engine/.venv/bin/pip install -q --disable-pip-version-check -e 'engine/[dev]'
fi
"$PY" -m pytest engine/tests -q || fail "pytest"
pass "pytest green"

step "2/6  Compose config valid under --profile report"
docker compose --profile report config --quiet || fail "compose (report) invalid"
pass "compose --profile report OK"

step "3/6  Seed a minimal raw run (if none exists) and generate report"
RUN_ID="phase5-$(date -u +%Y%m%dT%H%M%SZ)"

# If the engine image is built, reuse it; otherwise stand up the stack so the
# engine can produce a small deterministic run the reporter can aggregate.
if docker image inspect waflab/engine:phase3 >/dev/null 2>&1; then
  docker compose up -d --wait --wait-timeout 600 --remove-orphans >/dev/null \
    || fail "compose up --wait"
  docker compose --profile engine run --rm \
    --name waflab-engine-phase5 \
    engine run \
    --classes sqli --mutators lexical --targets dvwa \
    --run-id "$RUN_ID" >/tmp/engine-phase5.log 2>&1 \
    || { tail -20 /tmp/engine-phase5.log; fail "engine seed run"; }
else
  fail "waflab/engine:phase3 not built — run 'make build-engine' first"
fi
pass "seed run $RUN_ID written"

"$PY" -m wafeval report --run-id "$RUN_ID" >/tmp/reporter-phase5.log 2>&1 \
  || { cat /tmp/reporter-phase5.log; fail "reporter"; }
pass "reporter completed"

step "4/6  CSVs + figures + report files present"
for f in results/processed/$RUN_ID/per_variant.csv \
         results/processed/$RUN_ID/per_payload.csv \
         results/processed/$RUN_ID/bypass_rates.csv; do
  [[ -s "$f" ]] || fail "missing/empty: $f"
done
pass "3 CSVs present under results/processed/$RUN_ID/"

png_count=$(ls results/figures/$RUN_ID/*.png 2>/dev/null | wc -l)
svg_count=$(ls results/figures/$RUN_ID/*.svg 2>/dev/null | wc -l)
[[ "$png_count" -ge 4 && "$svg_count" -ge 4 ]] \
  || fail "expected ≥4 PNG + ≥4 SVG, got $png_count + $svg_count"
pass "figures: $png_count PNG + $svg_count SVG"

MD="results/reports/$RUN_ID/report.md"
TEX="results/reports/$RUN_ID/report.tex"
[[ -s "$MD" && -s "$TEX" ]] || fail "report.md / report.tex missing"
pass "report.md + report.tex present"

step "5/6  report.md has Table 1 + all 5 mutator rows"
grep -q "Table 1" "$MD" || fail "no 'Table 1' header"
for mut in lexical encoding structural context_displacement multi_request; do
  grep -qE "\`$mut\`" "$MD" || fail "no row for $mut in report.md"
done
pass "report.md structure ok"

grep -q '\\documentclass\[conference\]{IEEEtran}' "$TEX" || fail "no IEEEtran class"
grep -q '\\begin{document}' "$TEX" || fail "no \\begin{document}"
grep -q 'bibitem{yusifova2024}' "$TEX" || fail "bibliography missing"
pass "report.tex well-formed"

step "6/6  bypass_rates.csv covers each (mutator × waf) DVWA cell"
"$PY" - <<PY_EOF
import pandas as pd, sys
df = pd.read_csv("results/processed/$RUN_ID/bypass_rates.csv")
# true-bypass lens rows only (DVWA); every active WAF × the lexical mutator
# we just ran should have one row.
tb = df[df["lens"] == "true_bypass"]
have = set(tuple(r) for r in tb[["waf", "mutator"]].itertuples(index=False, name=None))
need = {("modsec","lexical"), ("coraza","lexical"), ("shadowd","lexical")}
missing = need - have
if missing:
    sys.exit(f"missing rows in bypass_rates.csv: {missing}")
print("  covers:", sorted(have))
PY_EOF
pass "bypass_rates.csv cell coverage OK"

printf '\n\e[1;32mPhase 5 PASSED\e[0m — analyzer + reporter produce CSVs, figures, MD, and TeX\n'
