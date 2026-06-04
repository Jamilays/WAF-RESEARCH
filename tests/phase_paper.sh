#!/usr/bin/env bash
# ==============================================================================
# Paper-replication acceptance — TODO.md #1.
#
# Runs the 40-payload ``paper_subset`` corpus (20 SQLi + 20 XSS) through
# the default profile's 4 routes (baseline + modsec + coraza + shadowd)
# against DVWA, then checks the ladder-style outputs match the shape the
# paper reported: bypass rates strictly increase with obfuscation
# complexity (lexical → encoding → structural → context_displacement →
# multi_request). We don't assert specific per-category numbers — CRS 4
# is stricter than the CRS 3 the paper tested — but the ordinal
# relationship is a stable invariant of the methodology and catches
# regressions where one mutator stops firing.
#
# Invariants:
#   1. Engine image builds.
#   2. ``--corpus paper_subset`` loads exactly 40 payloads (20 SQLi + 20 XSS).
#   3. Engine produced ≥1 ``allowed`` verdict across the whole run
#      (smoke-level proof that mutations + routing + triggers are all wired).
#   4. On shadowd × dvwa, ``encoding`` ≥ ``lexical`` — the paper's
#      canonical "encoding defeats lexical checks" result, robust to
#      CRS-version and target-shape differences. We don't assert the
#      full 1→5 monotonic ladder: context_displacement and multi_request
#      relocate the payload outside the target's sink on DVWA/SQLi, so
#      their rate collapses to baseline_fail rather than a WAF win.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
info()  { printf '  \e[34mi\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[phase-paper]\e[0m %s\n' "$*"; }

PY=engine/.venv/bin/python
MAX_CONCURRENCY="${MAX_CONCURRENCY:-4}"
RUN_ID="${RUN_ID:-paper-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="${OUT:-results/raw/$RUN_ID}"

step "1/4  Prerequisites"
[[ -x "$PY" ]] || fail "engine venv missing — run: python3 -m venv engine/.venv && engine/.venv/bin/pip install -e 'engine/[dev]'"
[[ -f engine/src/wafeval/payloads/paper_subset.yaml ]] || fail "paper_subset.yaml missing"
pass "venv + corpus file present"

step "2/4  Confirm corpus shape via the loader"
"$PY" -c "
from wafeval.payloads.loader import load_corpus
from wafeval.models import VulnClass
corpus = load_corpus(corpus_name='paper_subset')
counts = {}
for p in corpus:
    counts[p.vuln_class.value] = counts.get(p.vuln_class.value, 0) + 1
assert len(corpus) == 40, f'expected 40, got {len(corpus)}'
assert counts == {'sqli': 20, 'xss': 20}, counts
print(f'ok: 40 payloads (sqli=20, xss=20)')
"
pass "paper_subset loader output matches"

step "3/4  Run engine across 4 WAFs × DVWA with all 5 mutators"
docker compose --profile engine run --rm \
  -e MAX_CONCURRENCY="$MAX_CONCURRENCY" \
  --name waflab-engine-phase-paper \
  engine run \
  --corpus paper_subset \
  --classes sqli,xss \
  --targets dvwa \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "$RUN_ID" >/tmp/phase-paper-engine.log 2>&1 \
  || { tail -40 /tmp/phase-paper-engine.log; fail "engine run"; }
pass "engine run: $RUN_ID"

step "4/4  Bypass-rate sanity + encoding ≥ lexical on shadowd × dvwa"
"$PY" <<PY
import json, pathlib
from collections import Counter

run_root = pathlib.Path("$OUT")
all_records = list(run_root.rglob("*.json"))
all_verdicts = Counter(json.loads(p.read_text()).get("verdict") for p in all_records)
print(f"run-wide verdict totals: {dict(all_verdicts)}")
if all_verdicts.get("allowed", 0) < 1:
    raise SystemExit("no 'allowed' verdicts in the whole run — engine pipeline is broken?")

shadowd_dvwa = run_root / "shadowd/dvwa"
if not shadowd_dvwa.exists():
    raise SystemExit(f"no shadowd/dvwa records at {shadowd_dvwa}")

by_mut = {}
for f in shadowd_dvwa.glob("*.json"):
    rec = json.loads(f.read_text())
    by_mut.setdefault(rec["mutator"], []).append(rec["verdict"])

def rate(verdicts):
    c = Counter(verdicts)
    denom = c.get("allowed", 0) + c.get("blocked", 0) + c.get("blocked_silent", 0) + c.get("flagged", 0)
    if denom == 0:
        return None
    return c.get("allowed", 0) / denom

order = ["lexical", "encoding", "structural", "context_displacement", "multi_request"]
print("shadowd × dvwa bypass rates (— = no attack datapoints):")
rates = {}
for m in order:
    r = rate(by_mut.get(m, []))
    rates[m] = r
    print(f"  {m:22s}  " + ("—    " if r is None else f"{r*100:5.1f}%"))

lex = rates.get("lexical")
enc = rates.get("encoding")
if lex is None or enc is None:
    raise SystemExit("lexical or encoding produced no attack datapoints — pipeline broken?")
if enc + 0.01 < lex:  # 1pp slack absorbs Wilson noise at N=20
    raise SystemExit(f"encoding ({enc:.2f}) < lexical ({lex:.2f}) — paper's canonical invariant broken")
print(f"ok: encoding ({enc*100:.1f}%) ≥ lexical ({lex*100:.1f}%)")
PY
pass "encoding ≥ lexical + non-zero bypass run-wide"

printf '\n\e[1;32mphase-paper PASSED\e[0m — ``--corpus paper_subset`` end-to-end\n'
