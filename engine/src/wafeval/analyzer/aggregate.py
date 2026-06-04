"""Load raw verdict JSON into a long-format pandas DataFrame.

One row per VerdictRecord. Columns match model fields plus a few derived
convenience columns (baseline_triggered, category_rank) the reporter/
analyzer keys off. Keeping this a flat table means the aggregator, CSV
exporter, and chart module all speak the same shape.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


_COLUMNS = [
    "run_id", "waf", "target", "payload_id", "vuln_class",
    "mutator", "variant", "complexity_rank", "verdict",
    "baseline_status", "baseline_ms", "baseline_triggered",
    "waf_status", "waf_ms",
    "mutated_body", "notes",
]


def load_run(results_root: Path, run_id: str) -> pd.DataFrame:
    """Read every JSON under ``results/raw/<run_id>/`` into a DataFrame.

    ``manifest.json`` is ignored (it's run-level metadata, not a datapoint).
    """
    root = Path(results_root) / run_id
    if not root.is_dir():
        raise FileNotFoundError(f"no run directory at {root}")

    rows: list[dict] = []
    for p in sorted(root.rglob("*.json")):
        if p.name == "manifest.json":
            continue
        d = json.loads(p.read_text())
        baseline = d.get("baseline") or {}
        waf = d.get("waf_route") or {}
        rows.append({
            "run_id":              d["run_id"],
            "waf":                 d["waf"],
            "target":              d["target"],
            "payload_id":          d["payload_id"],
            "vuln_class":          d["vuln_class"],
            "mutator":             d["mutator"],
            "variant":             d["variant"],
            "complexity_rank":     d["complexity_rank"],
            "verdict":             d["verdict"],
            "baseline_status":     baseline.get("status_code"),
            "baseline_ms":         baseline.get("response_ms"),
            # Recover "was the baseline trigger met?" from the verdict: any
            # non-"baseline_fail" verdict implies baseline triggered (or the
            # waf response pre-empted with a block, in which case baseline
            # was never consulted — see verdict.classify for the ordering).
            "baseline_triggered":  d["verdict"] != "baseline_fail",
            "waf_status":          waf.get("status_code"),
            "waf_ms":              waf.get("response_ms"),
            "mutated_body":        d.get("mutated_body"),
            "notes":               d.get("notes"),
        })
    df = pd.DataFrame(rows, columns=_COLUMNS)
    return df


def latest_run_id(results_root: Path) -> str:
    """Return the newest run_id under ``results_root`` (lexicographic ≈ time order).

    The engine uses ``YYYYMMDDTHHMMSSZ_<hash>`` directory names, so a sorted
    listing maps to chronological order.
    """
    root = Path(results_root)
    runs = sorted(p.name for p in root.iterdir() if p.is_dir())
    if not runs:
        raise FileNotFoundError(f"no runs under {root}")
    return runs[-1]
