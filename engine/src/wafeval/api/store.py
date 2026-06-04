"""Data access layer for the dashboard API.

Wraps the analyzer functions with a small TTL-free mtime cache: a run's
aggregated DataFrames are recomputed only when a new JSON lands under the
raw/ dir, so the Live Run page can poll cheaply without re-parsing ~9 MB
of JSON per call.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from wafeval.analyzer.aggregate import load_run
from wafeval.analyzer.bypass import compute_rates
from wafeval.analyzer.combined import combine_runs
from wafeval.reporter.hall_of_fame import hall_of_fame


# Cache: run_id → (newest_mtime_seen, DataFrame). Invalidated on new writes.
_df_cache: dict[str, tuple[float, int, pd.DataFrame]] = {}

# Incremental cache for the /live endpoint: run_id → {"seen", "rows", "histogram"}.
# Each poll reads only files that have appeared since the last call. Without this,
# a polling dashboard against a 70k-file run re-parses every JSON on every tick
# and the FastAPI handler exceeds nginx's 30s timeout (504 Gateway Time-out).
_live_cache: dict[str, dict[str, Any]] = {}


def _run_dir(raw_root: Path, run_id: str) -> Path:
    d = raw_root / run_id
    if not d.is_dir():
        raise FileNotFoundError(f"run not found: {run_id}")
    return d


def _scan_raw(run_dir: Path) -> tuple[float, int]:
    """Return (newest mtime, file count) for all *.json under run_dir."""
    newest = 0.0
    count = 0
    for p in run_dir.rglob("*.json"):
        if p.name == "manifest.json":
            continue
        st = p.stat()
        if st.st_mtime > newest:
            newest = st.st_mtime
        count += 1
    return newest, count


def _load_cached(raw_root: Path, run_id: str) -> pd.DataFrame:
    run_dir = _run_dir(raw_root, run_id)
    newest, count = _scan_raw(run_dir)
    cached = _df_cache.get(run_id)
    if cached is not None and cached[0] == newest and cached[1] == count:
        return cached[2]
    df = load_run(raw_root, run_id)
    _df_cache[run_id] = (newest, count, df)
    return df


def latest_run_id(raw_root: Path) -> str | None:
    if not raw_root.is_dir():
        return None
    runs = sorted(p.name for p in raw_root.iterdir() if p.is_dir())
    return runs[-1] if runs else None


def _manifest_dict(run_dir: Path) -> dict[str, Any]:
    p = run_dir / "manifest.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}


def list_runs(raw_root: Path) -> list[dict[str, Any]]:
    if not raw_root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for d in sorted(raw_root.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        m = _manifest_dict(d)
        out.append({
            "run_id": d.name,
            "started_at": m.get("started_at"),
            "mutators": m.get("mutators", []),
            "classes": m.get("classes", []),
            "totals": m.get("totals", {}),
        })
    return out


def run_manifest(raw_root: Path, run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(raw_root, run_id)
    m = _manifest_dict(run_dir)
    m.setdefault("run_id", run_id)
    return m


def run_live(raw_root: Path, run_id: str, tail: int) -> dict[str, Any]:
    """Freshly scan the run dir — intended for a polling progress panel.

    Incremental: parses only JSON files that haven't been seen on a previous
    poll for this ``run_id``. The histogram and the "rows" tail are accumulated
    in ``_live_cache`` so each call is O(new files) rather than O(all files).
    """
    run_dir = _run_dir(raw_root, run_id)
    manifest = _manifest_dict(run_dir)
    expected = int(manifest.get("totals", {}).get("datapoints", 0)) or None

    cache = _live_cache.setdefault(run_id, {"seen": set(), "rows": [], "histogram": {}})
    seen: set[str] = cache["seen"]
    rows: list[dict[str, Any]] = cache["rows"]
    histogram: dict[str, int] = cache["histogram"]

    new_files: list[tuple[float, Path]] = []
    for p in run_dir.rglob("*.json"):
        if p.name == "manifest.json":
            continue
        sp = str(p)
        if sp in seen:
            continue
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            continue
        new_files.append((mtime, p))

    # Sort newcomers by mtime so the rolling "recent" tail stays time-ordered.
    new_files.sort(key=lambda x: x[0])
    for _mtime, p in new_files:
        try:
            d = json.loads(p.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            continue
        seen.add(str(p))
        v = d.get("verdict", "unknown")
        histogram[v] = histogram.get(v, 0) + 1
        rows.append({
            "payload_id": d.get("payload_id"),
            "variant":    d.get("variant"),
            "mutator":    d.get("mutator"),
            "vuln_class": d.get("vuln_class"),
            "waf":        d.get("waf"),
            "target":     d.get("target"),
            "verdict":    d.get("verdict"),
            "timestamp":  d.get("timestamp"),
        })

    recent = rows[-tail:][::-1]
    return {
        "run_id": run_id,
        "processed": len(rows),
        "expected": expected,
        "histogram": dict(histogram),
        "recent": recent,
        "manifest": manifest,
    }


def _df_to_json_rows(df: pd.DataFrame) -> list[dict[str, Any]]:
    """DataFrame → list[dict] with NaN → None so the response is clean JSON."""
    if df.empty:
        return []
    return json.loads(df.replace({np.nan: None}).to_json(orient="records"))


def _baseline_fail_share(df: pd.DataFrame, groupby: list[str]) -> pd.DataFrame:
    """Return (…groupby, baseline_fail_rate, n_total) for each cell.

    Lets the dashboard dim cells where many datapoints never had a chance
    to bypass — those rows' "rate" numbers are misleading on their own.
    """
    if df.empty:
        return pd.DataFrame(columns=[*groupby, "baseline_fail_rate", "n_total"])
    rows = []
    for key, sub in df.groupby(groupby, dropna=False):
        n_total = len(sub)
        n_fail = int((sub["verdict"] == "baseline_fail").sum())
        row = dict(zip(groupby, key if isinstance(key, tuple) else (key,)))
        row["baseline_fail_rate"] = n_fail / n_total if n_total else 0.0
        row["n_total"] = n_total
        rows.append(row)
    return pd.DataFrame(rows)


def run_bypass_rates(raw_root: Path, run_id: str, anchor_target: str = "dvwa") -> list[dict[str, Any]]:
    df = _load_cached(raw_root, run_id)
    if df.empty:
        return []
    frames: list[pd.DataFrame] = []

    dvwa = df[df["target"] == anchor_target]
    tb = compute_rates(dvwa[dvwa["waf"] != "baseline"], ["waf", "mutator"], lens="true_bypass")
    if not tb.empty:
        bf = _baseline_fail_share(dvwa[dvwa["waf"] != "baseline"], ["waf", "mutator"])
        tb = tb.merge(bf, on=["waf", "mutator"], how="left").assign(target=anchor_target)
        frames.append(tb)

    wv = compute_rates(df[df["waf"] != "baseline"], ["waf", "mutator", "target"], lens="waf_view")
    if not wv.empty:
        bf = _baseline_fail_share(df[df["waf"] != "baseline"], ["waf", "mutator", "target"])
        wv = wv.merge(bf, on=["waf", "mutator", "target"], how="left")
        frames.append(wv)

    if not frames:
        return []
    out = pd.concat(frames, ignore_index=True)
    return _df_to_json_rows(out)


def run_per_payload(raw_root: Path, run_id: str) -> list[dict[str, Any]]:
    df = _load_cached(raw_root, run_id)
    if df.empty:
        return []
    roll = (
        df.assign(
            n_allowed=(df["verdict"] == "allowed").astype(int),
            n_blocked=(df["verdict"] == "blocked").astype(int),
            n_blocked_silent=(df["verdict"] == "blocked_silent").astype(int),
            n_flagged=(df["verdict"] == "flagged").astype(int),
            n_baseline_fail=(df["verdict"] == "baseline_fail").astype(int),
            n_error=(df["verdict"] == "error").astype(int),
        )
        .groupby(["payload_id", "vuln_class", "waf", "target"], as_index=False)
        .agg({
            "variant": "count",
            "n_allowed": "sum", "n_blocked": "sum", "n_blocked_silent": "sum",
            "n_flagged": "sum", "n_baseline_fail": "sum", "n_error": "sum",
        })
        .rename(columns={"variant": "n_total"})
    )
    return _df_to_json_rows(roll)


def run_per_variant(
    raw_root: Path,
    run_id: str,
    filters: dict[str, str | None],
    limit: int,
    offset: int,
) -> dict[str, Any]:
    df = _load_cached(raw_root, run_id)
    if df.empty:
        return {"total": 0, "limit": limit, "offset": offset, "rows": []}
    view = df
    for col, val in filters.items():
        if val is None:
            continue
        view = view[view[col] == val]
    total = len(view)
    # Drop the large mutated_body from the list view — the detail endpoint
    # serves it on demand. Keeps the wire payload below 100 KB even with
    # thousands of rows.
    light_cols = [c for c in view.columns if c != "mutated_body"]
    page = view.iloc[offset:offset + limit][light_cols]
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "rows": _df_to_json_rows(page),
    }


def run_hall_of_fame(raw_root: Path, run_id: str, top_n: int = 20) -> list[dict[str, Any]]:
    df = _load_cached(raw_root, run_id)
    rows = hall_of_fame(df, top_n=top_n)
    return _df_to_json_rows(rows)


def run_combined(
    raw_root: Path,
    run_ids: list[str],
    anchor_target: str = "dvwa",
) -> dict[str, Any]:
    """Merge ``run_ids`` and return combined bypass rates + provenance.

    Shape mirrors ``run_bypass_rates`` (true_bypass DVWA + waf_view all
    targets, with baseline_fail_rate annotations) but across the union of
    the merged runs. The ``waf_provenance`` map lets the dashboard render a
    "which run did this WAF's numbers come from?" tooltip without a second
    request.
    """
    df, provenance = combine_runs(raw_root, run_ids)
    if df.empty:
        return {
            "run_ids": run_ids, "waf_provenance": provenance,
            "rows": [], "wafs": [],
        }

    frames: list[pd.DataFrame] = []
    dvwa = df[df["target"] == anchor_target]
    tb = compute_rates(dvwa[dvwa["waf"] != "baseline"], ["waf", "mutator"], lens="true_bypass")
    if not tb.empty:
        bf = _baseline_fail_share(dvwa[dvwa["waf"] != "baseline"], ["waf", "mutator"])
        tb = tb.merge(bf, on=["waf", "mutator"], how="left").assign(target=anchor_target)
        frames.append(tb)

    wv = compute_rates(df[df["waf"] != "baseline"], ["waf", "mutator", "target"], lens="waf_view")
    if not wv.empty:
        bf = _baseline_fail_share(df[df["waf"] != "baseline"], ["waf", "mutator", "target"])
        wv = wv.merge(bf, on=["waf", "mutator", "target"], how="left")
        frames.append(wv)

    rows: list[dict[str, Any]] = []
    if frames:
        rows = _df_to_json_rows(pd.concat(frames, ignore_index=True))

    wafs = sorted(w for w in df["waf"].unique().tolist() if w != "baseline")
    return {
        "run_ids": run_ids,
        "waf_provenance": provenance,
        "wafs": wafs,
        "rows": rows,
    }


def compare_runs(raw_root: Path, a: str, b: str, anchor_target: str = "dvwa") -> dict[str, Any]:
    """Side-by-side bypass-rate diff for two runs."""
    def _rates(run_id: str) -> pd.DataFrame:
        df = _load_cached(raw_root, run_id)
        if df.empty:
            return pd.DataFrame(columns=["waf", "mutator", "rate", "k", "n"])
        dvwa = df[(df["target"] == anchor_target) & (df["waf"] != "baseline")]
        return compute_rates(dvwa, ["waf", "mutator"], lens="true_bypass")

    ra = _rates(a).rename(columns={"rate": "rate_a", "k": "k_a", "n": "n_a"})
    rb = _rates(b).rename(columns={"rate": "rate_b", "k": "k_b", "n": "n_b"})
    merged = ra.merge(rb, on=["waf", "mutator"], how="outer")
    merged["delta"] = merged["rate_b"] - merged["rate_a"]
    keep = ["waf", "mutator", "rate_a", "rate_b", "delta", "k_a", "n_a", "k_b", "n_b"]
    for c in keep:
        if c not in merged.columns:
            merged[c] = None
    merged = merged[keep].sort_values(["waf", "mutator"]).reset_index(drop=True)
    return {"a": a, "b": b, "rows": _df_to_json_rows(merged)}
