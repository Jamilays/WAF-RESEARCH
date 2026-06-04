"""Markdown reporter.

Renders ``results/reports/<run_id>/report.md``. Sections:

  1. Title, run-id, UTC timestamp, git SHA, WAF image tags
  2. Run summary (datapoints, mutators, classes, targets)
  3. Table 1 reproduction — mutator × WAF true-bypass rate + CI, DVWA
  4. Delta vs paper aggregate (our mean across WAFs − paper number)
  5. WAF-view appendix — baseline-agnostic rates including Juice Shop + WebGoat
  6. Figures inlined as ``![…](…)`` relative paths
  7. Recommendations (templated, auto-filled deltas)
  8. Bibliography (paper + lab sources)
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from wafeval.analyzer.bypass import compute_rates
from wafeval.analyzer.latency import latency_stats, render_markdown_table as render_latency_md
from wafeval.reporter._data import BIBLIOGRAPHY, MUTATOR_SECTIONS, PAPER_TABLE1
from wafeval.reporter.hall_of_fame import hall_of_fame, render_markdown as render_hall_of_fame


_WAF_ORDER = ["modsec", "coraza", "shadowd"]
# Preferred rendering order for the headline table. Runs that only contain
# compositional mutators (``make run-adaptive``) or any future rank
# contribute extra rows appended in rank-then-alphabetical order by
# ``_resolve_mut_order``. Keeping the base five up front matches the
# paper's mutator-category ordering and the PAPER_TABLE1 reference keys.
_PREFERRED_MUT_ORDER = [
    "lexical", "encoding", "structural",
    "context_displacement", "multi_request",
    "adaptive", "adaptive3",
    "noop",
]


def _resolve_mut_order(df: pd.DataFrame) -> list[str]:
    """Order the mutators present in ``df`` for rendering.

    Preferred names land first (in ``_PREFERRED_MUT_ORDER``); any
    mutator the reporter hasn't heard of (a custom extension) comes
    after them in alphabetical order. Absent mutators are skipped so
    the table isn't padded with dashes for categories this run didn't
    exercise.
    """
    present: set[str] = set(df["mutator"].unique()) if "mutator" in df.columns else set()
    known = [m for m in _PREFERRED_MUT_ORDER if m in present]
    extra = sorted(m for m in present if m not in _PREFERRED_MUT_ORDER)
    return known + extra
# Cells with fewer than this many baseline-triggered datapoints are rendered
# as "—" with a footnote, not as a rate. Wilson CI half-widths are enormous
# below ~5 samples and the cell just misleads the reader otherwise.
_MIN_N = 5


def _git_sha(cwd: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=cwd, stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _waf_versions() -> dict[str, str]:
    """Pin tags from docker-compose — read statically, not via docker inspect
    so the reporter works even when the stack is down."""
    return {
        "modsecurity": "owasp/modsecurity-crs:4.25.0-nginx-alpine-202604040104",
        "coraza":      "waflab/coraza:phase1 (built from corazawaf/coraza)",
        "shadowd":     "zecure/shadowd:2.2.0 + custom Python JSON proxy",
    }


def _fmt_rate(r: float, lo: float, hi: float, n: int | None = None) -> str:
    if pd.isna(r) or (n is not None and n < _MIN_N):
        return "—"
    return f"{r*100:.1f}% (±{max(r-lo, hi-r)*100:.1f}pp)"


def _baseline_fail_summary(df: pd.DataFrame) -> str:
    """One-line summary of baseline-fail share, grouped by (target, class)."""
    if df.empty:
        return "*(no data)*"
    lines = []
    for (tgt, cls), sub in df.groupby(["target", "vuln_class"]):
        if sub.empty:
            continue
        fail = int((sub["verdict"] == "baseline_fail").sum())
        total = len(sub)
        if total == 0:
            continue
        pct = fail / total * 100.0
        if pct >= 5.0:
            lines.append(f"- `{tgt}` × `{cls}` — {fail}/{total} datapoints ({pct:.1f}%) baseline_fail")
    if not lines:
        return "- *(all (target × class) cells have <5% baseline-fail — triggers look healthy)*"
    return "\n".join(lines)


def _true_bypass_pivot(df: pd.DataFrame, target: str) -> pd.DataFrame:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return pd.DataFrame()
    rates = rates.set_index(["mutator", "waf"])
    return rates


def _render_table1(df: pd.DataFrame, target: str) -> str:
    """Paper Table 1 analogue: mutator rows, WAF cols, cells = rate ± CI.

    "Our pooled" is the fraction over the union of all WAFs' baseline-
    triggered datapoints — i.e. every verdict gets equal weight, not every
    WAF. This matches the paper's aggregate definition and aligns with the
    Recommendations section below the table.
    """
    p = _true_bypass_pivot(df, target)
    if p.empty:
        return "*(no data — run is empty)*"
    pooled = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator"], lens="true_bypass",
    ).set_index("mutator")
    mut_order = _resolve_mut_order(df[df["target"] == target])
    lines = [f"| Mutator | {' | '.join(_WAF_ORDER)} | Our pooled | Paper | Δ |",
             f"|---|{'|'.join(['---:'] * len(_WAF_ORDER))}|---:|---:|---:|"]
    for mut in mut_order:
        cells = []
        for waf in _WAF_ORDER:
            if (mut, waf) in p.index:
                r = p.loc[(mut, waf)]
                cells.append(_fmt_rate(r["rate"], r["ci_lo"], r["ci_hi"], int(r["n"])))
            else:
                cells.append("—")
        paper = PAPER_TABLE1.get(mut)
        paper_cell = f"{paper*100:.1f}%" if paper is not None else "—"
        if mut in pooled.index and int(pooled.loc[mut, "n"]) >= _MIN_N:
            pooled_rate = float(pooled.loc[mut, "rate"])
            delta_cell = f"{(pooled_rate - paper)*100:+.1f}pp" if paper is not None else "—"
            lines.append(
                f"| `{mut}` | {' | '.join(cells)} | "
                f"{pooled_rate*100:.1f}% (n={int(pooled.loc[mut, 'n'])}) | "
                f"{paper_cell} | {delta_cell} |"
            )
        else:
            lines.append(
                f"| `{mut}` | {' | '.join(cells)} | — | "
                f"{paper_cell} | — |"
            )
    lines.append("")
    lines.append(f"*Cells with n < {_MIN_N} baseline-triggered datapoints are rendered as `—` "
                 f"(Wilson CI half-width ≥ 0.4 at that size).*")
    return "\n".join(lines)


def _render_latency(df: pd.DataFrame) -> str:
    # Scope to non-baseline routes — baseline latencies belong to the target,
    # not to a WAF, so mixing them dilutes the comparison.
    stats = latency_stats(
        df[df["waf"] != "baseline"] if "waf" in df.columns else df,
        groupby=["waf", "target"],
    )
    return render_latency_md(stats)


def _render_waf_view(df: pd.DataFrame) -> str:
    rates = compute_rates(
        df[df["waf"] != "baseline"],
        ["mutator", "waf", "target"], lens="waf_view",
    )
    if rates.empty:
        return "*(no data)*"
    lines = ["| mutator | waf | target | rate | n |",
             "|---|---|---|---:|---:|"]
    for _, r in rates.iterrows():
        lines.append(
            f"| `{r['mutator']}` | {r['waf']} | {r['target']} | "
            f"{r['rate']*100:.1f}% | {int(r['n'])} |"
        )
    return "\n".join(lines)


def _recommendations(df: pd.DataFrame) -> str:
    rates = compute_rates(
        df[(df["target"] == "dvwa") & (df["waf"] != "baseline")],
        ["mutator"], lens="true_bypass",
    ).set_index("mutator")
    bullets: list[str] = []
    for mut in _resolve_mut_order(df):
        if mut not in rates.index:
            continue
        r = rates.loc[mut, "rate"]
        paper = PAPER_TABLE1.get(mut)
        if paper is None:
            bullets.append(
                f"- **{mut}** — bypass rate {r*100:.1f}% "
                f"(no paper baseline for this category)."
            )
            continue
        delta = r - paper
        if abs(delta) < 0.05:
            verdict = "reproduces the paper within ±5pp"
        elif delta > 0:
            verdict = f"bypass rate is {delta*100:+.1f}pp **higher** than the paper"
        else:
            verdict = f"bypass rate is {delta*100:+.1f}pp lower than the paper"
        bullets.append(f"- **{mut}** — {verdict}.")
    if not bullets:
        bullets.append("- *(insufficient data)*")
    return "\n".join(bullets)


def render_markdown(
    df: pd.DataFrame,
    out_path: Path,
    run_id: str,
    figures: list[Path],
    manifest: dict | None = None,
    repo_root: Path | None = None,
    anchor_target: str = "dvwa",
) -> Path:
    """Render ``report.md``. ``figures`` paths are made relative to out_path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    repo_root = repo_root or Path.cwd()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    fig_md = []
    for p in figures:
        stem = p.stem.replace("_", " ")
        try:
            rel = p.resolve().relative_to(out_path.parent.resolve())
        except ValueError:
            rel = p
        fig_md.append(f"### {stem}\n\n![{stem}]({rel})\n")

    totals = (manifest or {}).get("totals", {})
    mut_sections = "\n".join(f"- **{name}** — {desc}" for name, desc in MUTATOR_SECTIONS)
    bib = "\n".join(f"{i+1}. {e}" for i, e in enumerate(BIBLIOGRAPHY))

    waf_versions = "\n".join(f"- `{k}` → `{v}`" for k, v in _waf_versions().items())

    md = f"""# WAF Evasion Lab — report ({run_id})

- **Generated:** {now}
- **Git SHA:** `{_git_sha(repo_root)}`
- **Anchor target for true-bypass numbers:** `{anchor_target}` (DVWA — the only
  target with dependable triggers across all six vuln classes).

## WAF versions

{waf_versions}

## Run summary

- Datapoints: **{totals.get("datapoints", len(df))}**
- Mutators: {", ".join(f"`{m}`" for m in (manifest or {}).get("mutators", []))}
- Classes: {", ".join(f"`{c}`" for c in (manifest or {}).get("classes", []))}
- Targets: {", ".join(sorted(df["target"].unique())) if not df.empty else "—"}
- Verdict tallies:
  - allowed: {totals.get("allowed", 0)}
  - blocked: {totals.get("blocked", 0)}
  - blocked_silent: {totals.get("blocked_silent", 0)}
  - flagged: {totals.get("flagged", 0)}
  - baseline_fail: {totals.get("baseline_fail", 0)}
  - error: {totals.get("error", 0)}

## Mutator categories (prompt.md §7)

{mut_sections}

## Table 1 — true-bypass rate by mutator × WAF (DVWA)

{_render_table1(df, anchor_target)}

*Cells are mean bypass rate with 95% Wilson CI half-width.* *"Our pooled" is
the fraction over the union of every WAF's baseline-triggered datapoints
(each verdict weighted equally), which is the definition closest to the
paper's aggregate.* *"Paper" is Yusifova (2024); Δ is our pooled − paper.*

### Trigger health (baseline_fail share by target × class)

{_baseline_fail_summary(df)}

*Target × class cells with high baseline-fail share indicate a corpus-trigger
mismatch (the exploit wouldn't have worked on baseline either), not a WAF
that caught the attack. Cells here should generally read < 10 %.*

## Recommendations

{_recommendations(df)}

## Figures

{chr(10).join(fig_md) if fig_md else "*(no figures produced for this run)*"}

## Hall of Fame — top variants that bypass the most WAFs

Variants are ranked by the number of (WAF × target) cells that let them
through as an `allowed` verdict. Ties broken by raw bypass rate. Only
baseline-confirmed cells count toward either metric — a variant that
baseline_fails everywhere is excluded. Useful for reviewers who want
concrete exploit strings rather than aggregate percentages.

{render_hall_of_fame(hall_of_fame(df, top_n=20))}

## Appendix A — WAF-view rates (baseline-agnostic)

These numbers are useful for `context_displacement` / `multi_request` variants
against targets whose vulnerable sinks don't read from the relocated slot.
WAF-view counts anything the WAF didn't block, irrespective of whether the
transformed payload would have exploited the app sans-WAF.

{_render_waf_view(df)}

## Appendix B — Latency profile (WAF response ms)

Per-(waf × target) percentiles over `waf_ms`, excluding `error` and
`baseline_fail` rows (those don't reflect real WAF processing cost). A
long p99 tail often signals rule chains with expensive backtracking or
an ML-agent cold cache; compare with the bypass table above to see
whether latency correlates with detection strength.

{_render_latency(df)}

## Bibliography

{bib}
"""
    out_path.write_text(md)
    return out_path
