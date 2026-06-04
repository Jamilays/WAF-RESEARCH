"""Ladder / ablation analyzer — bypass rate and optional FPR per step.

The headline use case is the open-appsec minimum-confidence ablation
(`critical` → `high` → `medium` → `low`): one run per setting, plotted as
a line curve showing how bypass rate moves as the ML threshold loosens.
The same machinery works for any ordered ablation (CRS paranoia 1→4, the
open-appsec confidence ladder, anything else the researcher reruns with
one knob turned).

The module stays corpus-agnostic: it doesn't know *why* a run differs
from its neighbour, only that the caller ordered them. Downstream
reporting picks the WAF column from each run (after filtering
``waf != "baseline"``) and groups by ``mutator``. If the caller merged
multiple WAFs into one run, the ladder is computed per WAF separately
and the rendered figure has one line per (waf, mutator) pair.

**FPR overlay.** Passing a second set of ``fpr_steps`` (same step labels,
separate run_ids against the ``benign`` corpus + ``noop`` mutator) lets
the ladder compute a false-positive rate per (step, waf) and overlay it
as dashed lines on the same chart — turns the simple line into an
ROC-ish trade-off view. The markdown report gains a dedicated FPR table;
the CSV grows ``fpr`` / ``fpr_ci_lo`` / ``fpr_ci_hi`` columns joined on
``(step, waf)``.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from wafeval.analyzer.aggregate import load_run
from wafeval.analyzer.bypass import compute_rates


_MUTATOR_ORDER = ["lexical", "encoding", "structural", "context_displacement", "multi_request"]


def build_fpr_table(
    results_root: Path,
    fpr_steps: list[tuple[str, str]],
    target: str,
) -> pd.DataFrame:
    """Return one FPR row per (step, waf) from a benign-corpus ladder.

    Each ``fpr_steps`` run_id is expected to come from a ``--classes
    benign --mutators noop`` engine invocation against the same WAFs as
    the attack ladder. The frame drops anything that isn't the ``benign``
    class so a mixed run still produces clean numbers; on-target filter
    matches the attack-ladder's ``target`` arg so the two axes are
    apples-to-apples.

    FPR is computed by taking the waf_view bypass rate (``allowed +
    flagged`` over eligible) on the benign subset and flipping it: a
    benign request that the WAF *didn't* forward is a false positive.
    The Wilson CI flips the same way (``1 − ci_hi`` becomes the lower
    FPR bound).
    """
    rows: list[pd.DataFrame] = []
    for step_label, run_id in fpr_steps:
        df = load_run(Path(results_root), run_id)
        if df.empty:
            continue
        sub = df[
            (df["target"] == target)
            & (df["waf"] != "baseline")
            & (df["vuln_class"] == "benign")
        ]
        if sub.empty:
            continue
        rates = compute_rates(sub, ["waf"], lens="waf_view")
        rates = rates.assign(
            fpr=(1.0 - rates["rate"]),
            fpr_ci_lo=(1.0 - rates["ci_hi"]),
            fpr_ci_hi=(1.0 - rates["ci_lo"]),
            step=step_label,
            target=target,
        )
        rows.append(
            rates[["step", "waf", "fpr", "fpr_ci_lo", "fpr_ci_hi", "n", "k", "target"]]
        )
    if not rows:
        return pd.DataFrame(columns=[
            "step", "waf", "fpr", "fpr_ci_lo", "fpr_ci_hi", "n", "k", "target",
        ])
    return pd.concat(rows, ignore_index=True)


def build_ladder_table(
    results_root: Path,
    steps: list[tuple[str, str]],
    target: str,
    lens: str = "waf_view",
) -> pd.DataFrame:
    """Return a long-format table one row per (step_label, waf, mutator).

    Columns: ``step, waf, mutator, rate, ci_lo, ci_hi, n, k, target``. Rows
    with ``n < 5`` are kept (the reporter dims them) because the reader
    wants to see the empty cells to understand coverage; a silent drop
    would be misleading for a small-ablation use case.
    """
    rows: list[pd.DataFrame] = []
    for step_label, run_id in steps:
        df = load_run(Path(results_root), run_id)
        if df.empty:
            continue
        # Filter to the anchor target *and* exclude the baseline — we want
        # "what does this WAF do at this setting", not "what was the trigger
        # healthy enough to fire".
        sub = df[(df["target"] == target) & (df["waf"] != "baseline")]
        if sub.empty:
            continue
        rates = compute_rates(sub, ["waf", "mutator"], lens=lens)
        rates = rates.assign(step=step_label, target=target)
        rows.append(rates)
    if not rows:
        return pd.DataFrame(columns=["step", "waf", "mutator", "rate",
                                      "ci_lo", "ci_hi", "n", "k", "target"])
    return pd.concat(rows, ignore_index=True)


def render_ladder_chart(
    table: pd.DataFrame,
    steps: list[tuple[str, str]],
    out_dir: Path,
    stem: str = "ladder",
    title: str = "Bypass rate vs ablation step",
    fpr_table: pd.DataFrame | None = None,
) -> list[Path]:
    """Render a line chart: x = step (categorical, left→right), y = rate.

    One line per (waf, mutator). Seaborn's ``lineplot`` can't read a pair of
    dimensions as hue + style cleanly when the categorical x-axis has no
    numeric order, so we plot one line at a time and handle the legend
    manually. Returns [png, svg] paths.

    ``fpr_table`` (optional, from ``build_fpr_table``) overlays a dashed
    black line per WAF showing false-positive rate at each step, so a
    reader can read the trade-off directly off the same axes.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if table.empty:
        return []

    sns.set_theme(style="whitegrid", context="paper")
    step_order = [s for s, _ in steps]
    table = table.copy()
    table["step_idx"] = table["step"].map({s: i for i, s in enumerate(step_order)})

    wafs = sorted(table["waf"].unique())
    mutators = [m for m in _MUTATOR_ORDER if m in table["mutator"].unique()]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    palette = sns.color_palette("tab10", n_colors=len(mutators))
    linestyles = ["-", "--", ":", "-."]
    for wi, waf in enumerate(wafs):
        for mi, mut in enumerate(mutators):
            sub = (table[(table["waf"] == waf) & (table["mutator"] == mut)]
                   .sort_values("step_idx"))
            if sub.empty:
                continue
            ax.plot(
                sub["step_idx"], sub["rate"],
                marker="o",
                linestyle=linestyles[wi % len(linestyles)],
                color=palette[mi],
                label=f"{waf} · {mut}" if len(wafs) > 1 else mut,
            )
            ax.fill_between(sub["step_idx"], sub["ci_lo"], sub["ci_hi"],
                            color=palette[mi], alpha=0.10)

    if fpr_table is not None and not fpr_table.empty:
        fpr = fpr_table.copy()
        fpr["step_idx"] = fpr["step"].map({s: i for i, s in enumerate(step_order)})
        # One dashed black line per WAF — different marker shape per WAF so
        # the overlay stays readable even when the attack lines use the
        # whole palette.
        fpr_markers = ["s", "D", "^", "v", "P", "X"]
        for wi, waf in enumerate(sorted(fpr["waf"].unique())):
            sub = fpr[fpr["waf"] == waf].sort_values("step_idx")
            if sub.empty:
                continue
            ax.plot(
                sub["step_idx"], sub["fpr"],
                marker=fpr_markers[wi % len(fpr_markers)],
                linestyle="--",
                color="black",
                alpha=0.7,
                label=f"FPR · {waf}",
            )
            ax.fill_between(sub["step_idx"], sub["fpr_ci_lo"], sub["fpr_ci_hi"],
                            color="black", alpha=0.08)

    ax.set_xticks(range(len(step_order)))
    ax.set_xticklabels(step_order, rotation=0)
    ax.set_xlabel("ablation step (ordered by caller)")
    ax.set_ylabel("rate (95 % Wilson CI)")
    ax.set_ylim(0, 1)
    ax.set_title(title)
    ax.legend(loc="best", fontsize="x-small", ncols=2)

    paths = []
    for ext, kw in [("png", {"dpi": 300}), ("svg", {})]:
        p = out_dir / f"{stem}.{ext}"
        fig.savefig(p, bbox_inches="tight", **kw)
        paths.append(p)
    plt.close(fig)
    return paths


def render_ladder_markdown(
    table: pd.DataFrame,
    steps: list[tuple[str, str]],
    out_path: Path,
    figures: list[Path],
    title: str = "Ladder ablation",
    fpr_table: pd.DataFrame | None = None,
    fpr_steps: list[tuple[str, str]] | None = None,
) -> Path:
    """Emit a small Markdown report: provenance + pivot + inlined figures.

    ``fpr_table`` (+ its ``fpr_steps`` for provenance) adds a dedicated
    false-positive-rate table — one row per WAF, one column per step —
    so a reader can eyeball the trade-off alongside the per-mutator
    bypass numbers.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [f"# {title}", ""]
    lines.append("## Provenance")
    lines.append("")
    lines.append("| Step | Attack run_id |" + (" FPR run_id |" if fpr_steps else ""))
    lines.append("|---|---|" + ("---|" if fpr_steps else ""))
    fpr_run_by_step = dict(fpr_steps) if fpr_steps else {}
    for step_label, rid in steps:
        row = f"| `{step_label}` | `{rid}` |"
        if fpr_steps:
            fpr_rid = fpr_run_by_step.get(step_label, "—")
            row += f" `{fpr_rid}` |"
        lines.append(row)
    lines.append("")

    if table.empty:
        lines.append("*(no data — ran out of rows after filtering)*")
        out_path.write_text("\n".join(lines) + "\n")
        return out_path

    step_order = [s for s, _ in steps]
    for waf, sub in table.groupby("waf"):
        lines.append(f"## {waf}")
        lines.append("")
        pivot = sub.pivot(index="mutator", columns="step", values="rate")
        pivot = pivot.reindex(
            index=[m for m in _MUTATOR_ORDER if m in pivot.index],
            columns=[s for s in step_order if s in pivot.columns],
        )
        header = "| mutator | " + " | ".join(pivot.columns) + " |"
        sep = "|---|" + "|".join(["---:"] * len(pivot.columns)) + "|"
        lines.append(header)
        lines.append(sep)
        for mut, row in pivot.iterrows():
            cells = [f"{v*100:.1f}%" if pd.notna(v) else "—" for v in row.values]
            lines.append(f"| `{mut}` | " + " | ".join(cells) + " |")
        lines.append("")

    if fpr_table is not None and not fpr_table.empty:
        lines.append("## False-positive rate (benign corpus)")
        lines.append("")
        fpr_pivot = fpr_table.pivot(index="waf", columns="step", values="fpr")
        fpr_pivot = fpr_pivot.reindex(
            columns=[s for s in step_order if s in fpr_pivot.columns],
        )
        header = "| waf | " + " | ".join(fpr_pivot.columns) + " |"
        sep = "|---|" + "|".join(["---:"] * len(fpr_pivot.columns)) + "|"
        lines.append(header)
        lines.append(sep)
        for waf, row in fpr_pivot.iterrows():
            cells = [f"{v*100:.1f}%" if pd.notna(v) else "—" for v in row.values]
            lines.append(f"| `{waf}` | " + " | ".join(cells) + " |")
        lines.append("")

    pngs = [p for p in figures if p.suffix == ".png"]
    if pngs:
        lines.append("## Figures")
        lines.append("")
        for p in pngs:
            try:
                rel = p.resolve().relative_to(out_path.parent.resolve())
            except ValueError:
                rel = p
            lines.append(f"![{p.stem}]({rel})")
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n")
    return out_path
