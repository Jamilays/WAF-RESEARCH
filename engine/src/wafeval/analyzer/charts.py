"""Chart generation (prompt.md §9).

All charts emit BOTH a 300 dpi PNG and an SVG so the reporter can inline
whichever the consumer wants (Markdown prefers PNG; LaTeX happier with PDF
but we keep SVG as a lossless source for downstream conversion).

Chart set:
  1. heatmap_mutator_waf  — mutator × waf, cell = true-bypass rate, DVWA
  2. bar_table1           — grouped bars: mutator (x) × waf (hue), height =
                            true-bypass rate, errorbars = Wilson 95% CI. Matches
                            prompt.md §15 / paper Table 1.
  3. line_complexity      — complexity_rank (x) × waf (colour), monotone
                            trend per paper finding.
  4. facet_vuln_class     — small-multiples: one subplot per vuln class,
                            mutator × waf heatmap inside each.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")   # no display
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from wafeval.analyzer.bypass import compute_rates
from wafeval.analyzer.latency import latency_stats

_MUTATOR_ORDER = ["lexical", "encoding", "structural", "context_displacement",
                  "multi_request", "adaptive", "adaptive3", "noop"]
# Default render order for the 7 WAFs the lab ships. Cells absent from a
# given DataFrame are simply skipped — the helpers below intersect this
# list with what's actually present so adding/removing a WAF doesn't
# require chart-side changes.
_WAF_ORDER = ["modsec", "coraza", "shadowd", "openappsec", "modsec-ph", "coraza-ph"]


def _wafs_present(df: pd.DataFrame, exclude_baseline: bool = True) -> list[str]:
    """Return ``_WAF_ORDER`` filtered to wafs that appear in ``df`` (+ unknowns alphabetised)."""
    if df.empty or "waf" not in df.columns:
        return []
    present = set(df["waf"].unique())
    if exclude_baseline:
        present.discard("baseline")
    known = [w for w in _WAF_ORDER if w in present]
    extra = sorted(w for w in present if w not in _WAF_ORDER)
    return known + extra


def _mutators_present(df: pd.DataFrame) -> list[str]:
    if df.empty or "mutator" not in df.columns:
        return []
    present = set(df["mutator"].unique())
    known = [m for m in _MUTATOR_ORDER if m in present]
    extra = sorted(m for m in present if m not in _MUTATOR_ORDER)
    return known + extra


def _save(fig: plt.Figure, out_dir: Path, stem: str) -> list[Path]:
    """Save a figure as PNG (300 dpi) and SVG. Returns [png, svg] paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext, kwargs in [("png", {"dpi": 300}), ("svg", {})]:
        p = out_dir / f"{stem}.{ext}"
        fig.savefig(p, bbox_inches="tight", **kwargs)
        paths.append(p)
    plt.close(fig)
    return paths


def heatmap_mutator_waf(df: pd.DataFrame, out_dir: Path, target: str = "dvwa",
                          lens: str = "true_bypass") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens=lens,
    )
    if rates.empty:
        return []
    wafs = _wafs_present(df)
    muts = _mutators_present(df)
    pivot = rates.pivot(index="mutator", columns="waf", values="rate").reindex(
        index=muts, columns=wafs,
    )
    fig, ax = plt.subplots(figsize=(max(6, 0.9 * len(wafs) + 2), max(4, 0.55 * len(muts) + 1.5)))
    sns.heatmap(pivot, annot=True, fmt=".2f", cmap="RdYlGn_r",
                vmin=0, vmax=1, cbar_kws={"label": f"{lens} rate"}, ax=ax)
    ax.set_title(f"{lens.replace('_', ' ').title()} rate — mutator × WAF ({target})")
    ax.set_xlabel("WAF")
    ax.set_ylabel("mutator")
    return _save(fig, out_dir, f"heatmap_mutator_waf_{target}_{lens}")


def bar_table1(df: pd.DataFrame, out_dir: Path, target: str = "dvwa",
                lens: str = "true_bypass") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens=lens,
    )
    if rates.empty:
        return []
    rates = rates.assign(
        err_lo=(rates["rate"] - rates["ci_lo"]).clip(lower=0.0),
        err_hi=(rates["ci_hi"] - rates["rate"]).clip(lower=0.0),
    )
    wafs = _wafs_present(df)
    muts = _mutators_present(df)
    fig, ax = plt.subplots(figsize=(max(9, 1.5 * len(muts) + 2), 5))
    sns.barplot(
        data=rates, x="mutator", y="rate", hue="waf",
        order=muts, hue_order=wafs, ax=ax,
    )
    widths = 0.8 / max(1, len(wafs))
    for i, mut in enumerate(muts):
        for j, waf in enumerate(wafs):
            row = rates[(rates["mutator"] == mut) & (rates["waf"] == waf)]
            if row.empty:
                continue
            x = i - 0.4 + (j + 0.5) * widths
            y = float(row["rate"].iloc[0])
            ax.errorbar(
                x, y,
                yerr=[[float(row["err_lo"].iloc[0])], [float(row["err_hi"].iloc[0])]],
                fmt="none", ecolor="black", elinewidth=1, capsize=3,
            )
    ax.set_ylim(0, 1)
    ax.set_ylabel(f"{lens} rate (95% Wilson CI)")
    ax.set_xlabel("mutator (low rank → high complexity)")
    ax.set_title(f"Bypass rate by mutator × WAF ({target}, {lens})")
    ax.legend(loc="best", fontsize="small", ncols=2)
    return _save(fig, out_dir, f"bar_table1_{target}_{lens}")


def line_complexity(df: pd.DataFrame, out_dir: Path, target: str = "dvwa",
                     lens: str = "true_bypass") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["complexity_rank", "waf"], lens=lens,
    )
    if rates.empty:
        return []
    wafs = _wafs_present(df)
    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    sns.lineplot(
        data=rates, x="complexity_rank", y="rate",
        hue="waf", hue_order=wafs, marker="o", ax=ax,
    )
    for (waf,), sub in rates.groupby(["waf"]):
        ax.fill_between(sub["complexity_rank"], sub["ci_lo"], sub["ci_hi"], alpha=0.10)
    ax.set_ylim(0, 1)
    # Cover ranks 0..7: noop=0, lexical=1..multi_request=5, adaptive=6, adaptive3=7.
    ranks = sorted(int(r) for r in rates["complexity_rank"].unique()) if not rates.empty else [1]
    ax.set_xticks(ranks)
    ax.set_xlabel("complexity rank (0=noop · 1-5=base mutators · 6-7=compositional)")
    ax.set_ylabel(f"{lens} rate")
    ax.set_title(f"Bypass rate vs obfuscation complexity ({target}, {lens})")
    return _save(fig, out_dir, f"line_complexity_{target}_{lens}")


def facet_vuln_class(df: pd.DataFrame, out_dir: Path, target: str = "dvwa",
                       lens: str = "true_bypass") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["vuln_class", "mutator", "waf"], lens=lens,
    )
    if rates.empty:
        return []
    classes = sorted(rates["vuln_class"].unique())
    wafs = _wafs_present(df)
    muts = _mutators_present(df)
    n = len(classes)
    cols = min(3, n)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4.5 * cols, 3.5 * rows), squeeze=False)

    for idx, cls in enumerate(classes):
        ax = axes[idx // cols][idx % cols]
        sub = rates[rates["vuln_class"] == cls]
        pivot = sub.pivot(index="mutator", columns="waf", values="rate").reindex(
            index=muts, columns=wafs,
        )
        sns.heatmap(pivot, annot=True, fmt=".2f", cmap="RdYlGn_r",
                    vmin=0, vmax=1, cbar=False, ax=ax)
        ax.set_title(cls)
        ax.set_xlabel("")
        ax.set_ylabel("")
    for j in range(n, rows * cols):
        axes[j // cols][j % cols].axis("off")
    fig.suptitle(f"Per-vuln-class {lens} rate × mutator × WAF ({target})", y=1.02)
    return _save(fig, out_dir, f"facet_vuln_class_{target}_{lens}")


# ---------------------------------------------------------------------------
# New (post-Phase-7) chart types — surface the differentiation that the
# DVWA-anchored true_bypass charts collapse to zero.
# ---------------------------------------------------------------------------


def pooled_waf_target_heatmap(df: pd.DataFrame, out_dir: Path) -> list[Path]:
    """Headline panel: rows = WAF, cols = target, cell = pooled waf_view rate.

    "Pooled" = ``allowed_or_flagged / (allowed_or_flagged + blocked + blocked_silent)``,
    where the eligible set already excludes ``baseline_fail`` and ``error``
    (see ``compute_rates(lens="waf_view")``). This is the smallest
    information-dense headline the dashboard can ship: one cell per
    (WAF, target) with the rate the operator actually feels.
    """
    if df.empty:
        return []
    wafs = _wafs_present(df)
    targets = sorted(df["target"].unique()) if "target" in df.columns else []
    if not (wafs and targets):
        return []

    rows = []
    for waf in wafs:
        for tgt in targets:
            sub = df[(df["waf"] == waf) & (df["target"] == tgt)]
            r = compute_rates(sub, ["waf"], lens="waf_view")
            if r.empty:
                continue
            row = r.iloc[0].to_dict()
            row["target"] = tgt
            rows.append(row)
    if not rows:
        return []
    flat = pd.DataFrame(rows)
    pivot = flat.pivot(index="waf", columns="target", values="rate").reindex(
        index=wafs, columns=targets,
    )
    n_pivot = flat.pivot(index="waf", columns="target", values="n").reindex(
        index=wafs, columns=targets,
    )
    annot = pivot.copy().astype(object)
    for w in pivot.index:
        for t in pivot.columns:
            v = pivot.at[w, t]
            n = n_pivot.at[w, t]
            if pd.isna(v) or pd.isna(n) or n == 0:
                annot.at[w, t] = ""
            else:
                annot.at[w, t] = f"{v*100:.0f}%\nn={int(n)}"

    fig, ax = plt.subplots(figsize=(max(5, 1.3 * len(targets) + 2.5),
                                    max(3.5, 0.6 * len(wafs) + 1.5)))
    sns.heatmap(pivot, annot=annot, fmt="", cmap="RdYlGn_r",
                vmin=0, vmax=1, cbar_kws={"label": "pooled waf_view bypass rate"},
                linewidths=0.5, linecolor="white", ax=ax)
    ax.set_title("Pooled bypass rate — WAF × target (every mutator, every class)")
    ax.set_xlabel("target")
    ax.set_ylabel("WAF")
    return _save(fig, out_dir, "pooled_waf_target")


def waf_class_heatmap(df: pd.DataFrame, out_dir: Path,
                       target: str = "juiceshop") -> list[Path]:
    """Where each WAF leaks by vuln class.

    Rows = WAF, cols = vuln_class, cell = waf_view rate aggregated over
    every mutator on ``target``. Picks ``juiceshop`` by default because
    that's where the WAFs actually differ — DVWA collapses to 0 across
    the board.
    """
    if df.empty:
        return []
    sub = df[(df["target"] == target) & (df["waf"] != "baseline")]
    if sub.empty:
        return []
    rates = compute_rates(sub, ["waf", "vuln_class"], lens="waf_view")
    if rates.empty:
        return []
    wafs = _wafs_present(sub)
    classes = sorted(rates["vuln_class"].unique())
    pivot = rates.pivot(index="waf", columns="vuln_class", values="rate").reindex(
        index=wafs, columns=classes,
    )

    fig, ax = plt.subplots(figsize=(max(7, 0.9 * len(classes) + 2),
                                    max(3.5, 0.6 * len(wafs) + 1.5)))
    sns.heatmap(pivot, annot=True, fmt=".0%", cmap="RdYlGn_r",
                vmin=0, vmax=1, cbar_kws={"label": "waf_view bypass rate"},
                linewidths=0.5, linecolor="white", ax=ax)
    ax.set_title(f"WAF × vuln class — {target} ({target}: where the WAFs differ)")
    ax.set_xlabel("vuln class")
    ax.set_ylabel("WAF")
    return _save(fig, out_dir, f"waf_class_{target}")


def latency_vs_bypass_scatter(df: pd.DataFrame, out_dir: Path) -> list[Path]:
    """Trade-off chart: x = WAF p50 latency (ms), y = pooled bypass rate.

    One marker per (WAF, target). Points in the upper-right are slow AND
    leaky (worst trade-off); lower-left is fast AND tight (best). Useful
    for "is shadowd's slowness buying us anything?" type questions.
    """
    if df.empty:
        return []
    wafs = _wafs_present(df)
    targets = sorted(df["target"].unique()) if "target" in df.columns else []
    if not (wafs and targets):
        return []

    lat = latency_stats(df[df["waf"] != "baseline"], groupby=["waf", "target"])
    if lat.empty:
        return []

    rate_rows = []
    for waf in wafs:
        for tgt in targets:
            sub = df[(df["waf"] == waf) & (df["target"] == tgt)]
            r = compute_rates(sub, ["waf"], lens="waf_view")
            if r.empty:
                continue
            row = r.iloc[0].to_dict()
            row["target"] = tgt
            rate_rows.append(row)
    rate_df = pd.DataFrame(rate_rows)
    if rate_df.empty:
        return []

    merged = lat.merge(rate_df, on=["waf", "target"], how="inner",
                        suffixes=("_lat", "_rate"))
    if merged.empty:
        return []

    fig, ax = plt.subplots(figsize=(7.5, 5))
    palette = sns.color_palette("tab10", n_colors=len(wafs))
    waf_to_color = {w: palette[i % len(palette)] for i, w in enumerate(wafs)}
    target_markers = {t: m for t, m in zip(targets, ["o", "s", "D", "^", "v", "P", "X"])}

    for _, r in merged.iterrows():
        ax.scatter(
            r["p50"], r["rate"],
            color=waf_to_color.get(r["waf"], "gray"),
            marker=target_markers.get(r["target"], "o"),
            s=80 + r["n_rate"] / 50,
            edgecolor="black", linewidth=0.5, alpha=0.85,
        )
        ax.annotate(
            f"{r['waf']}·{r['target']}",
            (r["p50"], r["rate"]),
            xytext=(5, 4), textcoords="offset points",
            fontsize=7, alpha=0.75,
        )

    ax.set_xlabel("WAF p50 latency (ms)")
    ax.set_ylabel("pooled waf_view bypass rate")
    ax.set_ylim(-0.02, 1.02)
    ax.set_xscale("log")
    ax.grid(True, which="both", alpha=0.3)
    ax.set_title("Trade-off — latency vs bypass (lower-left = fast & tight; upper-right = slow & leaky)")
    return _save(fig, out_dir, "latency_vs_bypass")


def render_all(df: pd.DataFrame, out_dir: Path, target: str = "dvwa",
                lens: str = "true_bypass") -> list[Path]:
    """Emit every chart. Returns the flat list of output paths."""
    sns.set_theme(style="whitegrid", context="paper")
    paths: list[Path] = []
    paths += heatmap_mutator_waf(df, out_dir, target, lens=lens)
    paths += bar_table1(df, out_dir, target, lens=lens)
    paths += line_complexity(df, out_dir, target, lens=lens)
    paths += facet_vuln_class(df, out_dir, target, lens=lens)
    paths += pooled_waf_target_heatmap(df, out_dir)
    paths += waf_class_heatmap(df, out_dir, target=target)
    paths += latency_vs_bypass_scatter(df, out_dir)
    return paths
