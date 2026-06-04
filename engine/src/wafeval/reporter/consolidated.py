"""Consolidated headline reporter.

Takes up to three input runs and renders a single Markdown report that
foregrounds the *interesting* numbers buried under the per-run reporter's
DVWA-anchored Table 1:

* an **attack run** (the canonical 5-mutators × 12-classes × 7-WAFs scan)
* an optional **adaptive run** (rank-6/7 compositional mutators)
* an optional **benign run** (``--classes benign --mutators noop``) for
  the false-positive-rate trade-off

Output sections, in the order the reader sees them:

  1. Headline panel (pooled WAF × target heatmap, all attack data)
  2. Attack vs FPR table — bypass + false-positive side by side
  3. Table 1 anchored on Juice Shop (the differentiating target)
  4. Compositional uplift — adaptive / adaptive3 vs single mutator
  5. Paranoia ablation — modsec PL1↔PL4 vs coraza PL1↔PL4
  6. WAF × vuln-class heatmap on Juice Shop
  7. Latency-vs-bypass scatter (from the attack run)
  8. Hall of Fame — best variant per payload (dedup'ed)
  9. Appendix A — full waf_view rates table
 10. Appendix B — latency profile
 11. Bibliography

Unlike ``reporter.combined``, this reporter does **not** dedup by WAF —
it expects the input runs to be disjoint in (waf, mutator) space (the
attack run owns the base mutators, the adaptive run owns rank-6/7, the
benign run owns ``noop``). Concatenation is therefore safe.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from wafeval.analyzer.aggregate import load_run
from wafeval.analyzer.bypass import compute_rates
from wafeval.analyzer.charts import (
    bar_table1,
    facet_vuln_class,
    heatmap_mutator_waf,
    latency_vs_bypass_scatter,
    line_complexity,
    pooled_waf_target_heatmap,
    waf_class_heatmap,
)
from wafeval.analyzer.latency import latency_stats, render_markdown_table as render_latency_md
from wafeval.analyzer.paranoia import build_paranoia_table
from wafeval.analyzer.paranoia import render_markdown as render_paranoia_md
from wafeval.reporter._data import BIBLIOGRAPHY
from wafeval.reporter.hall_of_fame import hall_of_fame, render_markdown as render_hall_of_fame


_PREFERRED_WAF_ORDER = ["modsec", "coraza", "shadowd", "openappsec",
                         "modsec-ph", "coraza-ph"]
_PREFERRED_MUT_ORDER = ["lexical", "encoding", "structural",
                         "context_displacement", "multi_request",
                         "adaptive", "adaptive3", "noop"]


def _wafs_in(df: pd.DataFrame) -> list[str]:
    if df.empty or "waf" not in df.columns:
        return []
    present = set(df["waf"].unique()) - {"baseline"}
    known = [w for w in _PREFERRED_WAF_ORDER if w in present]
    extra = sorted(w for w in present if w not in _PREFERRED_WAF_ORDER)
    return known + extra


def _muts_in(df: pd.DataFrame) -> list[str]:
    if df.empty or "mutator" not in df.columns:
        return []
    present = set(df["mutator"].unique())
    known = [m for m in _PREFERRED_MUT_ORDER if m in present]
    extra = sorted(m for m in present if m not in _PREFERRED_MUT_ORDER)
    return known + extra


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _provenance_md(attack_id: str, adaptive_id: str | None, benign_id: str | None) -> str:
    rows = [f"| attack | `{attack_id}` |"]
    if adaptive_id:
        rows.append(f"| adaptive | `{adaptive_id}` |")
    else:
        rows.append("| adaptive | *(skipped)* |")
    if benign_id:
        rows.append(f"| benign / FPR | `{benign_id}` |")
    else:
        rows.append("| benign / FPR | *(skipped — no FPR data)* |")
    return "| Source | run_id |\n|---|---|\n" + "\n".join(rows)


def _attack_vs_fpr_md(attack_df: pd.DataFrame, benign_df: pd.DataFrame | None,
                       target: str) -> str:
    """Per-WAF: pooled bypass rate (attack), pooled FPR (benign), trade-off score.

    FPR = ``1 − waf_view rate`` on the benign corpus (i.e. the share of
    benign requests the WAF *did not* let through). The trade-off cell
    flags "good operational defaults" — high block on attack, low block
    on benign.
    """
    if attack_df.empty:
        return "*(no attack data)*"
    a_sub = attack_df[(attack_df["target"] == target) & (attack_df["waf"] != "baseline")]
    if a_sub.empty:
        return f"*(no attack data on target `{target}`)*"
    a_rates = compute_rates(a_sub, ["waf"], lens="waf_view")
    if a_rates.empty:
        return f"*(attack rates empty on target `{target}`)*"

    if benign_df is not None and not benign_df.empty:
        b_sub = benign_df[(benign_df["target"] == target) & (benign_df["waf"] != "baseline")]
        b_rates = compute_rates(b_sub, ["waf"], lens="waf_view")
    else:
        b_rates = pd.DataFrame(columns=["waf", "rate", "n"])

    wafs = _wafs_in(attack_df)
    a_idx = a_rates.set_index("waf") if not a_rates.empty else pd.DataFrame()
    b_idx = b_rates.set_index("waf") if not b_rates.empty else pd.DataFrame()

    lines = [
        "| WAF | bypass rate (attack) | n | FPR (benign) | n | block-attack ÷ block-benign |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for waf in wafs:
        if waf not in a_idx.index:
            continue
        ar = float(a_idx.loc[waf, "rate"])
        an = int(a_idx.loc[waf, "n"])
        bypass_cell = f"{ar*100:.1f}%"

        if waf in b_idx.index:
            br = float(b_idx.loc[waf, "rate"])
            bn = int(b_idx.loc[waf, "n"])
            fpr = 1.0 - br
            fpr_cell = f"{fpr*100:.1f}%"
            bn_cell = str(bn)
            # Operational ratio: how many attacks blocked per benign blocked.
            block_attack = 1.0 - ar
            block_benign = 1.0 - br
            if block_benign <= 0:
                ratio_cell = "∞" if block_attack > 0 else "—"
            else:
                ratio_cell = f"{block_attack / block_benign:.2f}×"
        else:
            fpr_cell = "—"
            bn_cell = "—"
            ratio_cell = "—"

        lines.append(
            f"| `{waf}` | {bypass_cell} | {an} | {fpr_cell} | {bn_cell} | {ratio_cell} |"
        )
    return "\n".join(lines)


def _table1_md(df: pd.DataFrame, target: str) -> str:
    if df.empty:
        return "*(no data)*"
    # Exclude benign + noop from the bypass headline — those belong in the
    # FPR table (section 2). Mixing benign rows here makes "100% bypass on
    # noop" look like a WAF failure when it's just "WAF correctly let
    # benign traffic through".
    sub = df[
        (df["target"] == target)
        & (df["waf"] != "baseline")
        & (df["vuln_class"] != "benign")
        & (df["mutator"] != "noop")
    ]
    if sub.empty:
        return f"*(no rows on `{target}` after excluding benign/noop)*"
    rates = compute_rates(sub, ["mutator", "waf"], lens="waf_view")
    if rates.empty:
        return "*(no rates)*"
    p = rates.set_index(["mutator", "waf"])

    wafs = _wafs_in(sub)
    muts = _muts_in(sub)
    header = "| Mutator | " + " | ".join(wafs) + " | Pooled |"
    sep = "|---|" + "|".join(["---:"] * len(wafs)) + "|---:|"
    lines = [header, sep]
    pooled = compute_rates(sub, ["mutator"], lens="waf_view").set_index("mutator")
    # For mutators that were exercised on a target *other* than the anchor
    # (e.g. paper_subset XSS skips Juice Shop, so adaptive/adaptive3 land on
    # DVWA + WebGoat), fall back to a cross-target pooled rate so the row
    # isn't a wall of dashes. Renders the cross-target rate with a marker
    # so the reader knows it's not anchor-equivalent.
    cross_target_pooled = compute_rates(
        df[(df["waf"] != "baseline")
           & (df["vuln_class"] != "benign")
           & (df["mutator"] != "noop")],
        ["mutator", "waf"], lens="waf_view",
    )
    cross_target_pooled = cross_target_pooled.set_index(["mutator", "waf"]) if not cross_target_pooled.empty else cross_target_pooled
    for mut in muts:
        cells = []
        # Detect a "no anchor coverage" row so we can render the cross-target
        # fallback with a † marker. Anchor rows look like every cell is "—".
        anchor_n = sum(int(p.loc[(mut, w), "n"]) if (mut, w) in p.index else 0 for w in wafs)
        anchor_missing = anchor_n == 0
        for waf in wafs:
            if (mut, waf) in p.index and int(p.loc[(mut, waf), "n"]) >= 5:
                r = float(p.loc[(mut, waf), "rate"])
                cells.append(f"{r*100:.1f}%")
            elif anchor_missing and not cross_target_pooled.empty and (mut, waf) in cross_target_pooled.index:
                r = float(cross_target_pooled.loc[(mut, waf), "rate"])
                n = int(cross_target_pooled.loc[(mut, waf), "n"])
                cells.append(f"{r*100:.1f}%†" if n >= 5 else "—")
            else:
                cells.append("—")
        if mut in pooled.index and int(pooled.loc[mut, "n"]) >= 5:
            pooled_cell = f"**{pooled.loc[mut, 'rate']*100:.1f}%** (n={int(pooled.loc[mut, 'n'])})"
        elif anchor_missing:
            # Pool the fallback across all targets per-mutator for the row total.
            mut_rows = df[(df["waf"] != "baseline")
                          & (df["vuln_class"] != "benign")
                          & (df["mutator"] == mut)]
            mut_pooled = compute_rates(mut_rows, ["mutator"], lens="waf_view")
            if not mut_pooled.empty and int(mut_pooled["n"].iloc[0]) >= 5:
                pooled_cell = (f"**{mut_pooled['rate'].iloc[0]*100:.1f}%†** "
                               f"(n={int(mut_pooled['n'].iloc[0])})")
            else:
                pooled_cell = "—"
        else:
            pooled_cell = "—"
        lines.append(f"| `{mut}` | " + " | ".join(cells) + f" | {pooled_cell} |")
    lines.append("")
    lines.append("*Cells marked **†** are pooled across every target the "
                 "mutator was exercised on (not just the anchor) — useful when "
                 "the mutator's corpus has no anchor-target endpoint, e.g. "
                 "paper_subset XSS on Juice Shop.*")
    return "\n".join(lines)


def _compositional_uplift_md(attack_df: pd.DataFrame, adaptive_df: pd.DataFrame | None) -> str:
    """Per (WAF × target): best base mutator rate, adaptive rate, adaptive3 rate, Δ.

    The compositional uplift story is **per-target** — it's the strongest on
    cells where the base mutators are tight (low leak rate) and stacking adds
    bypass headroom. Cross-target pooling washed this out: WebGoat's tight
    base mutators (≤2% lexical) are diluted by Juice Shop's leaky ones (50%+
    encoding). Per-target rows make the "stacking helps where the WAF is
    actually catching" finding readable.

    The "Δ" column = ``best(adaptive, adaptive3) − best base mutator rate``,
    bolded when > 5 pp. Cells with n < 5 on the adaptive run are dropped
    since their CI is uninformative.
    """
    if attack_df.empty:
        return "*(no attack data)*"
    if adaptive_df is None or adaptive_df.empty:
        return "*(no adaptive run provided — re-run with `--adaptive-run-id` to populate)*"

    base_sub = attack_df[attack_df["waf"] != "baseline"]
    base_rates = compute_rates(base_sub, ["waf", "target", "mutator"], lens="waf_view")

    adapt_sub = adaptive_df[adaptive_df["waf"] != "baseline"]
    adapt_rates = compute_rates(adapt_sub, ["waf", "target", "mutator"], lens="waf_view")
    if adapt_rates.empty:
        return "*(adaptive run is empty after waf filter)*"

    wafs = _wafs_in(adapt_sub)
    targets = sorted(adapt_sub["target"].unique()) if "target" in adapt_sub.columns else []
    lines = [
        "| WAF | target | best base mutator | adaptive (r6) | adaptive3 (r7) | Δ best-comp − base |",
        "|---|---|---|---:|---:|---:|",
    ]
    for waf in wafs:
        for tgt in targets:
            b = base_rates[(base_rates["waf"] == waf) & (base_rates["target"] == tgt)]
            b = b[b["n"] >= 5]
            if b.empty:
                best_str, best_val = "—", None
            else:
                top = b.sort_values("rate", ascending=False).iloc[0]
                best_val = float(top["rate"])
                best_str = f"`{top['mutator']}` {best_val*100:.0f}%"

            a6 = adapt_rates[(adapt_rates["waf"] == waf) & (adapt_rates["target"] == tgt)
                              & (adapt_rates["mutator"] == "adaptive")]
            a7 = adapt_rates[(adapt_rates["waf"] == waf) & (adapt_rates["target"] == tgt)
                              & (adapt_rates["mutator"] == "adaptive3")]
            a6 = a6[a6["n"] >= 5]
            a7 = a7[a7["n"] >= 5]
            a6_val = float(a6["rate"].iloc[0]) if not a6.empty else None
            a7_val = float(a7["rate"].iloc[0]) if not a7.empty else None
            a6_str = f"{a6_val*100:.0f}% (n={int(a6['n'].iloc[0])})" if a6_val is not None else "—"
            a7_str = f"{a7_val*100:.0f}% (n={int(a7['n'].iloc[0])})" if a7_val is not None else "—"

            comp_best = max((v for v in (a6_val, a7_val) if v is not None), default=None)
            if comp_best is not None and best_val is not None:
                d = (comp_best - best_val) * 100.0
                if d >= 5:
                    delta = f"**+{d:.0f}pp**"
                elif d > 0:
                    delta = f"+{d:.0f}pp"
                else:
                    delta = f"{d:.0f}pp"
            else:
                delta = "—"

            # Skip rows where neither side produced data — keeps the table readable.
            if best_val is None and a6_val is None and a7_val is None:
                continue
            lines.append(f"| `{waf}` | `{tgt}` | {best_str} | {a6_str} | {a7_str} | {delta} |")
    return "\n".join(lines)


def _waf_view_appendix_md(df: pd.DataFrame) -> str:
    if df.empty:
        return "*(no data)*"
    rates = compute_rates(df[df["waf"] != "baseline"],
                           ["mutator", "waf", "target"], lens="waf_view")
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


def _figure_md(figures: list[Path], stems: list[str], out_dir: Path) -> str:
    """Inline a hand-picked subset of the rendered chart paths."""
    keep: list[Path] = []
    for stem in stems:
        for p in figures:
            if p.suffix == ".png" and p.stem == stem:
                keep.append(p)
                break
    if not keep:
        return ""
    lines: list[str] = []
    for p in keep:
        try:
            rel = p.resolve().relative_to(out_dir.resolve())
        except ValueError:
            rel = p
        title = p.stem.replace("_", " ")
        lines.append(f"### {title}\n\n![{title}]({rel})\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def render_consolidated(
    raw_root: Path,
    attack_run_id: str,
    adaptive_run_id: str | None,
    benign_run_id: str | None,
    out_dir: Path,
    figures_dir: Path,
    anchor_target: str = "juiceshop",
) -> Path:
    """Render ``report-headline.md`` + a fixed set of figures.

    Returns the path of the rendered Markdown file. Figures land under
    ``figures_dir/`` next to (not inside) the report — same convention as
    the per-run reporter.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    attack_df = load_run(raw_root, attack_run_id)
    adaptive_df = load_run(raw_root, adaptive_run_id) if adaptive_run_id else pd.DataFrame()
    benign_df = load_run(raw_root, benign_run_id) if benign_run_id else pd.DataFrame()

    # The merged frame is what most charts read. Disjoint by construction:
    # attack (base mutators + 12 attack classes), adaptive (rank-6/7), benign
    # (noop / class=benign). Concatenation is safe.
    frames = [df for df in (attack_df, adaptive_df, benign_df) if not df.empty]
    merged = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()

    # Charts. We render each twice (PNG + SVG) by way of charts.py's _save.
    figures: list[Path] = []
    figures += pooled_waf_target_heatmap(attack_df, figures_dir)
    figures += waf_class_heatmap(attack_df, figures_dir, target=anchor_target)
    figures += latency_vs_bypass_scatter(attack_df, figures_dir)
    figures += heatmap_mutator_waf(merged, figures_dir, target=anchor_target, lens="waf_view")
    figures += bar_table1(merged, figures_dir, target=anchor_target, lens="waf_view")
    figures += line_complexity(merged, figures_dir, target=anchor_target, lens="waf_view")
    figures += facet_vuln_class(attack_df, figures_dir, target=anchor_target, lens="waf_view")

    # Section payloads.
    provenance = _provenance_md(attack_run_id, adaptive_run_id, benign_run_id)
    attack_vs_fpr = _attack_vs_fpr_md(attack_df, benign_df if not benign_df.empty else None,
                                        target=anchor_target)
    table1 = _table1_md(merged, target=anchor_target)
    uplift = _compositional_uplift_md(
        attack_df,
        adaptive_df if not adaptive_df.empty else None,
    )
    paranoia = render_paranoia_md(build_paranoia_table(attack_df, target=anchor_target))
    # Hall of Fame: attack payloads only — benign passing through is the
    # designed outcome, not an "exploit", so it has no place in a gallery
    # of bypasses.
    hof_input = merged[merged["vuln_class"] != "benign"] if "vuln_class" in merged.columns else merged
    hof = render_hall_of_fame(hall_of_fame(hof_input, top_n=15, dedup_by_payload=True))
    appendix_a = _waf_view_appendix_md(merged)

    lat_df = merged[merged["waf"] != "baseline"] if "waf" in merged.columns else merged
    appendix_b = render_latency_md(latency_stats(lat_df, groupby=["waf", "target"]))

    # Pick the most informative inline figures.
    figure_block = _figure_md(figures, [
        "pooled_waf_target",
        f"waf_class_{anchor_target}",
        "latency_vs_bypass",
        f"heatmap_mutator_waf_{anchor_target}_waf_view",
    ], out_dir)

    bib = "\n".join(f"{i+1}. {e}" for i, e in enumerate(BIBLIOGRAPHY))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    md = f"""# WAF Evasion Lab — headline report

- **Generated:** {now}
- **Anchor target:** `{anchor_target}` (the target where WAFs actually
  differ — DVWA collapses to ~0% across the board, masking the signal).

## Provenance

{provenance}

## 1. Headline panel — pooled bypass rate (WAF × target)

Each cell is the pooled `waf_view` bypass rate over every mutator and
every vuln class in the **attack run**. `baseline_fail` and `error` rows
are excluded — the denominator is "requests that actually tested the
WAF", not "all rows on disk".

![pooled_waf_target](../../figures/{out_dir.name}/pooled_waf_target.png)

## 2. Attack vs FPR — the operational trade-off

Pooled bypass rate against the attack corpus, side by side with the
false-positive rate measured on the benign corpus (a real user's
realistic searches and natural English). The right-most column is
`block-attack ÷ block-benign`: how many attacks each WAF blocks per
benign request it also blocks. >10× is operationally usable; ~1× means
the WAF is blocking everything indiscriminately.

{attack_vs_fpr}

## 3. Table 1 — bypass rate × mutator × WAF (`{anchor_target}`, waf_view)

Anchored on `{anchor_target}` because that's where the WAFs
differentiate; DVWA pinned every base mutator at 0%. Pooled column is
the mutator's rate across all listed WAFs combined (each request
weighted equally).

{table1}

*Cells with `n < 5` baseline-eligible datapoints are rendered as `—`
(Wilson CI half-width ≥ 0.4 at that size). This table includes the
compositional `adaptive` / `adaptive3` rows when an adaptive run was
supplied.*

## 4. Compositional uplift — does stacking transforms beat single mutators?

The lab's adaptive mutator (rank 6) stacks pairs of base mutators;
adaptive3 (rank 7) stacks triples. The hypothesis from prior work is
"each composition layer strictly increases bypass rate".

{uplift}

## 5. Paranoia ablation — PL1 vs PL4 (CRS-derived WAFs)

Side by side: each rule-based WAF run at PL1 (default) and PL4
(paranoia-high). A negative delta means PL4 closes the gap. The known
deployment gotcha — `PARANOIA=N` env var on the upstream ModSec image
*doesn't* activate the JSON-SQL plugin rules — should show up as a
near-zero delta on `ModSec` while `Coraza` closes meaningfully.

{paranoia}

## 6. WAF × vuln class on `{anchor_target}`

![waf_class_{anchor_target}](../../figures/{out_dir.name}/waf_class_{anchor_target}.png)

Per-class bypass rate aggregated over every mutator. Reading top-down
identifies which payload families each WAF struggles with. Bands of red
across a row = a WAF that's broadly weak on `{anchor_target}`; a single
red cell = a class-specific blind spot.

## 7. Latency vs detection trade-off

![latency_vs_bypass](../../figures/{out_dir.name}/latency_vs_bypass.png)

x = WAF p50 latency (log-ms), y = pooled bypass rate. Points in the
**lower-left** are fast and tight (the goal). Points **upper-right** are
slow and leaky (the trap). Marker size ∝ datapoint count.

## 8. Hall of Fame — top exploit families

Best variant per source payload (deduped — the original report had
eleven variants of the same `admin'-- -` taking rows 2-12).

{hof}

## 9. Appendix A — full waf_view rates

{appendix_a}

## 10. Appendix B — latency profile

{appendix_b}

## 11. Bibliography

{bib}
"""
    out_path = out_dir / "report-headline.md"
    out_path.write_text(md)
    return out_path
