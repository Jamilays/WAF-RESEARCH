"""Combined Markdown + LaTeX reporter — headline 4-WAF × paranoia table.

Consumes a merged DataFrame (``analyzer.combined.combine_runs``) and renders
``report-combined.md`` / ``report-combined.tex`` with:

  1. Provenance block — which run_id each WAF's numbers came from
  2. Headline Table 1 — rows = mutator, cols = every WAF that appeared in
     the merged set, in a stable display order (modsec, coraza, shadowd,
     openappsec, modsec-ph, coraza-ph, any unknowns alphabetical)
  3. WAF-view appendix — per-(mutator × waf × target) for all targets
  4. Bibliography — same entries as the single-run reporter

Unlike the per-run reporter, there's no "anchor target" debate: all runs
being merged should share a DVWA route, and we anchor true-bypass on DVWA
exactly like the per-run report does.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from wafeval.analyzer.bypass import compute_rates
from wafeval.reporter._data import BIBLIOGRAPHY, PAPER_TABLE1


_MUT_ORDER = ["lexical", "encoding", "structural", "context_displacement", "multi_request"]
_PREFERRED_WAF_ORDER = ["modsec", "coraza", "shadowd", "openappsec", "modsec-ph", "coraza-ph"]
_MIN_N = 5


def _order_wafs(wafs: list[str]) -> list[str]:
    """Place known WAFs in paper/compose order; append unknowns alphabetically."""
    known = [w for w in _PREFERRED_WAF_ORDER if w in wafs]
    extra = sorted(w for w in wafs if w not in _PREFERRED_WAF_ORDER and w != "baseline")
    return known + extra


def _fmt_rate(r: float, lo: float, hi: float, n: int | None = None) -> str:
    if pd.isna(r) or (n is not None and n < _MIN_N):
        return "—"
    return f"{r*100:.1f}% (±{max(r-lo, hi-r)*100:.1f}pp)"


def _esc_tex(text: str) -> str:
    return (text.replace("\\", "\\textbackslash{}")
                .replace("&", "\\&").replace("%", "\\%")
                .replace("_", "\\_").replace("#", "\\#")
                .replace("$", "\\$").replace("{", "\\{").replace("}", "\\}"))


def _headline_table_md(df: pd.DataFrame, wafs: list[str], target: str) -> str:
    if df.empty or "target" not in df.columns:
        return "*(no data — merged run set is empty on this anchor target)*"
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return "*(no data — merged run set is empty on this anchor target)*"
    p = rates.set_index(["mutator", "waf"])

    header = "| Mutator | " + " | ".join(wafs) + " | Paper |"
    sep = "|---|" + "|".join(["---:"] * len(wafs)) + "|---:|"
    lines = [header, sep]
    for mut in _MUT_ORDER:
        cells: list[str] = []
        for waf in wafs:
            if (mut, waf) in p.index:
                r = p.loc[(mut, waf)]
                cells.append(_fmt_rate(r["rate"], r["ci_lo"], r["ci_hi"], int(r["n"])))
            else:
                cells.append("—")
        paper = PAPER_TABLE1.get(mut)
        paper_cell = f"{paper*100:.1f}%" if paper is not None else "—"
        lines.append(f"| `{mut}` | " + " | ".join(cells) + f" | {paper_cell} |")
    lines.append("")
    lines.append(f"*Cells with n < {_MIN_N} baseline-triggered datapoints are "
                 f"rendered as `—` (Wilson CI half-width ≥ 0.4 at that size).* "
                 f"*`modsec-ph` / `coraza-ph` denote the `--profile paranoia-high` "
                 f"variants (PL4 rules on the same CRS v4 set).*")
    return "\n".join(lines)


def _headline_table_tex(df: pd.DataFrame, wafs: list[str], target: str) -> str:
    if df.empty or "target" not in df.columns:
        return r"\textit{no data}"
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return r"\textit{no data}"
    p = rates.set_index(["mutator", "waf"])
    col_spec = "l" + "r" * (len(wafs) + 1)
    header = " & ".join([r"mutator"] + [_esc_tex(w) for w in wafs] + ["paper"])
    lines = [
        r"\begin{table}[tb]",
        r"\centering",
        r"\caption{True-bypass rate by mutator $\times$ WAF on DVWA across the "
        r"merged run set. \textit{paper} is Yusifova~\cite{yusifova2024}. "
        r"\texttt{modsec-ph} / \texttt{coraza-ph} are the paranoia-high "
        r"variants (PL4 CRS v4).}",
        r"\label{tab:combined}",
        r"\begin{tabular}{" + col_spec + "}",
        r"\toprule",
        header + r" \\",
        r"\midrule",
    ]
    for mut in _MUT_ORDER:
        cells = []
        for waf in wafs:
            if (mut, waf) in p.index:
                r = p.loc[(mut, waf), "rate"]
                n = int(p.loc[(mut, waf), "n"])
                cells.append(f"{r*100:.1f}\\%" if n >= _MIN_N else "---")
            else:
                cells.append("---")
        paper = PAPER_TABLE1.get(mut)
        paper_cell = f"{paper*100:.1f}\\%" if paper is not None else "---"
        disp = mut.replace("_", r"\_")
        lines.append(f"\\texttt{{{disp}}} & " + " & ".join(cells) + f" & {paper_cell} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


def _waf_view_md(df: pd.DataFrame, wafs: list[str]) -> str:
    if df.empty or "waf" not in df.columns:
        return "*(no data)*"
    rates = compute_rates(
        df[df["waf"] != "baseline"],
        ["mutator", "waf", "target"], lens="waf_view",
    )
    if rates.empty:
        return "*(no data)*"
    rates = rates[rates["waf"].isin(wafs)]
    lines = ["| mutator | waf | target | rate | n |",
             "|---|---|---|---:|---:|"]
    for _, r in rates.iterrows():
        lines.append(
            f"| `{r['mutator']}` | {r['waf']} | {r['target']} | "
            f"{r['rate']*100:.1f}% | {int(r['n'])} |"
        )
    return "\n".join(lines)


def _provenance_md(provenance: dict[str, str], wafs: list[str]) -> str:
    lines = ["| WAF | Source run_id |", "|---|---|"]
    for w in wafs:
        rid = provenance.get(w, "—")
        lines.append(f"| `{w}` | `{rid}` |")
    if "baseline" in provenance:
        lines.append(f"| `baseline` | `{provenance['baseline']}` |")
    return "\n".join(lines)


def render_combined_markdown(
    df: pd.DataFrame,
    provenance: dict[str, str],
    out_path: Path,
    run_ids: list[str],
    anchor_target: str = "dvwa",
) -> Path:
    """Render ``report-combined.md``."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    wafs_in_df = sorted(df["waf"].unique().tolist()) if not df.empty else []
    wafs = _order_wafs(wafs_in_df)

    bib = "\n".join(f"{i+1}. {e}" for i, e in enumerate(BIBLIOGRAPHY))
    run_list = "\n".join(f"- `{rid}`" for rid in run_ids)

    md = f"""# WAF Evasion Lab — combined report

- **Generated:** {now}
- **Merged run_ids (in provenance order — last-in-list wins on WAF overlap):**

{run_list}

- **Anchor target for true-bypass numbers:** `{anchor_target}` (DVWA, the
  only target with dependable triggers across all twelve vuln classes).

## WAF provenance

Every cell in Table 1 below is traceable to a single source run. If a WAF
was present in more than one merged run, the run listed here is the one
whose rows survived the de-duplication pass (last-in-list wins).

{_provenance_md(provenance, wafs)}

## Table 1 — true-bypass rate by mutator × WAF (DVWA, combined)

{_headline_table_md(df, wafs, anchor_target)}

*Cells are mean bypass rate with 95% Wilson CI half-width.* *"Paper" column
reproduces Yusifova (2024) §Results aggregate for reference.*

## Appendix A — WAF-view rates (baseline-agnostic)

Useful for `context_displacement` / `multi_request` variants whose sink
differs from the baseline's, and for Juice Shop cells where the trigger is
class-specific.

{_waf_view_md(df, wafs)}

## Bibliography

{bib}
"""
    out_path.write_text(md)
    return out_path


def render_combined_latex(
    df: pd.DataFrame,
    provenance: dict[str, str],
    out_path: Path,
    run_ids: list[str],
    anchor_target: str = "dvwa",
) -> Path:
    """Render ``report-combined.tex`` (IEEE conference class)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    wafs_in_df = sorted(df["waf"].unique().tolist()) if not df.empty else []
    wafs = _order_wafs(wafs_in_df)
    table = _headline_table_tex(df, wafs, anchor_target)

    keys = ["yusifova2024", "crs", "coraza", "shadowd", "openappsec", "portswigger"]
    bib_lines = [r"\begin{thebibliography}{9}"]
    for k, entry in zip(keys, BIBLIOGRAPHY):
        bib_lines.append(f"\\bibitem{{{k}}} {_esc_tex(entry)}")
    bib_lines.append(r"\end{thebibliography}")
    bib = "\n".join(bib_lines)

    run_list_esc = ", ".join(_esc_tex(rid) for rid in run_ids)
    now_esc = _esc_tex(now)

    body = (
        "\\documentclass[conference]{IEEEtran}\n"
        "\\usepackage[utf8]{inputenc}\n"
        "\\usepackage{graphicx}\n"
        "\\usepackage{booktabs}\n"
        "\\usepackage{hyperref}\n"
        "\\usepackage{caption}\n\n"
        "\\title{WAF Evasion Lab --- combined 4-WAF comparison}\n"
        "\\author{%\n"
        "  \\IEEEauthorblockN{Generated by \\texttt{wafeval report-combined}}\n"
        "  \\IEEEauthorblockA{Merged runs: " + run_list_esc + " --- " + now_esc + "}\n"
        "}\n\n"
        "\\begin{document}\n"
        "\\maketitle\n\n"
        "\\begin{abstract}\n"
        "This report merges per-run artifacts from the WAF Evasion Lab into a "
        "single headline comparison across all four open-source WAFs "
        "(ModSecurity + CRS v4, Coraza, Shadow Daemon, open-appsec) plus the "
        "paranoia-high variants of the two rule-based CRS deployments. True-"
        "bypass rates are reported on DVWA --- the anchor target whose "
        "baseline triggers fire dependably across every payload class.\n"
        "\\end{abstract}\n\n"
        "\\section{Methodology}\n"
        "Each WAF's row in Table~\\ref{tab:combined} is sourced from a single "
        "``\\texttt{wafeval run}'' invocation. When a WAF appeared in more "
        "than one merged run, the last run listed on the command line wins "
        "(so the freshest data for each WAF survives de-duplication).\n\n"
        f"{table}\n\n"
        "\\section{Conclusions}\n"
        "See the accompanying \\texttt{report-combined.md} for the "
        "WAF-provenance block and baseline-agnostic WAF-view appendix.\n\n"
        f"{bib}\n\n"
        "\\end{document}\n"
    )
    out_path.write_text(body)
    return out_path
