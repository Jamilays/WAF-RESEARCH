"""LaTeX reporter — IEEE conference class output.

Produces ``report.tex`` that compiles with ``pdflatex`` to an IEEE-style PDF.
The sidecar container (docker-compose profile ``report``) mounts
``results/reports/<run_id>/`` and runs ``pdflatex report.tex`` twice so
references resolve.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from wafeval.analyzer.bypass import compute_rates
from wafeval.reporter._data import BIBLIOGRAPHY, PAPER_TABLE1


_WAF_ORDER = ["modsec", "coraza", "shadowd"]
_MUT_ORDER = ["lexical", "encoding", "structural", "context\\_displacement", "multi\\_request"]
_MUT_RAW   = ["lexical", "encoding", "structural", "context_displacement", "multi_request"]


def _esc(text: str) -> str:
    """Minimal LaTeX-escape for user-facing strings."""
    return (text.replace("\\", "\\textbackslash{}")
                .replace("&", "\\&").replace("%", "\\%")
                .replace("_", "\\_").replace("#", "\\#")
                .replace("$", "\\$").replace("{", "\\{").replace("}", "\\}"))


def _table1_tex(df: pd.DataFrame, target: str) -> str:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return "\\textit{no data}"
    pooled = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator"], lens="true_bypass",
    ).set_index("mutator")
    p = rates.set_index(["mutator", "waf"])

    lines = [
        r"\begin{table}[tb]",
        r"\centering",
        r"\caption{True-bypass rate by mutator $\times$ WAF on DVWA. \textit{Our "
        r"pooled} is the rate over the union of WAFs' baseline-triggered datapoints. "
        r"\textit{Paper} is Yusifova~\cite{yusifova2024}.}",
        r"\label{tab:table1}",
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r"mutator & modsec & coraza & shadowd & ours (pooled) & paper & $\Delta$ \\",
        r"\midrule",
    ]
    for mut_disp, mut_raw in zip(_MUT_ORDER, _MUT_RAW):
        cells = []
        for waf in _WAF_ORDER:
            if (mut_raw, waf) in p.index:
                r = p.loc[(mut_raw, waf), "rate"]
                cells.append(f"{r*100:.1f}\\%")
            else:
                cells.append("---")
        if mut_raw in pooled.index:
            pooled_rate = float(pooled.loc[mut_raw, "rate"])
            paper = PAPER_TABLE1[mut_raw]
            delta = pooled_rate - paper
            lines.append(
                f"\\texttt{{{mut_disp}}} & "
                + " & ".join(cells)
                + f" & {pooled_rate*100:.1f}\\% & {paper*100:.1f}\\% & "
                + f"{delta*100:+.1f}pp"
                + r" \\"
            )
        else:
            lines.append(
                f"\\texttt{{{mut_disp}}} & "
                + " & ".join(cells)
                + f" & --- & {PAPER_TABLE1[mut_raw]*100:.1f}\\% & ---"
                + r" \\"
            )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


def _figure_tex(path: Path, stem: str) -> str:
    """Wrap a PNG path in a \\figure{} block. Path is relative to report dir."""
    return (
        "\\begin{figure}[t]\n"
        "\\centering\n"
        f"\\includegraphics[width=\\columnwidth]{{{path.as_posix()}}}\n"
        f"\\caption{{{_esc(stem.replace('_', ' '))}}}\n"
        f"\\label{{fig:{stem}}}\n"
        "\\end{figure}"
    )


def _bibliography_tex() -> str:
    # plain manual bibliography keyed \bibitem{yusifova2024}, \bibitem{crs}, …
    keys = ["yusifova2024", "crs", "coraza", "shadowd", "openappsec", "portswigger"]
    lines = [r"\begin{thebibliography}{9}"]
    for k, entry in zip(keys, BIBLIOGRAPHY):
        lines.append(f"\\bibitem{{{k}}} {_esc(entry)}")
    lines.append(r"\end{thebibliography}")
    return "\n".join(lines)


def render_latex(
    df: pd.DataFrame,
    out_path: Path,
    run_id: str,
    figures: list[Path],
    manifest: dict | None = None,
    anchor_target: str = "dvwa",
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    totals = (manifest or {}).get("totals", {})

    fig_blocks = []
    for p in figures:
        if p.suffix != ".png":
            continue   # prefer PNG for pdflatex
        try:
            rel = p.resolve().relative_to(out_path.parent.resolve())
        except ValueError:
            rel = p
        fig_blocks.append(_figure_tex(rel, p.stem))

    mutators_str = _esc(", ".join((manifest or {}).get("mutators", [])))
    classes_str = _esc(", ".join((manifest or {}).get("classes", [])))
    datapoints = totals.get("datapoints", len(df))
    run_id_esc = _esc(run_id)
    now_esc = _esc(now)
    table1 = _table1_tex(df, anchor_target)
    figures_block = "\n".join(fig_blocks) if fig_blocks else r"\textit{No figures produced for this run.}"
    bib = _bibliography_tex()

    body = (
        "\\documentclass[conference]{IEEEtran}\n"
        "\\usepackage[utf8]{inputenc}\n"
        "\\usepackage{graphicx}\n"
        "\\usepackage{booktabs}\n"
        "\\usepackage{hyperref}\n"
        "\\usepackage{caption}\n\n"
        "\\title{WAF Evasion Lab --- reproduction of Yusifova (2024)}\n"
        "\\author{%\n"
        "  \\IEEEauthorblockN{Generated by \\texttt{wafeval}}\n"
        "  \\IEEEauthorblockA{Run \\texttt{" + run_id_esc + "} --- " + now_esc + "}\n"
        "}\n\n"
        "\\begin{document}\n"
        "\\maketitle\n\n"
        "\\begin{abstract}\n"
        "This report reproduces the headline results of Yusifova (2024) on a "
        "reproducible lab comprising four open-source WAFs (ModSecurity + CRS v4, "
        "Coraza, Shadow Daemon, open-appsec) fronting three intentionally vulnerable "
        "applications (DVWA, WebGoat, Juice Shop). Payloads from a "
        f"{datapoints}-point corpus are mutated via five obfuscation categories of "
        "increasing complexity and tested through each WAF.\n"
        "\\end{abstract}\n\n"
        "\\section{Methodology}\n"
        f"Run configuration: mutators = \\{{{mutators_str}\\}}, "
        f"classes = \\{{{classes_str}\\}}. True-bypass rates are reported on DVWA only "
        "--- it is the anchor target whose vulnerable sinks dependably consume all "
        "six payload classes. Appendix A of the Markdown companion report lists "
        "WAF-view rates across WebGoat and Juice Shop for comparison.\n\n"
        f"{table1}\n\n"
        "\\section{Figures}\n\n"
        f"{figures_block}\n\n"
        "\\section{Conclusions}\n"
        "See the accompanying \\texttt{report.md} for prose recommendations and "
        "WAF-view appendix. Deltas against Yusifova (2024) are in "
        "Table~\\ref{tab:table1}.\n\n"
        f"{bib}\n\n"
        "\\end{document}\n"
    )
    out_path.write_text(body)
    return out_path
