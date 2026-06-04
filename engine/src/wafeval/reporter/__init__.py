"""Reporter — Markdown + LaTeX report rendering (prompt.md §10).

``render_markdown`` is callable directly; ``render_latex`` produces the
``.tex`` source alongside it but relies on the ``texlive`` sidecar container
(``--profile report``) to produce a PDF. Both variants consume the same
bypass-rate DataFrame computed by ``wafeval.analyzer``.
"""
from wafeval.reporter.markdown import render_markdown
from wafeval.reporter.latex import render_latex
from wafeval.reporter.combined import render_combined_markdown, render_combined_latex
from wafeval.reporter.consolidated import render_consolidated

__all__ = [
    "render_markdown",
    "render_latex",
    "render_combined_markdown",
    "render_combined_latex",
    "render_consolidated",
]
