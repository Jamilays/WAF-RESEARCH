"""FastAPI read-only backend for the dashboard (prompt.md §11).

Serves aggregated views of ``results/`` so the React UI can render run lists,
bypass-rate tables, per-variant drill-downs, and a live-run progress panel.
Never mutates state — results are produced by the engine + reporter.
"""
from wafeval.api.app import build_app

__all__ = ["build_app"]
