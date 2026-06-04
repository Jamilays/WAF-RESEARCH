"""FastAPI app factory — read-only dashboard backend.

All endpoints read from the bind-mounted ``results/`` tree; nothing here
spawns engine runs. Mutating state is the engine/reporter's job — keeping
this surface strictly read-only means the dashboard container can run
unprivileged and be restarted without interrupting a run in progress.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from wafeval import __version__
from wafeval.api import store


def _paths() -> dict[str, Path]:
    return {
        "raw":       Path(os.environ.get("RESULTS_RAW_DIR",       "results/raw")),
        "processed": Path(os.environ.get("RESULTS_PROCESSED_DIR", "results/processed")),
        "figures":   Path(os.environ.get("RESULTS_FIGURES_DIR",   "results/figures")),
        "reports":   Path(os.environ.get("RESULTS_REPORTS_DIR",   "results/reports")),
    }


def build_app() -> FastAPI:
    app = FastAPI(
        title="wafeval dashboard API",
        version=__version__,
        description="Read-only views over results/raw for the React dashboard.",
    )
    # CORS — dashboard served on :3000, API on :8001. Loopback-only in compose,
    # so we allow every origin (there's no sensitive state to protect).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        p = _paths()
        return {
            "status": "ok",
            "version": __version__,
            "results_raw_exists": p["raw"].is_dir(),
        }

    # ---- runs --------------------------------------------------------------

    @app.get("/runs")
    def list_runs() -> list[dict[str, Any]]:
        p = _paths()
        return store.list_runs(p["raw"])

    @app.get("/runs/latest")
    def latest_run() -> dict[str, Any]:
        p = _paths()
        run_id = store.latest_run_id(p["raw"])
        if run_id is None:
            raise HTTPException(404, "no runs under results/raw")
        return store.run_manifest(p["raw"], run_id)

    @app.get("/runs/compare")
    def compare_runs(a: str = Query(...), b: str = Query(...)) -> dict[str, Any]:
        p = _paths()
        return store.compare_runs(p["raw"], a, b)

    @app.get("/runs/combined")
    def combined_runs(ids: str = Query(..., description="comma-separated run_ids; later ids override earlier on WAF overlap")) -> dict[str, Any]:
        """Merge N runs and return cross-run bypass rates + WAF provenance.

        Enables the dashboard to surface the 4-WAF headline table without
        the user eyeballing three separate run views. Ordering semantics
        match ``wafeval report-combined``: last-in-list wins on overlap.
        """
        p = _paths()
        run_ids = [r.strip() for r in ids.split(",") if r.strip()]
        if not run_ids:
            raise HTTPException(400, "ids query parameter must contain at least one run_id")
        return store.run_combined(p["raw"], run_ids)

    @app.get("/runs/{run_id}")
    def run_manifest(run_id: str) -> dict[str, Any]:
        p = _paths()
        return store.run_manifest(p["raw"], run_id)

    @app.get("/runs/{run_id}/live")
    def run_live(run_id: str, tail: int = Query(20, ge=1, le=200)) -> dict[str, Any]:
        """Live progress — re-scans the raw dir; call on a poll."""
        p = _paths()
        return store.run_live(p["raw"], run_id, tail=tail)

    @app.get("/runs/{run_id}/bypass-rates")
    def bypass_rates(run_id: str) -> list[dict[str, Any]]:
        p = _paths()
        return store.run_bypass_rates(p["raw"], run_id)

    @app.get("/runs/{run_id}/per-payload")
    def per_payload(run_id: str) -> list[dict[str, Any]]:
        p = _paths()
        return store.run_per_payload(p["raw"], run_id)

    @app.get("/runs/{run_id}/hall-of-fame")
    def hall_of_fame_endpoint(run_id: str, top_n: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
        """Top-N payload variants ranked by (WAF × target) cells they bypassed.

        Denominator counts only baseline-confirmed cells (a variant that
        baseline_fails everywhere doesn't appear in the ranking).
        """
        p = _paths()
        return store.run_hall_of_fame(p["raw"], run_id, top_n=top_n)

    @app.get("/runs/{run_id}/per-variant")
    def per_variant(
        run_id: str,
        waf: str | None = None,
        target: str | None = None,
        vuln_class: str | None = None,
        mutator: str | None = None,
        verdict: str | None = None,
        limit: int = Query(200, ge=1, le=5000),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        p = _paths()
        return store.run_per_variant(
            p["raw"], run_id,
            filters={
                "waf": waf, "target": target,
                "vuln_class": vuln_class, "mutator": mutator,
                "verdict": verdict,
            },
            limit=limit, offset=offset,
        )

    @app.get("/runs/{run_id}/records/{waf}/{target}/{payload_id}/{variant}")
    def record_detail(run_id: str, waf: str, target: str, payload_id: str, variant: str) -> dict[str, Any]:
        p = _paths()
        path = p["raw"] / run_id / waf / target / f"{payload_id}__{variant}.json"
        if not path.is_file():
            raise HTTPException(404, f"record not found: {path.name}")
        return json.loads(path.read_text())

    @app.get("/runs/{run_id}/figures")
    def figure_list(run_id: str) -> list[str]:
        p = _paths()
        fdir = p["figures"] / run_id
        if not fdir.is_dir():
            return []
        return sorted(f.name for f in fdir.iterdir() if f.is_file())

    @app.get("/runs/{run_id}/figures/{filename}")
    def figure_file(run_id: str, filename: str):
        p = _paths()
        # Guard against path traversal — filename must be a plain basename.
        if "/" in filename or ".." in filename:
            raise HTTPException(400, "invalid filename")
        path = p["figures"] / run_id / filename
        if not path.is_file():
            raise HTTPException(404, "figure not found")
        return FileResponse(path)

    @app.get("/runs/{run_id}/report")
    def report_md(run_id: str) -> JSONResponse:
        p = _paths()
        md = p["reports"] / run_id / "report.md"
        if not md.is_file():
            raise HTTPException(404, "report.md not yet generated for this run")
        return JSONResponse({"run_id": run_id, "markdown": md.read_text()})

    return app
