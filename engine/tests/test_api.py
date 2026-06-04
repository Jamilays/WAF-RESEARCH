"""API smoke tests — seed a tiny results/raw tree and hit every endpoint."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wafeval.api.app import build_app


def _write_record(base: Path, run_id: str, waf: str, target: str,
                  payload_id: str, variant: str, verdict: str,
                  mutator: str = "lexical", vuln_class: str = "sqli",
                  complexity_rank: int = 1) -> None:
    p = base / run_id / waf / target
    p.mkdir(parents=True, exist_ok=True)
    rec = {
        "run_id": run_id,
        "timestamp": "2026-04-21T00:00:00+00:00",
        "waf": waf,
        "target": target,
        "payload_id": payload_id,
        "vuln_class": vuln_class,
        "variant": variant,
        "mutator": mutator,
        "complexity_rank": complexity_rank,
        "mutated_body": f"{payload_id}::{variant}",
        "verdict": verdict,
        "baseline": {
            "route": f"baseline-{target}.local",
            "status_code": 200, "response_ms": 5.0,
            "response_bytes": 42, "response_snippet": "ok",
            "error": None, "notes": None,
        },
        "waf_route": {
            "route": f"{waf}-{target}.local",
            "status_code": 403 if verdict == "blocked" else 200,
            "response_ms": 7.0,
            "response_bytes": 12, "response_snippet": "",
            "error": None, "notes": None,
        },
        "notes": None,
    }
    (p / f"{payload_id}__{variant}.json").write_text(json.dumps(rec))


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    monkeypatch.setenv("RESULTS_RAW_DIR", str(raw))
    monkeypatch.setenv("RESULTS_PROCESSED_DIR", str(tmp_path / "processed"))
    monkeypatch.setenv("RESULTS_FIGURES_DIR", str(tmp_path / "figures"))
    monkeypatch.setenv("RESULTS_REPORTS_DIR", str(tmp_path / "reports"))
    run_a = "20260420T000000Z_aaaaaaaa"
    run_b = "20260421T000000Z_bbbbbbbb"
    for rid, verdict_modsec in ((run_a, "blocked"), (run_b, "allowed")):
        for target in ("dvwa",):
            _write_record(raw, rid, "baseline", target, "sqli-001", "case_0", "allowed")
            _write_record(raw, rid, "modsec",   target, "sqli-001", "case_0", verdict_modsec)
            _write_record(raw, rid, "coraza",   target, "sqli-001", "case_0", "blocked")
        (raw / rid / "manifest.json").write_text(json.dumps({
            "run_id": rid,
            "started_at": "2026-04-21T00:00:00+00:00",
            "mutators": ["lexical"],
            "classes": ["sqli"],
            "totals": {"datapoints": 3, "allowed": 1, "blocked": 2},
        }))
    # Clear the store mtime cache so fixtures from different tests don't
    # leak across each other.
    from wafeval.api import store
    store._df_cache.clear()
    return {"raw": raw, "runs": [run_a, run_b]}


@pytest.fixture
def client(seeded):
    return TestClient(build_app())


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_runs(client, seeded):
    r = client.get("/runs")
    assert r.status_code == 200
    ids = [row["run_id"] for row in r.json()]
    # newest-first
    assert ids == [seeded["runs"][1], seeded["runs"][0]]


def test_latest_and_manifest(client, seeded):
    r = client.get("/runs/latest")
    assert r.status_code == 200
    assert r.json()["run_id"] == seeded["runs"][1]

    r = client.get(f"/runs/{seeded['runs'][0]}")
    assert r.status_code == 200
    assert r.json()["totals"]["datapoints"] == 3


def test_live(client, seeded):
    r = client.get(f"/runs/{seeded['runs'][1]}/live")
    assert r.status_code == 200
    body = r.json()
    assert body["processed"] == 3
    assert body["histogram"]["blocked"] >= 1
    assert body["recent"]  # not empty


def test_bypass_rates(client, seeded):
    r = client.get(f"/runs/{seeded['runs'][0]}/bypass-rates")
    assert r.status_code == 200
    rows = r.json()
    # true_bypass for dvwa × (modsec, coraza)
    tb = [row for row in rows if row["lens"] == "true_bypass"]
    assert {row["waf"] for row in tb} == {"modsec", "coraza"}
    # Bundle-5: every cell now carries a baseline_fail_rate (0.0 for seeded).
    for row in tb:
        assert "baseline_fail_rate" in row
        assert "n_total" in row


def test_per_variant_and_record(client, seeded):
    r = client.get(f"/runs/{seeded['runs'][1]}/per-variant", params={"waf": "modsec"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["rows"][0]["waf"] == "modsec"

    rec = client.get(
        f"/runs/{seeded['runs'][1]}/records/modsec/dvwa/sqli-001/case_0"
    )
    assert rec.status_code == 200
    assert rec.json()["verdict"] == "allowed"


def test_per_variant_pagination(client, seeded):
    r = client.get(
        f"/runs/{seeded['runs'][0]}/per-variant",
        params={"limit": 1, "offset": 0},
    )
    body = r.json()
    assert body["total"] == 3
    assert len(body["rows"]) == 1


def test_compare_runs(client, seeded):
    a, b = seeded["runs"]
    r = client.get("/runs/compare", params={"a": a, "b": b})
    assert r.status_code == 200
    body = r.json()
    modsec_row = next(row for row in body["rows"] if row["waf"] == "modsec")
    # run_a: modsec blocked → rate 0.0; run_b: modsec allowed → rate 1.0.
    assert modsec_row["rate_a"] == 0.0
    assert modsec_row["rate_b"] == 1.0
    assert modsec_row["delta"] == 1.0


def test_record_404(client, seeded):
    r = client.get(f"/runs/{seeded['runs'][0]}/records/modsec/dvwa/nope/none")
    assert r.status_code == 404


def test_figure_path_traversal_rejected(client, seeded):
    r = client.get(f"/runs/{seeded['runs'][0]}/figures/..%2Fetc%2Fpasswd")
    # fastapi decodes the %2F into '/', which we reject
    assert r.status_code in (400, 404)
