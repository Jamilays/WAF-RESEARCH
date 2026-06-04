"""Unit tests for the compositional (adaptive) mutator.

The adaptive mutator stacks two base string-body mutators per variant and
optionally re-ranks the (A, B) pairs using past-run bypass data. These
tests cover the contract plus the two hinge behaviours: the fixed
ordering when no seed is provided, and the seed-ranked ordering when
``ADAPTIVE_SEED_RUN`` env var points at a real results-raw directory.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from wafeval.models import Payload
from wafeval.mutators import adaptive as adaptive_mod
from wafeval.mutators.adaptive import AdaptiveMutator
from wafeval.mutators.base import REGISTRY


@pytest.fixture(autouse=True)
def _clean_rank_cache():
    # ``_rank_pairs`` is ``functools.cache``-memoised on (seed_run, results_root).
    # Tests flip env vars between cases; clear so each test sees a fresh lookup.
    adaptive_mod._rank_pairs.cache_clear()
    yield
    adaptive_mod._rank_pairs.cache_clear()


@pytest.fixture
def sqli_payload() -> Payload:
    return Payload.model_validate({
        "id": "adaptive-sqli-001",
        "class": "sqli",
        "payload": "1' or '1'='1 -- -",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


@pytest.fixture
def xss_payload() -> Payload:
    return Payload.model_validate({
        "id": "adaptive-xss-001",
        "class": "xss",
        "payload": "<script>alert(1)</script>",
        "trigger": {"kind": "reflected", "marker": "<script>alert"},
    })


def test_registered_under_category():
    assert REGISTRY["adaptive"] is AdaptiveMutator


def test_category_and_rank_are_stable():
    # The rank landed after the five base mutators (1-5), so the
    # complexity-vs-rate chart x-axis now spans 1..6 — asserting the
    # value here catches an accidental bump that'd mis-plot every run.
    assert AdaptiveMutator.category == "adaptive"
    assert AdaptiveMutator.complexity_rank == 6


def test_produces_at_least_5_variants(sqli_payload: Payload, monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    monkeypatch.delenv("ADAPTIVE_TOP_K", raising=False)
    variants = AdaptiveMutator().mutate(sqli_payload)
    assert len(variants) >= 5, f"paper requires >=5 variants, got {len(variants)}"


def test_xss_produces_at_least_5_variants(xss_payload: Payload, monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    monkeypatch.delenv("ADAPTIVE_TOP_K", raising=False)
    variants = AdaptiveMutator().mutate(xss_payload)
    assert len(variants) >= 5


def test_variants_inherit_source_id_and_category(sqli_payload: Payload):
    for v in AdaptiveMutator().mutate(sqli_payload):
        assert v.source_id == sqli_payload.id
        assert v.mutator == "adaptive"
        assert v.complexity_rank == 6


def test_variant_bodies_differ_from_original(sqli_payload: Payload):
    for v in AdaptiveMutator().mutate(sqli_payload):
        assert v.body != sqli_payload.payload, (
            f"variant {v.variant!r} was a no-op; composition didn't change the body"
        )


def test_variant_bodies_are_unique(sqli_payload: Payload):
    variants = AdaptiveMutator().mutate(sqli_payload)
    bodies = [v.body for v in variants]
    assert len(bodies) == len(set(bodies)), (
        "adaptive mutator emitted duplicate bodies; the dedup path is broken"
    )


def test_variant_tag_encodes_both_base_mutators(sqli_payload: Payload):
    # The tag format is ``<A>><a_tag>|<B>><b_tag>`` so a reader can trace
    # a variant back to the exact pair + sub-variants without rerunning.
    variants = AdaptiveMutator().mutate(sqli_payload)
    for v in variants:
        assert "|" in v.variant
        a_part, b_part = v.variant.split("|", 1)
        assert ">" in a_part and ">" in b_part
        a_base = a_part.split(">", 1)[0]
        b_base = b_part.split(">", 1)[0]
        assert a_base in adaptive_mod._COMPOSABLE_BASES
        assert b_base in adaptive_mod._COMPOSABLE_BASES
        assert a_base != b_base, "identity pair (A == B) should never be emitted"


def test_top_k_caps_pair_count(sqli_payload: Payload, monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    monkeypatch.setenv("ADAPTIVE_TOP_K", "1")
    variants = AdaptiveMutator().mutate(sqli_payload)
    # Only one (A, B) pair → only one distinct A-base prefix in variant tags.
    bases = {v.variant.split(">", 1)[0] for v in variants}
    assert len(bases) == 1, f"expected a single A-base under top_k=1, got {bases}"


def test_fixed_order_without_seed(monkeypatch):
    # Without a seed, the ordering is deterministic cross-product of the
    # three base mutators, skipping identity.
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    adaptive_mod._rank_pairs.cache_clear()
    pairs = adaptive_mod._rank_pairs(None, "results/raw")
    assert pairs == [
        ("lexical", "encoding"),
        ("lexical", "structural"),
        ("encoding", "lexical"),
        ("encoding", "structural"),
        ("structural", "lexical"),
        ("structural", "encoding"),
    ]


def _write_seed_record(
    raw_root: Path,
    run_id: str,
    waf: str,
    mutator: str,
    verdict: str,
    variant: str,
) -> None:
    """Write one VerdictRecord JSON under results/raw/<run_id>/<waf>/dvwa/."""
    p = raw_root / run_id / waf / "dvwa"
    p.mkdir(parents=True, exist_ok=True)
    (p / f"p1__{variant}.json").write_text(json.dumps({
        "run_id": run_id,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "waf": waf,
        "target": "dvwa",
        "payload_id": "p1",
        "vuln_class": "sqli",
        "variant": variant,
        "mutator": mutator,
        "complexity_rank": 1,
        "mutated_body": "irrelevant",
        "verdict": verdict,
        "baseline": {
            "route": "baseline-dvwa.local", "status_code": 200,
            "response_ms": 1.0, "response_bytes": 1,
            "response_snippet": "First name", "error": None, "notes": None,
        },
        "waf_route": {
            "route": f"{waf}-dvwa.local",
            "status_code": 200 if verdict == "allowed" else 403,
            "response_ms": 1.0, "response_bytes": 1,
            "response_snippet": "ok" if verdict == "allowed" else "blocked",
            "error": None, "notes": None,
        },
        "notes": None,
    }))


def test_seed_run_reranks_pairs_by_observed_bypass_rate(
    tmp_path: Path, monkeypatch
):
    """A seed run where ``structural`` bypasses modsec while ``lexical``
    always gets blocked should push ``structural`` to the front of the
    pair ordering (and ``lexical`` to the back)."""
    raw_root = tmp_path / "raw"
    run_id = "seed-20260101T000000Z"

    # structural: 3 allowed, 0 blocked  →  rate 1.0
    for i in range(3):
        _write_seed_record(raw_root, run_id, "modsec", "structural", "allowed", f"s{i}")
    # encoding:   2 allowed, 2 blocked  →  rate 0.5
    for i in range(2):
        _write_seed_record(raw_root, run_id, "modsec", "encoding", "allowed", f"e-a{i}")
    for i in range(2):
        _write_seed_record(raw_root, run_id, "modsec", "encoding", "blocked", f"e-b{i}")
    # lexical:    0 allowed, 3 blocked  →  rate 0.0
    for i in range(3):
        _write_seed_record(raw_root, run_id, "modsec", "lexical", "blocked", f"l{i}")

    monkeypatch.setenv("ADAPTIVE_SEED_RUN", run_id)
    monkeypatch.setenv("RESULTS_ROOT", str(raw_root))
    adaptive_mod._rank_pairs.cache_clear()

    pairs = adaptive_mod._rank_pairs(run_id, str(raw_root))
    # Top pair should be structural∘encoding (in either order; both score
    # 1.0 × 0.5 = 0.5 and the tiebreak is lexicographic → encoding first).
    assert set(pairs[0]) == {"structural", "encoding"}
    # ``lexical`` has rate 0 → every pair containing it scores 0. They
    # should all sit at the tail.
    tail_pairs = pairs[-4:]
    assert all("lexical" in p for p in tail_pairs)
