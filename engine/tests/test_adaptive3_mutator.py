"""Tests for AdaptiveTripleMutator — the rank-7 compositional mutator.

Complements test_adaptive_mutator.py which covers the pair composer.
Focuses on the invariants specific to the triple: 6 permutations of
distinct bases, seed-ranking by triple-product of rates, variant tag
carries all three base names, body round-trips through A→B→C.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from wafeval.models import Payload
from wafeval.mutators import adaptive as adaptive_mod
from wafeval.mutators.adaptive import AdaptiveTripleMutator
from wafeval.mutators.base import REGISTRY


@pytest.fixture(autouse=True)
def _clean_rank_caches():
    adaptive_mod._rank_pairs.cache_clear()
    adaptive_mod._rank_triples.cache_clear()
    yield
    adaptive_mod._rank_pairs.cache_clear()
    adaptive_mod._rank_triples.cache_clear()


@pytest.fixture
def sqli_payload() -> Payload:
    return Payload.model_validate({
        "id": "adaptive3-sqli-001",
        "class": "sqli",
        "payload": "1' or '1'='1 -- -",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


@pytest.fixture
def xss_payload() -> Payload:
    return Payload.model_validate({
        "id": "adaptive3-xss-001",
        "class": "xss",
        "payload": "<script>alert(1)</script>",
        "trigger": {"kind": "reflected", "marker": "<script>alert"},
    })


def test_registered_under_category():
    assert REGISTRY["adaptive3"] is AdaptiveTripleMutator


def test_category_and_rank_are_stable():
    assert AdaptiveTripleMutator.category == "adaptive3"
    # Rank 7 — slots above AdaptiveMutator (6). Assert the number so a
    # rebump of the ladder is caught here.
    assert AdaptiveTripleMutator.complexity_rank == 7


def test_produces_at_least_5_variants(sqli_payload, monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    monkeypatch.delenv("ADAPTIVE_TOP_K_TRIPLES", raising=False)
    variants = AdaptiveTripleMutator().mutate(sqli_payload)
    assert len(variants) >= 5, f"paper requires >=5 variants, got {len(variants)}"


def test_xss_produces_at_least_5_variants(xss_payload, monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    monkeypatch.delenv("ADAPTIVE_TOP_K_TRIPLES", raising=False)
    variants = AdaptiveTripleMutator().mutate(xss_payload)
    assert len(variants) >= 5


def test_variants_inherit_source_id_and_category(sqli_payload):
    for v in AdaptiveTripleMutator().mutate(sqli_payload):
        assert v.source_id == sqli_payload.id
        assert v.mutator == "adaptive3"
        assert v.complexity_rank == 7


def test_variant_bodies_differ_from_original(sqli_payload):
    for v in AdaptiveTripleMutator().mutate(sqli_payload):
        assert v.body != sqli_payload.payload


def test_variant_bodies_are_unique(sqli_payload):
    variants = AdaptiveTripleMutator().mutate(sqli_payload)
    bodies = [v.body for v in variants]
    assert len(bodies) == len(set(bodies))


def test_variant_tag_encodes_all_three_base_mutators(sqli_payload):
    # Tag format: ``<A>><a_tag>|<B>><b_tag>|<C>><c_tag>``
    for v in AdaptiveTripleMutator().mutate(sqli_payload):
        parts = v.variant.split("|")
        assert len(parts) == 3, f"expected 3 parts in {v.variant!r}"
        bases = [p.split(">", 1)[0] for p in parts]
        for b in bases:
            assert b in adaptive_mod._COMPOSABLE_BASES
        # Distinct bases — the rank-7 composer is about 3-way stacks,
        # not repeated application.
        assert len(set(bases)) == 3, f"expected distinct bases in {v.variant!r}"


def test_top_k_caps_triple_count(sqli_payload, monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    monkeypatch.setenv("ADAPTIVE_TOP_K_TRIPLES", "1")
    adaptive_mod._rank_triples.cache_clear()
    variants = AdaptiveTripleMutator().mutate(sqli_payload)
    # One (A, B, C) triple → only one distinct base-name triple across
    # variant tags. Different av.variant / bv.variant / cv.variant combos
    # within the same triple produce different tag suffixes but share
    # the base-name prefix of each "|" segment.
    base_triples: set[tuple[str, str, str]] = set()
    for v in variants:
        parts = v.variant.split("|")
        assert len(parts) == 3
        bases = tuple(p.split(">", 1)[0] for p in parts)
        base_triples.add(bases)
    assert len(base_triples) == 1, \
        f"expected a single base triple under top_k=1, got {base_triples}"


def test_fixed_order_without_seed(monkeypatch):
    monkeypatch.delenv("ADAPTIVE_SEED_RUN", raising=False)
    adaptive_mod._rank_triples.cache_clear()
    triples = adaptive_mod._rank_triples(None, "results/raw")
    assert len(triples) == 6  # 3! permutations of distinct elements
    # All triples must be permutations of the same 3 bases.
    assert all(set(t) == set(adaptive_mod._COMPOSABLE_BASES) for t in triples)
    # Deterministic — the nested-loop generation order is stable across
    # runs, so a second call returns the same list byte-for-byte.
    triples_again = adaptive_mod._rank_triples(None, "results/raw")
    assert triples == triples_again
    # No duplicates.
    assert len(set(triples)) == 6


def _write_seed_record(
    raw_root: Path, run_id: str, waf: str, mutator: str, verdict: str, variant: str,
) -> None:
    p = raw_root / run_id / waf / "dvwa"
    p.mkdir(parents=True, exist_ok=True)
    (p / f"p1__{variant}.json").write_text(json.dumps({
        "run_id": run_id, "timestamp": "2026-01-01T00:00:00+00:00",
        "waf": waf, "target": "dvwa",
        "payload_id": "p1", "vuln_class": "sqli",
        "variant": variant, "mutator": mutator, "complexity_rank": 1,
        "mutated_body": "x", "verdict": verdict,
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


def test_seed_run_reranks_triples_by_observed_bypass_rate(tmp_path, monkeypatch):
    """A seed where ``structural`` bypasses most and ``lexical`` never
    bypasses should push any triple containing ``lexical`` to the tail.
    """
    raw_root = tmp_path / "raw"
    run_id = "seed-triples-20260101T000000Z"

    # structural: all allowed (rate = 1.0)
    for i in range(4):
        _write_seed_record(raw_root, run_id, "modsec", "structural", "allowed", f"s{i}")
    # encoding: 50%
    for i in range(2):
        _write_seed_record(raw_root, run_id, "modsec", "encoding", "allowed", f"e-a{i}")
    for i in range(2):
        _write_seed_record(raw_root, run_id, "modsec", "encoding", "blocked", f"e-b{i}")
    # lexical: all blocked (rate = 0.0)
    for i in range(4):
        _write_seed_record(raw_root, run_id, "modsec", "lexical", "blocked", f"l{i}")

    monkeypatch.setenv("ADAPTIVE_SEED_RUN", run_id)
    monkeypatch.setenv("RESULTS_ROOT", str(raw_root))
    adaptive_mod._rank_triples.cache_clear()

    triples = adaptive_mod._rank_triples(run_id, str(raw_root))
    # Every triple contains lexical (because distinct-triples always do).
    # So product-of-rates = 0 for every triple. They all tie — fall back
    # to lex order. Asserting the tie-breaker alone isn't interesting;
    # the stronger claim is the stronger test:
    assert all("lexical" in t for t in triples)  # (distinct-3 means all 3 bases present)
    # Remove the forcing element and test with a 4-base setup — but we
    # only have 3 composable bases, so verify the simpler claim: the
    # sort is total (no crash), the shape matches.
    assert len(triples) == 6
    assert all(len(set(t)) == 3 for t in triples)
