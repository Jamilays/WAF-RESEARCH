"""Unit tests for the noop (identity) mutator.

The noop mutator intentionally doesn't hit the paper's "≥5 variants per
input" bar — it emits the payload verbatim for benign-corpus runs so the
FPR measurement isn't polluted by case-permutation or encoding noise.
Tests cover the full contract except that minimum.
"""
from __future__ import annotations

from wafeval.models import Payload
from wafeval.mutators.base import REGISTRY
from wafeval.mutators.noop import NoOpMutator


def _p(body: str) -> Payload:
    return Payload.model_validate({
        "id": "noop-test",
        "class": "benign",
        "payload": body,
        "trigger": {"kind": "status", "code": 200},
    })


def test_registered_under_category():
    assert REGISTRY["noop"] is NoOpMutator


def test_category_and_rank_are_stable():
    assert NoOpMutator.category == "noop"
    # Rank 0 keeps it out of the 1..5 attack-mutator scale and off the
    # complexity-vs-rate chart (which does range(1, 7)).
    assert NoOpMutator.complexity_rank == 0


def test_emits_exactly_one_variant_per_payload():
    variants = NoOpMutator().mutate(_p("apple juice"))
    assert len(variants) == 1


def test_variant_body_is_byte_identical_to_source():
    # The whole point: benign corpus must reach the WAF exactly as the
    # YAML wrote it. A lexical or encoding transform here would conflate
    # FPR-on-realistic with FPR-on-permuted-realistic.
    for body in [
        "apple juice",
        "alice@example.com",
        "café espresso",
        "a \"good\" review",
        "it's a test",
    ]:
        variants = NoOpMutator().mutate(_p(body))
        assert variants[0].body == body


def test_variant_inherits_source_id_and_category():
    p = _p("banana")
    v = NoOpMutator().mutate(p)[0]
    assert v.source_id == p.id
    assert v.mutator == "noop"
    assert v.complexity_rank == 0
    assert v.variant == "identity"
    assert v.request_overrides is None
