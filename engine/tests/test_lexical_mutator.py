"""Unit tests for the lexical mutator.

Covers prompt.md §7 requirement that every mutator produce at least 5 variants
per input payload, and that variants remain distinct from the original body.
"""
from __future__ import annotations

import pytest

from wafeval.models import Payload, TriggerContains, VulnClass
from wafeval.mutators.base import REGISTRY
from wafeval.mutators.lexical import LexicalMutator


@pytest.fixture
def sqli_payload() -> Payload:
    return Payload.model_validate({
        "id": "sqli-test-001",
        "class": "sqli",
        "payload": "1' or '1'='1 -- -",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


@pytest.fixture
def xss_payload() -> Payload:
    return Payload.model_validate({
        "id": "xss-test-001",
        "class": "xss",
        "payload": "<script>alert(1)</script>",
        "trigger": {"kind": "reflected", "marker": "<script>alert"},
    })


def test_registered_under_category():
    assert REGISTRY["lexical"] is LexicalMutator


def test_sqli_produces_at_least_5_variants(sqli_payload: Payload):
    variants = LexicalMutator().mutate(sqli_payload)
    assert len(variants) >= 5, f"paper requires >=5 variants, got {len(variants)}"


def test_xss_produces_at_least_5_variants(xss_payload: Payload):
    variants = LexicalMutator().mutate(xss_payload)
    assert len(variants) >= 5


def test_variants_are_distinct_from_original(sqli_payload: Payload):
    variants = LexicalMutator().mutate(sqli_payload)
    for v in variants:
        assert v.body != sqli_payload.payload, (
            f"variant {v.variant!r} identical to source — mutation was a no-op"
        )


def test_variants_inherit_source_id(sqli_payload: Payload):
    variants = LexicalMutator().mutate(sqli_payload)
    assert all(v.source_id == "sqli-test-001" for v in variants)
    assert all(v.mutator == "lexical" for v in variants)
    assert all(v.complexity_rank == 1 for v in variants)


def test_alt_case_variant_actually_alternates(sqli_payload: Payload):
    variants = {v.variant: v for v in LexicalMutator().mutate(sqli_payload)}
    alt = variants["alt_case_keywords"].body
    # "OR" should become "Or" (alt-case starting upper on even index)
    assert "Or" in alt or "oR" in alt, f"alt_case didn't actually alternate: {alt!r}"


def test_upper_keywords_upper(sqli_payload: Payload):
    variants = {v.variant: v for v in LexicalMutator().mutate(sqli_payload)}
    assert " OR " in variants["upper_keywords"].body


def test_inline_comments_only_for_sqli(sqli_payload: Payload, xss_payload: Payload):
    sqli_tags = {v.variant for v in LexicalMutator().mutate(sqli_payload)}
    xss_tags = {v.variant for v in LexicalMutator().mutate(xss_payload)}
    assert "inline_comments" in sqli_tags
    assert "inline_comments" not in xss_tags
    assert "html_whitespace" in xss_tags


def test_whitespace_inflate_preserves_tokens(sqli_payload: Payload):
    variants = {v.variant: v for v in LexicalMutator().mutate(sqli_payload)}
    inflated = variants["whitespace_inflate"].body
    # All non-whitespace tokens from the original must still appear in order.
    original_tokens = sqli_payload.payload.split()
    pos = 0
    for tok in original_tokens:
        pos = inflated.find(tok, pos)
        assert pos != -1, f"token {tok!r} lost after whitespace_inflate"
        pos += len(tok)


def test_duplicate_registration_rejected():
    from wafeval.mutators.base import Mutator, register

    class _Dup(Mutator):
        category = "lexical"
        complexity_rank = 1

        def mutate(self, payload):  # pragma: no cover — never invoked
            return []

    with pytest.raises(ValueError, match="already registered"):
        register(_Dup)


def test_destructive_payload_rejected():
    with pytest.raises(Exception):  # pydantic wraps the ValueError
        Payload.model_validate({
            "id": "x",
            "class": "sqli",
            "payload": "1'; DROP TABLE users -- -",
            "trigger": {"kind": "contains", "needle": "x"},
        })
