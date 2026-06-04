"""Unit tests for the four new mutators shipped in Phase 4.

Each mutator is verified to:
  - Register under its category key
  - Produce >=5 variants per input payload (paper requirement, prompt.md §7)
  - Either mutate the body (lexical/encoding/structural) OR populate
    request_overrides (context_displacement/multi_request)
  - Reject destructive content in multi_request sequences
"""
from __future__ import annotations

import urllib.parse

import pytest

from wafeval.models import Payload
from wafeval.mutators.base import REGISTRY
from wafeval.mutators.context_displacement import ContextDisplacementMutator
from wafeval.mutators.encoding import EncodingMutator
from wafeval.mutators.multi_request import MultiRequestMutator
from wafeval.mutators.structural import StructuralMutator


@pytest.fixture
def sqli() -> Payload:
    return Payload.model_validate({
        "id": "s1", "class": "sqli",
        "payload": "1' or 'a'='a -- -",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


@pytest.fixture
def xss() -> Payload:
    return Payload.model_validate({
        "id": "x1", "class": "xss",
        "payload": "<svg onload=alert(1)>",
        "trigger": {"kind": "reflected", "marker": "onload=alert"},
    })


# ---------- registration -----------------------------------------------------


@pytest.mark.parametrize("cat,cls", [
    ("encoding", EncodingMutator),
    ("structural", StructuralMutator),
    ("context_displacement", ContextDisplacementMutator),
    ("multi_request", MultiRequestMutator),
])
def test_registered(cat: str, cls: type):
    assert REGISTRY[cat] is cls


def test_five_mutators_total():
    # lexical + four new = five, matching prompt.md §7.
    assert set(REGISTRY.keys()) >= {
        "lexical", "encoding", "structural",
        "context_displacement", "multi_request",
    }


# ---------- variant counts --------------------------------------------------


@pytest.mark.parametrize("cls", [EncodingMutator, StructuralMutator,
                                 ContextDisplacementMutator, MultiRequestMutator])
def test_sqli_at_least_5_variants(cls, sqli):
    vs = cls().mutate(sqli)
    assert len(vs) >= 5, f"{cls.__name__} produced only {len(vs)} variants on SQLi"


@pytest.mark.parametrize("cls", [EncodingMutator, StructuralMutator,
                                 ContextDisplacementMutator, MultiRequestMutator])
def test_xss_at_least_5_variants(cls, xss):
    vs = cls().mutate(xss)
    assert len(vs) >= 5, f"{cls.__name__} produced only {len(vs)} variants on XSS"


# ---------- encoding round-trip ---------------------------------------------


def test_encoding_url_single_roundtrips(sqli):
    vs = {v.variant: v.body for v in EncodingMutator().mutate(sqli)}
    assert urllib.parse.unquote(vs["url_single"]) == sqli.payload


def test_encoding_url_double_needs_two_passes(sqli):
    vs = {v.variant: v.body for v in EncodingMutator().mutate(sqli)}
    once = urllib.parse.unquote(vs["url_double"])
    twice = urllib.parse.unquote(once)
    assert twice == sqli.payload
    assert once != sqli.payload  # one pass shouldn't be enough


def test_encoding_variants_differ_from_original(sqli):
    for v in EncodingMutator().mutate(sqli):
        assert v.body != sqli.payload, f"{v.variant} was a no-op"


# ---------- structural ------------------------------------------------------


def test_structural_sqli_rewrites_keywords():
    p = Payload.model_validate({
        "id": "s", "class": "sqli",
        "payload": "SELECT user FROM accounts",
        "trigger": {"kind": "contains", "needle": "a"},
    })
    vs = {v.variant: v.body for v in StructuralMutator().mutate(p)}
    assert "CONCAT" in vs["concat_keywords"]
    assert "SELECT" not in vs["concat_keywords"]  # keyword fully rewritten


def test_structural_xss_uses_js_tricks(xss):
    vs = {v.variant: v.body for v in StructuralMutator().mutate(xss)}
    assert "String.fromCharCode" in vs["fromcharcode_svg"]
    assert "atob" in vs["atob_eval_img"]


# ---------- context displacement --------------------------------------------


def test_context_displacement_populates_overrides(sqli):
    vs = ContextDisplacementMutator().mutate(sqli)
    for v in vs:
        assert v.request_overrides is not None and len(v.request_overrides) == 1
        assert v.body == sqli.payload  # canonical preserved


def test_context_displacement_slots_cover_methods(sqli):
    tags = {v.variant for v in ContextDisplacementMutator().mutate(sqli)}
    assert {"json_body", "xml_body", "header_x_search",
            "multipart_upload", "form_urlencoded"} <= tags


def test_context_displacement_json_carries_payload(sqli):
    vs = {v.variant: v for v in ContextDisplacementMutator().mutate(sqli)}
    step = vs["json_body"].request_overrides[0]
    assert step.method == "POST"
    assert step.content_type == "application/json"
    assert sqli.payload in str(step.json_body)


def test_context_displacement_header_variant(sqli):
    vs = {v.variant: v for v in ContextDisplacementMutator().mutate(sqli)}
    step = vs["header_x_search"].request_overrides[0]
    assert step.headers.get("X-Search") == sqli.payload


# ---------- multi_request ---------------------------------------------------


def test_multi_request_uses_sequences(sqli):
    vs = MultiRequestMutator().mutate(sqli)
    for v in vs:
        assert v.request_overrides and len(v.request_overrides) >= 2


def test_multi_request_rejects_destructive():
    destructive = Payload.model_validate.__wrapped__ if False else None  # no-op; see below
    # Validator blocks at Payload load time, so we simulate by hand: craft a
    # Payload via construct() (bypasses validator) and confirm the mutator's
    # step-level safety re-check fires.
    p = Payload.model_construct(
        id="bad", vuln_class="sqli",
        payload="select; DROP TABLE users",
        trigger={"kind": "contains", "needle": "x"},
    )
    with pytest.raises(ValueError, match="destructive"):
        MultiRequestMutator().mutate(p)


def test_multi_request_split_halves_reassembles(sqli):
    vs = {v.variant: v for v in MultiRequestMutator().mutate(sqli)}
    parts = [s.query["q"] for s in vs["split_halves"].request_overrides]
    assert "".join(parts) == sqli.payload


def test_multi_request_chunked_token_distributes_body(sqli):
    vs = {v.variant: v for v in MultiRequestMutator().mutate(sqli)}
    seq = vs["chunked_token"].request_overrides
    combined_chars = sorted("".join(s.query["q"] for s in seq))
    assert combined_chars == sorted(sqli.payload)
