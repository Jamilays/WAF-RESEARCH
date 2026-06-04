"""Header-safe payload rendering — context_displacement + multi_request.

Locks the Bundle-7 fix: payloads with raw CR/LF/TAB chars must not leak into
header values (h11 would raise LocalProtocolError before the request flew).
"""
from __future__ import annotations

from wafeval.models import Payload
from wafeval.mutators.context_displacement import ContextDisplacementMutator
from wafeval.mutators.multi_request import MultiRequestMutator


def _newline_payload() -> Payload:
    return Payload.model_validate({
        "id": "sqli-nl",
        "class": "sqli",
        "payload": "1'\nOR\n'1'='1",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


def _has_header(step, name: str) -> str | None:
    for k, v in step.headers.items():
        if k.lower() == name.lower():
            return v
    return None


def test_context_displacement_header_no_control_chars():
    for v in ContextDisplacementMutator().mutate(_newline_payload()):
        assert v.request_overrides is not None
        for step in v.request_overrides:
            for val in step.headers.values():
                assert "\n" not in val and "\r" not in val and "\t" not in val, v.variant


def test_multi_request_header_no_control_chars():
    for v in MultiRequestMutator().mutate(_newline_payload()):
        assert v.request_overrides is not None
        for step in v.request_overrides:
            for val in step.headers.values():
                assert "\n" not in val and "\r" not in val and "\t" not in val, v.variant


def test_non_header_slots_keep_raw_payload():
    """Header sanitiser must not leak into JSON / multipart / query slots."""
    variants = ContextDisplacementMutator().mutate(_newline_payload())
    json_variant = next(v for v in variants if v.variant == "json_body")
    step = json_variant.request_overrides[0]
    assert step.json_body == {"q": "1'\nOR\n'1'='1", "search": "1'\nOR\n'1'='1"}
