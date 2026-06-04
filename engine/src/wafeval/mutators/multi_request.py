"""Multi-request obfuscation mutator.

Implements prompt.md §7(5) — split a single-shot exploit across N sequential
requests that share session/cookie state. Paper complexity rank 5; baseline
bypass rate ≈80%. The architectural insight: stateless per-request WAFs have
no way to aggregate signal across a session, so splitting a payload across
several "individually benign" requests defeats rule-based inspection.

Each variant emits a list of ``RequestStep``s. The runner replays them in
order with a shared cookie jar and evaluates the verdict against the *last*
step's response.

Safety: multi-request variants MUST NOT carry destructive payloads. We audit
every step's rendered string against the same destructive-pattern list the
``Payload`` loader uses (prompt.md §13).

Variant families
----------------
- split_halves:       two GETs, first half + second half of the payload
- split_thirds:       three GETs, thirds of the payload
- preamble_then_body: one "warm up" GET that sets a session cookie, then the
                      full payload GET
- cookie_first:       set the payload in a cookie via a first GET, then send
                      an empty query — WAFs often skip cookie re-inspection
                      on the next request
- header_then_query:  first GET carries the payload in ``X-Search``; second
                      GET re-sends it in ``q=`` (harder for per-request rules)
- chunked_token:      three GETs each carry a token that a stateless WAF sees
                      as harmless; final assembly happens server-side only
                      conceptually — for the engine's purposes this still
                      tests the WAF's aggregation blindness.
"""
from __future__ import annotations

from urllib.parse import quote

from wafeval.models import MutatedPayload, Payload, RequestStep
from wafeval.models import DESTRUCTIVE_PATTERNS
from wafeval.mutators.base import Mutator, register


_HEADER_FORBIDDEN = "\r\n\0\t"


def _header_safe(body: str) -> str:
    """Percent-encode chars HTTP header values can't legally carry.

    Also strips non-ASCII — RFC 9110 field-values are ASCII-only, and
    httpx/h11 raises before sending otherwise. Unicode-escape SQLi
    payloads (e.g. fullwidth apostrophe) that land in a header via
    ``_cookie_first`` / ``_header_then_query`` would have crashed the
    request; post-fix they reach the WAF as percent-encoded bytes.
    """
    needs_encode = any(c in body for c in _HEADER_FORBIDDEN) or any(
        ord(c) < 0x20 or ord(c) > 0x7e for c in body
    )
    if not needs_encode:
        return body
    return quote(body, safe="!@#$&*()-_=+[]{}|;:',.<>?/\\~`^")


def _assert_safe(steps: list[RequestStep]) -> None:
    """Reject any step body containing destructive patterns."""
    for step in steps:
        rendered = " ".join([
            *(v for v in step.query.values()),
            *(v for v in step.form.values()),
            *(v for v in step.headers.values()),
            step.raw_body or "",
            str(step.json_body or ""),
            *(c for _, c in step.file_fields.values()),
        ]).lower()
        for pat in DESTRUCTIVE_PATTERNS:
            if pat in rendered:
                raise ValueError(
                    f"multi_request variant rejected: destructive pattern {pat!r}"
                )


def _split_halves(body: str) -> list[RequestStep]:
    mid = max(1, len(body) // 2)
    return [
        RequestStep(method="GET", query={"q": body[:mid]}),
        RequestStep(method="GET", query={"q": body[mid:]}),
    ]


def _split_thirds(body: str) -> list[RequestStep]:
    n = len(body)
    if n < 3:
        return _split_halves(body)
    a, b = n // 3, 2 * n // 3
    return [
        RequestStep(method="GET", query={"q": body[:a]}),
        RequestStep(method="GET", query={"q": body[a:b]}),
        RequestStep(method="GET", query={"q": body[b:]}),
    ]


def _preamble_then_body(body: str) -> list[RequestStep]:
    return [
        RequestStep(method="GET", query={"q": "warmup"}),
        RequestStep(method="GET", query={"q": body}),
    ]


def _cookie_first(body: str) -> list[RequestStep]:
    return [
        RequestStep(method="GET", headers={"Cookie": f"search={_header_safe(body)}"}),
        RequestStep(method="GET", query={"q": "follow-up"}),
    ]


def _header_then_query(body: str) -> list[RequestStep]:
    return [
        RequestStep(method="GET", headers={"X-Search": _header_safe(body)}),
        RequestStep(method="GET", query={"q": body}),
    ]


def _chunked_token(body: str) -> list[RequestStep]:
    tokens = [body[i::3] for i in range(3)]  # interleaved thirds
    return [RequestStep(method="GET", query={"q": tok}) for tok in tokens]


@register
class MultiRequestMutator(Mutator):
    category = "multi_request"
    complexity_rank = 5

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        body = payload.payload

        families: list[tuple[str, list[RequestStep]]] = [
            ("split_halves",        _split_halves(body)),
            ("split_thirds",        _split_thirds(body)),
            ("preamble_then_body",  _preamble_then_body(body)),
            ("cookie_first",        _cookie_first(body)),
            ("header_then_query",   _header_then_query(body)),
            ("chunked_token",       _chunked_token(body)),
        ]

        out: list[MutatedPayload] = []
        for tag, steps in families:
            _assert_safe(steps)   # prompt.md §13 re-check
            out.append(MutatedPayload(
                source_id=payload.id,
                variant=tag,
                mutator=self.category,
                complexity_rank=self.complexity_rank,
                body=body,
                request_overrides=steps,
                notes=f"{len(steps)}-step sequence; shared cookie jar",
            ))
        return out
