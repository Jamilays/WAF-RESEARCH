"""Context-displacement mutator — moves the payload into a different request slot.

Implements prompt.md §7(4): relocate a payload from a URL query parameter into
a JSON body, XML body, custom HTTP header, or multipart field. Paper complexity
rank 4; baseline bypass rate ≈62%. The theory: WAFs inspect well-known sinks
(query strings, form bodies) more aggressively than unusual transport slots.

Each variant emits a single ``RequestStep`` override that the runner replays
in place of the default endpoint template. The original ``body`` string is
preserved verbatim for corpus/analyzer accounting.
"""
from __future__ import annotations

from urllib.parse import quote

from wafeval.models import MutatedPayload, Payload, RequestStep, VulnClass
from wafeval.mutators.base import Mutator, register


# HTTP field-values (RFC 9110 §5.5) forbid raw CR/LF/NUL/control chars.
# Percent-encoding is the closest semantic neighbour — the server that
# URL-decodes headers (some do, some don't) still sees the attack shape.
_HEADER_FORBIDDEN = "\r\n\0\t"


def _header_safe(body: str) -> str:
    """Percent-encode characters HTTP header values can't legally carry.

    RFC 9110 field-values are restricted to printable US-ASCII + SP/HTAB.
    Anything else (CR/LF/NUL, tabs, non-ASCII) trips httpx/h11's validation.
    We conservatively URL-encode the value whenever it contains either a
    forbidden control char *or* any byte outside 0x20..0x7e — that way
    Unicode-quote SQLi variants, tabs, CRLF payloads etc. all survive the
    transport layer while still carrying the attack bytes to the WAF (which
    URL-decodes headers before inspection in most configs).
    """
    needs_encode = any(c in body for c in _HEADER_FORBIDDEN) or any(
        ord(c) < 0x20 or ord(c) > 0x7e for c in body
    )
    if not needs_encode:
        return body
    return quote(body, safe="!@#$&*()-_=+[]{}|;:',.<>?/\\~`^")


def _json_body(body: str) -> RequestStep:
    return RequestStep(
        method="POST",
        json_body={"q": body, "search": body},
        content_type="application/json",
    )


def _xml_body(body: str) -> RequestStep:
    # Use XML-safe escapes. Keep the payload in a CDATA section so the XML
    # parser doesn't choke on angle-brackets from XSS payloads.
    xml = (
        '<?xml version="1.0"?>\n'
        f'<req><search><![CDATA[{body.replace("]]>", "]]]]><![CDATA[>")}]]></search></req>'
    )
    return RequestStep(
        method="POST",
        raw_body=xml,
        content_type="application/xml",
    )


def _header_injection(body: str, header_name: str = "X-Search") -> RequestStep:
    # Many WAF setups inspect ``Host``/``User-Agent`` but under-inspect custom
    # X-* headers. Put the payload in X-Search and also echo it in a no-op
    # query param so the endpoint still matches. ``_header_safe`` handles
    # control chars that would otherwise trigger h11's strict field-value
    # check before the request ever left the process.
    return RequestStep(
        method="GET",
        headers={header_name: _header_safe(body)},
        query={"q": "ok"},
    )


def _multipart(body: str) -> RequestStep:
    return RequestStep(
        method="POST",
        file_fields={
            "file": ("payload.txt", body),
            "q":    ("", body),
        },
    )


def _cookie_stuffing(body: str) -> RequestStep:
    # Some WAFs are lax on cookie-value inspection. Cookie header values are
    # field-values too, so the same control-char sanitisation applies.
    return RequestStep(
        method="GET",
        headers={"Cookie": f"search={_header_safe(body)}"},
        query={"q": "ok"},
    )


def _form_urlencoded(body: str) -> RequestStep:
    return RequestStep(
        method="POST",
        form={"q": body, "search": body},
        content_type="application/x-www-form-urlencoded",
    )


@register
class ContextDisplacementMutator(Mutator):
    category = "context_displacement"
    complexity_rank = 4

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        body = payload.payload
        xss_only = payload.vuln_class is VulnClass.XSS

        variants: list[tuple[str, RequestStep]] = [
            ("json_body",            _json_body(body)),
            ("xml_body",             _xml_body(body)),
            ("header_x_search",      _header_injection(body)),
            ("multipart_upload",     _multipart(body)),
            ("form_urlencoded",      _form_urlencoded(body)),
            ("cookie_stuffing",      _cookie_stuffing(body)),
        ]
        if xss_only:
            variants.append(("referer_header",
                             _header_injection(body, "Referer")))

        return [
            MutatedPayload(
                source_id=payload.id,
                variant=tag,
                mutator=self.category,
                complexity_rank=self.complexity_rank,
                body=body,                          # canonical payload preserved
                request_overrides=[step],
                notes=f"payload relocated via {tag}",
            )
            for tag, step in variants
        ]
