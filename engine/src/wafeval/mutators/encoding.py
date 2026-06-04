"""Encoding obfuscation mutator.

Implements prompt.md §7(2) — URL single/double %-encoding, Unicode escapes,
HTML entities, base64 (where applicable), and stacked layers. Paper complexity
rank 2; baseline bypass rate ≈27%.

Variants (≥5):
  1. url_single         — %XX for every ASCII printable
  2. url_double         — %25XX (the WAF normaliser sees %XX, the target sees the original)
  3. unicode_escape     — \\uXXXX for keyword runs (effective for JS-context sinks)
  4. html_entities      — &#NN; decimal entities (effective for HTML/attribute contexts)
  5. url_partial_keywords — %XX only on SQL keywords; leaves quotes alone so the
                           request still parses as a query param. Cheap & often beats naive rules.
  6. stacked            — url_single → html_entities (double-layered obfuscation)
"""
from __future__ import annotations

import base64
import urllib.parse

from wafeval.models import MutatedPayload, Payload, VulnClass
from wafeval.mutators.base import Mutator, register
from wafeval.mutators.lexical import _KEYWORD_RE


def _url_single(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _url_double(text: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")


def _unicode_escape(text: str) -> str:
    # \uXXXX for every char — JS-context sinks often decode this.
    return "".join(f"\\u{ord(c):04x}" for c in text)


def _html_entities(text: str) -> str:
    # Decimal entities: &#65; for 'A'. Works in HTML attribute contexts.
    return "".join(f"&#{ord(c)};" for c in text)


def _percent_every_byte(s: str) -> str:
    return "".join(f"%{b:02x}" for b in s.encode("utf-8"))


def _url_partial_keywords(text: str) -> str:
    # Percent-encode every byte of each keyword — ``quote`` leaves letters alone
    # because they're URL-safe, but we specifically want to defeat rules that
    # literal-match the keyword ``OR`` / ``SELECT`` / etc.
    return _KEYWORD_RE.sub(lambda m: _percent_every_byte(m.group(0)), text)


def _base64_js(text: str) -> str:
    # JS-only: eval(atob('...')) reconstruction. Useful for XSS. We keep the
    # <script> wrapper so the variant is drop-in for a reflected sink.
    b = base64.b64encode(text.encode()).decode()
    return f"<script>eval(atob('{b}'))</script>"


@register
class EncodingMutator(Mutator):
    category = "encoding"
    complexity_rank = 2

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        body = payload.payload
        is_sqli = payload.vuln_class is VulnClass.SQLI
        is_xss = payload.vuln_class is VulnClass.XSS

        variants: list[tuple[str, str]] = [
            ("url_single", _url_single(body)),
            ("url_double", _url_double(body)),
            ("unicode_escape", _unicode_escape(body)),
            ("html_entities", _html_entities(body)),
        ]

        if is_sqli:
            variants.append(("url_partial_keywords", _url_partial_keywords(body)))
        else:
            variants.append(("html_entities_partial",
                             _html_entities("".join(c for c in body if c in "<>/='\""))
                             + "".join(c for c in body if c not in "<>/='\"")))

        # Stacked layers — URL + HTML entities. Double obfuscation at the cost
        # of one more mutation step; paper emphasises this as effective.
        variants.append(("stacked_url_html", _url_single(_html_entities(body))))

        if is_xss:
            variants.append(("base64_js_eval", _base64_js(body)))

        return [
            MutatedPayload(
                source_id=payload.id,
                variant=tag,
                mutator=self.category,
                complexity_rank=self.complexity_rank,
                body=mutated,
            )
            for tag, mutated in variants
        ]
