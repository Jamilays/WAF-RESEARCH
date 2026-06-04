"""Lexical obfuscation mutator.

Implements prompt.md §7(1) — case permutation, whitespace injection, clause
reordering, and inline SQL comments (``/**/``). Per the paper (§Methodology)
this is the lowest-complexity category; baseline bypass rate ≈12%.

Variants produced per input (≥5, per prompt.md §7):
  1. alternating-case keywords (``SeLeCt ... FrOm``)
  2. upper-case keywords only (``SELECT ... FROM``) — catches case-sensitive WAF rules
  3. whitespace-inflated — single spaces → tabs + multiple spaces
  4. inline ``/**/`` between every SQL keyword (SQLi only)
  5. mixed: alt-case + inline comments (stacked cheap obfuscations)

For XSS the comment-insertion step is replaced with HTML whitespace (NBSP,
TAB, NL) between tag tokens, which serves the same "break naive regex" goal.
"""
from __future__ import annotations

import re

from wafeval.models import MutatedPayload, Payload, VulnClass
from wafeval.mutators.base import Mutator, register

# Rough-and-ready SQL keyword list. Doesn't need to be exhaustive — mutators
# over-match rather than miss, and the runner catches incorrect transforms via
# the baseline-trigger check.
_SQL_KEYWORDS = {
    "SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
    "INSERT", "UPDATE", "DELETE", "INTO", "VALUES",
    "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET",
    "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "ON",
    "AS", "NULL", "LIKE", "IN", "IS", "NOT", "CASE",
    "WHEN", "THEN", "ELSE", "END", "IF",
}
_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(sorted(_SQL_KEYWORDS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


def _alt_case(word: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))


def _apply_keywords(text: str, fn) -> str:
    return _KEYWORD_RE.sub(lambda m: fn(m.group(0)), text)


def _inflate_whitespace(text: str) -> str:
    # Single space → tab+space sequence; preserves token boundaries for the
    # WAF parser but trips naive literal-string rules.
    return re.sub(r" +", "\t \t", text)


def _inject_inline_comments(text: str) -> str:
    # ``/**/`` between adjacent SQL keywords.
    return _KEYWORD_RE.sub(lambda m: m.group(0) + "/**/", text)


def _inject_html_whitespace(text: str) -> str:
    # For XSS: squeeze NBSPs into whitespace between tag tokens.
    return re.sub(r" +", "\u00a0\t ", text)


@register
class LexicalMutator(Mutator):
    category = "lexical"
    complexity_rank = 1

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        body = payload.payload
        is_sqli = payload.vuln_class is VulnClass.SQLI

        variants: list[tuple[str, str]] = []  # (variant_tag, mutated_body)

        variants.append(("alt_case_keywords", _apply_keywords(body, _alt_case)))
        variants.append(("upper_keywords", _apply_keywords(body, str.upper)))
        variants.append(("whitespace_inflate", _inflate_whitespace(body)))

        if is_sqli:
            variants.append(("inline_comments", _inject_inline_comments(body)))
            variants.append((
                "alt_case_and_comments",
                _inject_inline_comments(_apply_keywords(body, _alt_case)),
            ))
        else:
            # Non-SQL payload → substitute HTML whitespace tricks for the
            # comment-insertion variants so we still produce ≥5 mutations.
            variants.append(("html_whitespace", _inject_html_whitespace(body)))
            variants.append((
                "alt_case_and_html_ws",
                _inject_html_whitespace(_apply_keywords(body, _alt_case)),
            ))

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
