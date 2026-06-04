"""Unit tests for _capture_waf_headers — the WAF-fingerprint header extractor.

This is the visible-in-dashboard half of TODO.md #2: headers the WAF
stamps on every response (``x-shadowd-threats``, ``x-waflab-waf``, etc.)
used to be captured as names-only in ``RouteResult.notes``. The values
carried the actual "why blocked" signal (threat class, rule family),
and were dropped on the floor. This suite locks the new name+value
capture against the three real emitters the lab ships — coraza-proxy,
shadowd-proxy, openappsec — plus a negative case so generic ``x-*``
noise doesn't leak in.
"""
from __future__ import annotations

import httpx

from wafeval.runner.engine import _capture_waf_headers


def _h(pairs: list[tuple[str, str]]) -> httpx.Headers:
    return httpx.Headers(pairs)


def test_captures_shadowd_threat_header():
    headers = _h([
        ("Content-Type", "text/plain"),
        ("X-Shadowd-Verdict", "shadowd:status=5"),
        ("X-Shadowd-Threats", "sqli,xss"),
        ("X-Waflab-Waf", "shadowdaemon"),
    ])
    names, values = _capture_waf_headers(headers)
    assert set(names) == {"x-shadowd-verdict", "x-shadowd-threats", "x-waflab-waf"}
    assert values["x-shadowd-threats"] == "sqli,xss"
    assert values["x-waflab-waf"] == "shadowdaemon"


def test_captures_coraza_status():
    # Coraza-proxy's WrapHandler stamps x-coraza-status on blocks.
    headers = _h([("X-Coraza-Status", "403 Forbidden"), ("X-Waflab-Waf", "coraza")])
    names, values = _capture_waf_headers(headers)
    assert set(names) == {"x-coraza-status", "x-waflab-waf"}
    assert values["x-coraza-status"] == "403 Forbidden"


def test_captures_modsec_interrupt():
    # Aspirational — the upstream image doesn't emit this today, but the
    # name filter already keeps space for it.
    headers = _h([("X-ModSec-Interrupted", "1"), ("Server", "nginx")])
    names, values = _capture_waf_headers(headers)
    assert names == ["x-modsec-interrupted"]
    assert values == {"x-modsec-interrupted": "1"}


def test_ignores_generic_x_headers():
    # Don't hoover up the whole security-headers soup just because it
    # starts with x-.
    headers = _h([
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-XSS-Protection", "1; mode=block"),
    ])
    names, values = _capture_waf_headers(headers)
    assert names == []
    assert values == {}


def test_case_insensitive_tag_match():
    # httpx lowercases header names on access; still, the filter must match
    # regardless of how the upstream server cased them.
    headers = _h([("X-CoRaZa-Status", "blocked")])
    names, values = _capture_waf_headers(headers)
    assert names == ["x-coraza-status"]
    assert values["x-coraza-status"] == "blocked"


def test_empty_headers_returns_empty_pair():
    names, values = _capture_waf_headers(_h([]))
    assert names == []
    assert values == {}


def test_values_reflect_curated_allowlist_only():
    # Baseline responses (no WAF in front) have nothing on the allowlist.
    # The returned dict should be empty — so a downstream consumer can key
    # "is this a WAF-decorated response?" off ``bool(waf_headers)``.
    headers = _h([
        ("Content-Type", "text/html; charset=UTF-8"),
        ("Server", "nginx/1.27.0"),
        ("Set-Cookie", "PHPSESSID=abc; Path=/"),
    ])
    names, values = _capture_waf_headers(headers)
    assert values == {}
