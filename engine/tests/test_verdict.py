"""Verdict-classifier unit tests.

Covers every branch: error, baseline_fail (incl. redirects and stripped
payloads), blocked, allowed, flagged, plus the any_of composite trigger.
"""
from __future__ import annotations

import pytest

from wafeval.models import Payload, RouteResult, Verdict
from wafeval.runner.verdict import classify


@pytest.fixture
def payload() -> Payload:
    return Payload.model_validate({
        "id": "p1", "class": "sqli",
        "payload": "1' or '1'='1 -- -",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


@pytest.fixture
def any_of_payload() -> Payload:
    return Payload.model_validate({
        "id": "p2", "class": "sqli",
        "payload": "' UNION SELECT 1 -- -",
        "trigger": {
            "kind": "any_of",
            "any_of": [
                {"kind": "contains", "needle": "First name"},
                {"kind": "regex", "pattern": "SQLITE_ERROR|syntax error"},
            ],
        },
    })


def _rr(route: str, status: int | None, body: str = "", *, error: str | None = None, notes: str | None = None) -> RouteResult:
    return RouteResult(
        route=route, status_code=status,
        response_ms=1.0 if status else None,
        response_bytes=len(body) if status else None,
        response_snippet=body if status else None,
        error=error, notes=notes,
    )


def test_blocked_on_403(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 403, "403 Forbidden")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED


def test_allowed_when_baseline_triggered(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 200, "First name: admin")
    assert classify(payload, baseline, waf) is Verdict.ALLOWED


def test_baseline_fail_suppresses_bypass_claim(payload):
    baseline = _rr("baseline-dvwa.local", 200, "no rows")
    waf = _rr("coraza-dvwa.local", 200, "no rows")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_baseline_fail_even_when_waf_blocks(payload):
    """WAF 403 w/ baseline that didn't fire → BASELINE_FAIL, not BLOCKED.

    Previously this was (falsely) classified BLOCKED and inflated the
    denominator vs. WAFs that didn't block. Post-Bundle-2 the baseline
    check gates every other verdict.
    """
    baseline = _rr("baseline-dvwa.local", 200, "no rows")
    waf = _rr("modsec-dvwa.local", 403, "403 Forbidden")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_302_redirect_is_baseline_fail_not_allowed(payload):
    """3xx means the app never reached the sink — can't call it a bypass."""
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("coraza-dvwa.local", 302, "")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_waf_2xx_without_marker_is_blocked_silent(payload):
    """WAF returned 200 but the trigger marker is absent — payload stripped/transformed.

    Silent sanitise pattern: open-appsec, Cloudflare Ruleset Engine, and
    modern CRS plugins sometimes pass the request but rewrite the query so
    the exploit never lands. Distinct verdict from ``BLOCKED`` (hard 403)
    because from the client's perspective the WAF is invisible.
    """
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("coraza-dvwa.local", 200, "ID: 1<br/>no rows returned")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED_SILENT


def test_flagged_on_block_marker_in_2xx(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    # Marker present (exploit landed) AND WAF sentinel body present.
    waf = _rr("shadowd-dvwa.local", 200, "First name: admin — Request blocked by Shadow Daemon observer")
    assert classify(payload, baseline, waf) is Verdict.FLAGGED


def test_error_on_network_failure(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", None, error="ConnectError('timeout')")
    assert classify(payload, baseline, waf) is Verdict.ERROR


def test_blocked_on_5xx_with_waf_marker(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 500, "ModSecurity: Access denied")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED


def test_any_of_trigger_dvwa_marker(any_of_payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("shadowd-dvwa.local", 200, "First name: admin")
    assert classify(any_of_payload, baseline, waf) is Verdict.ALLOWED


def test_any_of_trigger_juiceshop_error(any_of_payload):
    """Juice Shop 500 + SQLITE_ERROR is a successful SQLi bypass."""
    baseline = _rr("baseline-juiceshop.local", 500, "Error: SQLITE_ERROR: near UNION")
    waf = _rr("coraza-juiceshop.local", 500, "Error: SQLITE_ERROR: near UNION")
    assert classify(any_of_payload, baseline, waf) is Verdict.ALLOWED


def test_5xx_without_marker_is_baseline_fail(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("coraza-dvwa.local", 500, "something went wrong — not a WAF signature")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_trigger_override_supersedes_payload_trigger(payload):
    """Per-endpoint trigger (e.g. WebGoat JSON marker) wins over payload.trigger.

    ``payload`` fixture's trigger is ``contains "First name"``. Without the
    override, a WebGoat baseline wouldn't match and everything would collapse
    to BASELINE_FAIL. With the override set to the WebGoat JSON field, the
    exact same responses classify as ALLOWED.
    """
    from wafeval.models import TriggerRegex
    override = TriggerRegex(pattern=r'"attemptWasMade"\s*:\s*true')
    wg_body = '{"lessonCompleted" : false, "attemptWasMade" : true}'
    baseline = _rr("baseline-webgoat.local", 200, wg_body)
    waf = _rr("modsec-webgoat.local", 200, wg_body)

    # Without override: baseline body has no "First name" → baseline_fail.
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL
    # With override: WebGoat JSON marker matches → allowed.
    assert classify(payload, baseline, waf, trigger_override=override) is Verdict.ALLOWED


def test_trigger_override_still_blocks_on_403(payload):
    """Override only changes the marker — the block signature (403) still wins."""
    from wafeval.models import TriggerRegex
    override = TriggerRegex(pattern=r'"attemptWasMade"\s*:\s*true')
    baseline = _rr("baseline-webgoat.local", 200, '{"attemptWasMade" : true}')
    waf = _rr("modsec-webgoat.local", 403, "403 Forbidden")
    assert classify(payload, baseline, waf, trigger_override=override) is Verdict.BLOCKED
