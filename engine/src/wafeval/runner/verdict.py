"""Verdict classifier.

Implements prompt.md §8 verdict rules:
  - blocked: WAF returned 4xx/5xx matching a block signature AND the
             baseline proved the payload would have exploited the app.
  - allowed: 2xx and baseline trigger confirmed → real bypass
  - flagged: 2xx but WAF logged / signaled detection (headers, sentinel body)
  - baseline_fail: baseline didn't confirm vuln — can't claim bypass or block
  - error:   network/timeout/protocol failure

Block signatures are per-WAF. ModSecurity's CRS nginx image returns 403 with
a plain "403 Forbidden" body; Coraza returns 403 with an empty body (blocking
mode, post Bundle 1 fix); shadowd-proxy returns 403 when SHADOWD_ENFORCE=true
(default, post Bundle 1 fix).

Baseline-first ordering: the paper defines a "bypass" as "the exploit works
on the app AND the WAF let it through." Conversely a "block" only counts if
the exploit *would* have worked — otherwise we can't distinguish a WAF that
spotted an attack from an endpoint that wasn't vulnerable anyway. Placing
``baseline_triggered`` before the block-status check makes the denominator
the same across WAFs.
"""
from __future__ import annotations

import re
from typing import Final

from wafeval.models import Payload, RouteResult, Trigger, TriggerContains, TriggerReflected, TriggerRegex, TriggerStatus, Verdict

_BLOCK_STATUS_CODES: Final = frozenset({403, 406, 501})
_FLAG_HEADERS: Final = (
    "x-coraza-status",
    "x-modsec-interrupted",
    "x-shadowd-verdict",
)
_BLOCK_BODY_MARKERS: Final = (
    "mod_security",
    "modsecurity",
    "forbidden by coraza",
    "request denied by coraza",
    "request blocked by shadow",
)


def baseline_triggered(
    payload: Payload,
    baseline: RouteResult,
    trigger_override: Trigger | None = None,
) -> bool:
    """True iff the baseline response proves the vuln fired.

    Returns False on any network-level error. For ``reflected`` triggers the
    marker defaults to the raw payload body when the author didn't supply one.
    ``trigger_override`` supersedes ``payload.trigger`` — used when the target
    endpoint has a response-shape marker that's independent of the payload
    body (e.g. WebGoat's ``"attemptWasMade" : true`` JSON field).
    """
    if baseline.error or baseline.status_code is None or baseline.response_snippet is None:
        return False
    body = baseline.response_snippet

    t = trigger_override or payload.trigger
    return _match_trigger(t, body, baseline.status_code, payload)


def _match_trigger(t, body: str, status_code: int, payload: Payload) -> bool:
    """Dispatch a single trigger against a (body, status) pair."""
    # Late import to avoid a cycle when TriggerAnyOf is introduced downstream.
    from wafeval.models import TriggerAnyOf  # noqa: WPS433

    if isinstance(t, TriggerContains):
        return t.needle in body
    if isinstance(t, TriggerRegex):
        return re.search(t.pattern, body) is not None
    if isinstance(t, TriggerReflected):
        marker = t.marker or payload.payload
        return marker in body
    if isinstance(t, TriggerStatus):
        return status_code == t.code
    if isinstance(t, TriggerAnyOf):
        return any(_match_trigger(sub, body, status_code, payload) for sub in t.any_of)
    raise AssertionError(f"unknown trigger kind: {t!r}")


def classify(
    payload: Payload,
    baseline: RouteResult,
    waf_route: RouteResult,
    trigger_override: Trigger | None = None,
) -> Verdict:
    """Return the verdict for one (payload, waf_route) datapoint.

    Order:
      1. transport errors                          → ERROR
      2. baseline didn't exploit                   → BASELINE_FAIL
      3. WAF returned a block signature            → BLOCKED
      4. WAF 2xx response                          → ALLOWED / FLAGGED
      5. anything else (3xx without redirect, 4xx
         that isn't a block code, unknown status)  → BASELINE_FAIL

    (5) collapses 3xx redirects (auth-wall, Location=/login, etc) to
    BASELINE_FAIL because the payload never reached the app sink. Previously
    3xx was treated as "allowed", which credited WAFs for bypasses that never
    actually ran.
    """
    if waf_route.error is not None:
        return Verdict.ERROR

    # The block + "allowed" decisions below only make sense when the payload
    # was actually capable of exploiting the app — check the baseline first
    # so the denominator is the same across WAFs.
    if not baseline_triggered(payload, baseline, trigger_override):
        return Verdict.BASELINE_FAIL

    code = waf_route.status_code
    body = (waf_route.response_snippet or "").lower()
    headers_flagged = any(h in _FLAG_HEADERS for h in (waf_route.notes or "").lower().split(","))

    # 1. Hard block signatures.
    if code in _BLOCK_STATUS_CODES:
        return Verdict.BLOCKED
    if code is not None and 500 <= code < 600 and any(m in body for m in _BLOCK_BODY_MARKERS):
        return Verdict.BLOCKED

    waf_snippet = waf_route.response_snippet or ""

    # 2. 2xx OR 5xx-without-WAF-marker: if the same exploit marker that fired
    # on baseline fires here too, the WAF passed the attack through (Juice
    # Shop's /rest/products/search returns 500 + SQLITE_ERROR on a successful
    # SQLi — still an "allowed" bypass because the payload reached the sink).
    if code is not None and (200 <= code < 300 or 500 <= code < 600):
        if _match_trigger(trigger_override or payload.trigger, waf_snippet, code, payload):
            if headers_flagged or any(m in body for m in _BLOCK_BODY_MARKERS):
                return Verdict.FLAGGED
            return Verdict.ALLOWED
        # WAF responded 2xx but stripped the payload (no marker) → silent block.
        # Distinct verdict from a hard 403: the client wouldn't know the WAF
        # intervened without comparing to the baseline response. Paper-grade
        # analysis cares about this — some WAFs only sanitise, never block,
        # and that's a different threat model from "returns 403 with banner".
        if 200 <= code < 300:
            return Verdict.BLOCKED_SILENT
        # Non-block 5xx without the marker → app blew up for unrelated reasons;
        # don't claim a bypass we can't prove.
        return Verdict.BASELINE_FAIL

    # 3xx (auth wall), non-block 4xx (validation error) — the payload never
    # landed at the sink, so treat it as a baseline miss rather than a
    # spurious "allowed".
    return Verdict.BASELINE_FAIL
