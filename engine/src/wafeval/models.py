"""Core pydantic models shared across the engine.

Implements the payload + mutated-variant + verdict record schemas described in
prompt.md §6 (payload corpus) and §8 (test runner). Kept in one file because
they are tightly coupled — a mutator returns MutatedPayloads, the runner turns
those into VerdictRecords.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------- payload classes ---------------------------------------------------


class VulnClass(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    LFI = "lfi"
    SSTI = "ssti"
    XXE = "xxe"
    # Phase 7 additions — WAF-view classes (no real app sink in DVWA or Juice
    # Shop). The engine sends the payload to a reflective endpoint so the WAF
    # gets a chance to inspect and block. Their rows show whether each WAF
    # has signatures for the class, not whether the backend was exploited.
    NOSQL = "nosql"       # MongoDB operator injection + $where JS
    LDAP = "ldap"         # LDAP filter injection + auth bypass
    SSRF = "ssrf"         # Server-side request forgery — AWS/GCP metadata, file://, etc.
    JNDI = "jndi"         # CVE-2021-44228 Log4Shell patterns + obfuscations
    GRAPHQL = "graphql"   # introspection abuse, batch/alias attacks
    CRLF = "crlf"         # HTTP response splitting, CR/LF header injection
    # Post-Phase-7 — realistic non-attack traffic. Runs through the same
    # routes as the attack classes, but the analyzer interprets ``BLOCKED``
    # as a false-positive rather than a WAF win. Paired with the ``noop``
    # mutator for clean FPR measurement (a user never sends ``aPpLe JUICE``
    # to a real search box).
    BENIGN = "benign"


# ---------- trigger check (how we confirm a baseline exploit "worked") --------


class TriggerContains(BaseModel):
    """Baseline response body must contain this literal substring (case-sensitive)."""
    kind: Literal["contains"] = "contains"
    needle: str


class TriggerRegex(BaseModel):
    """Baseline response body must match this regex."""
    kind: Literal["regex"] = "regex"
    pattern: str


class TriggerReflected(BaseModel):
    """The payload itself (or a canonical substring) must be reflected in the body.

    Used for reflected-XSS payloads where the vuln is "payload round-trips into
    HTML." `marker` lets the payload author specify a minimal identifying
    substring (e.g. ``<script>alert`` from a larger vector); defaults to the
    full payload when omitted.
    """
    kind: Literal["reflected"] = "reflected"
    marker: str | None = None


class TriggerStatus(BaseModel):
    """Baseline response status must equal this code exactly."""
    kind: Literal["status"] = "status"
    code: int


class TriggerAnyOf(BaseModel):
    """Fire if *any* of the child triggers fire (logical OR).

    Exists so one payload entry can stay valid across multiple backends
    (e.g. DVWA's ``First name`` echo + Juice Shop's ``SQLITE_ERROR`` page).
    Children are evaluated left-to-right; there is no short-circuit visible
    difference because none of the child kinds have side effects.
    """
    kind: Literal["any_of"] = "any_of"
    any_of: list["TriggerContains | TriggerRegex | TriggerReflected | TriggerStatus"] = Field(min_length=1)


Trigger = TriggerContains | TriggerRegex | TriggerReflected | TriggerStatus | TriggerAnyOf


# ---------- payloads ----------------------------------------------------------


# Destructive patterns we refuse to load — matches prompt.md §13 (safety).
# Case-insensitive substring match; covers the common footguns.
DESTRUCTIVE_PATTERNS = (
    "drop table",
    "drop database",
    "truncate table",
    "rm -rf",
    "shutdown",
    "/etc/shadow",
    "mkfs",
    ":(){:|:&};:",  # fork bomb
)


class Payload(BaseModel):
    """A single baseline payload, loaded from YAML."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    vuln_class: VulnClass = Field(alias="class")
    payload: str
    trigger: Trigger = Field(discriminator="kind")
    cwe: str | None = None
    source: str | None = None
    notes: str | None = None

    @field_validator("payload")
    @classmethod
    def _reject_destructive(cls, v: str) -> str:
        lower = v.lower()
        for pat in DESTRUCTIVE_PATTERNS:
            if pat in lower:
                raise ValueError(
                    f"payload rejected: contains destructive pattern {pat!r}. "
                    f"See prompt.md §13 safety clause."
                )
        return v


class RequestStep(BaseModel):
    """A single HTTP request in an override chain.

    Used by context_displacement (relocating a payload into JSON/header/
    multipart) and multi_request (splitting an exploit across sequential
    requests with shared cookies). When a MutatedPayload carries
    ``request_overrides``, the runner replays these steps verbatim instead of
    filling the default endpoint template from ``targets.yaml``.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    method: Literal["GET", "POST"] = "GET"
    path_override: str | None = None          # None → runner uses endpoint default path
    query: dict[str, str] = Field(default_factory=dict)
    form: dict[str, str] = Field(default_factory=dict)
    json_body: dict | list | str | int | float | None = None
    raw_body: str | None = None               # used for XML / text/plain POSTs
    content_type: str | None = None           # override Content-Type (XML etc.)
    headers: dict[str, str] = Field(default_factory=dict)
    # multipart fields: name → (filename, content). Empty filename == plain form part.
    file_fields: dict[str, tuple[str, str]] = Field(default_factory=dict)


class MutatedPayload(BaseModel):
    """One variant produced by a Mutator.

    A mutator may return multiple MutatedPayloads per input Payload. Mutators
    that simply rewrite the payload string (lexical/encoding/structural) leave
    ``request_overrides`` as None — the runner substitutes ``body`` into the
    default endpoint template from ``targets.yaml``.

    Mutators that relocate the payload (context_displacement) or split it
    across steps (multi_request) populate ``request_overrides`` with one or
    more ``RequestStep``. The runner replays them with a shared cookie jar
    and classifies the *last* step's response against the trigger.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str          # Payload.id
    variant: str            # e.g. "case_permute_0", "whitespace_1"
    mutator: str            # mutator.category
    complexity_rank: int
    body: str               # the mutated payload string (canonical form)
    request_overrides: list[RequestStep] | None = None
    notes: str | None = None


# ---------- verdict records ---------------------------------------------------


class Verdict(StrEnum):
    BLOCKED = "blocked"                # WAF returned 4xx or 5xx that matches a block signature
    BLOCKED_SILENT = "blocked_silent"  # WAF passed the request through but the response
                                       # carries no exploit marker — silent sanitise (stripped
                                       # script tag, dropped quotes, etc.). Counts as a WAF win
                                       # but is distinct from a hard block for paper analysis.
    ALLOWED = "allowed"                # 2xx response, baseline triggered → real bypass
    FLAGGED = "flagged"                # 2xx response, but WAF log/header indicates detection
    BASELINE_FAIL = "baseline_fail"    # baseline didn't trigger → can't claim bypass
    ERROR = "error"                    # network / timeout / protocol failure


class RouteResult(BaseModel):
    """Outcome of one HTTP send (either baseline or a WAF route)."""
    model_config = ConfigDict(extra="forbid")

    route: str                 # e.g. "baseline-dvwa.local", "modsec-dvwa.local"
    status_code: int | None
    response_ms: float | None
    response_bytes: int | None
    response_snippet: str | None   # first ~512 chars of body for forensic review
    error: str | None = None
    notes: str | None = None       # comma-joined WAF-identifying header NAMES (legacy — kept
                                   # so verdict.classify's ``notes.split(",")`` check still works).
    # Name → value for a curated allowlist of WAF-identifying response headers
    # (``x-waflab-waf``, ``x-shadowd-threats``, etc). The ``notes`` field only
    # captured names, losing the values; readers that want "which CRS rule
    # family fired / which threat class shadowd detected" key off this dict.
    waf_headers: dict[str, str] = Field(default_factory=dict)


class VerdictRecord(BaseModel):
    """One full datapoint: (payload, variant, waf, target) → verdict.

    Written to results/raw/<run_id>/<waf>/<target>/<payload_id>__<variant>.json.
    The analyzer (Phase 5) aggregates these into bypass-rate tables.
    """
    model_config = ConfigDict(extra="forbid")

    run_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    waf: str                   # "baseline" | "modsec" | "coraza" | "shadowd"
    target: str                # "dvwa" | "webgoat" | "juiceshop"
    payload_id: str
    vuln_class: VulnClass
    variant: str
    mutator: str
    complexity_rank: int
    mutated_body: str
    verdict: Verdict
    baseline: RouteResult
    waf_route: RouteResult
    notes: str | None = None
