"""Runner engine — iterates (payload × variant × waf × target) and records verdicts.

Top-level entrypoint for Phase 3 (post-Phase-6 fixes). Architecture:

  1. Load the payload corpus + target routing config.
  2. For each requested mutator, enumerate variants per payload.
  3. For each route (waf × target) + baseline host, open a *dedicated*
     ``httpx.AsyncClient`` so cookie jars never leak across routes. The
     previous shared-client design leaked the baseline session into every
     WAF route and hid broken auth under a false "allowed" signal.
  4. For each variant, send (baseline, waf) pair. Baseline is cached per
     (target, mutated_body) since a WAF response depends on the body, not
     on the source payload id — distinct mutators producing identical bytes
     coalesce into one baseline probe.
  5. Each verdict writes one JSON under
     results/raw/<run_id>/<waf>/<target>/<payload_id>__<variant>.json.

Concurrency is governed by an anyio Semaphore — MAX_CONCURRENCY
``(waf, target)`` sends in flight at once.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import anyio
import httpx
import structlog

from wafeval.config import EndpointSpec, Route, TargetsConfig, load_targets
from wafeval.models import (
    MutatedPayload,
    Payload,
    RequestStep,
    RouteResult,
    Verdict,
    VerdictRecord,
    VulnClass,
)
from wafeval.mutators.base import REGISTRY
from wafeval.payloads.loader import load_corpus
from wafeval.runner.environment import capture_environment
from wafeval.runner.session import DEFAULT_USER_AGENT, login_dvwa, login_webgoat
from wafeval.runner.verdict import classify

log = structlog.get_logger(__name__)

# How much of each response we keep for forensic review. 64 KB is enough for
# every payload class in the corpus (longest: DVWA UNION dump ≈ 3 KB; Juice
# Shop SQLITE stack trace ≈ 12 KB) while still bounded.
_SNIPPET_BYTES_DEFAULT = 65536
SNIPPET_BYTES = int(os.environ.get("RESPONSE_SNIPPET_BYTES", _SNIPPET_BYTES_DEFAULT))

# Substrings that mark a response header as WAF-identifying. We match on
# lowercased name so case-variants (X-Coraza-Status vs x-coraza-status) both
# count. ``waflab`` covers the custom ``x-waflab-waf`` / ``x-waflab-verdict``
# tags our coraza-proxy + shadowd-proxy emit.
_WAF_HEADER_TAGS = ("coraza", "modsec", "shadowd", "waflab")


def _capture_waf_headers(headers) -> tuple[list[str], dict[str, str]]:
    """Return ``(names, name→value)`` for WAF-identifying response headers.

    Only captures ``x-*`` headers whose name contains one of
    ``_WAF_HEADER_TAGS``. Kept narrow to avoid dragging every ``x-frame-
    options``/``x-content-type-options`` into forensic metadata.
    """
    names = [
        h for h in headers
        if h.lower().startswith("x-")
        and any(tag in h.lower() for tag in _WAF_HEADER_TAGS)
    ]
    return names, {h: headers[h] for h in names}


@dataclass
class RunConfig:
    """Inputs to one engine run."""
    traefik_url: str = "http://127.0.0.1:8000"
    mutators: list[str] = field(default_factory=lambda: ["lexical"])
    classes: list[VulnClass] = field(default_factory=lambda: [VulnClass.SQLI, VulnClass.XSS])
    targets: list[str] | None = None       # None → all in targets.yaml
    wafs: list[str] | None = None          # None → all routes in targets.yaml
    max_concurrency: int = 10
    # 30s accommodates DVWA's /vulnerabilities/exec which hardcodes
    # ``ping -c 4 <ip>`` — a successful baseline cmdi request therefore
    # takes ~4s, and under load (many cmdi variants + PHP-FPM worker
    # queue) occasional baseline requests would previously hit the 15s
    # ceiling and be classified as ``error`` instead of ``allowed``.
    request_timeout_s: float = 30.0
    results_root: Path = Path("results/raw")
    run_id: str | None = None
    # Single-file corpus override. When set, the loader reads
    # ``payloads/<corpus>.yaml`` verbatim instead of the per-class split.
    # Used for the paper-replication subset.
    corpus: str | None = None
    # Optional seed for Python's ``random`` module. Recorded in
    # ``manifest.json`` so a rerun with the same seed produces the same
    # ordering for any future randomised step (sampling, GA mutator,
    # adaptive-pair tiebreaks). No-op today for the five base mutators
    # which are deterministic, but the field is the forcing function for
    # every future randomised flow to honour it.
    seed: int | None = None


def _new_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    h = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    return f"{ts}_{h}"


def _pick_routes(cfg: TargetsConfig, wafs: list[str] | None, targets: list[str] | None) -> list[Route]:
    out: list[Route] = []
    for r in cfg.routes:
        if wafs is not None and r.waf not in wafs:
            continue
        if targets is not None and r.target not in targets:
            continue
        out.append(r)
    return out


def _build_request(ep: EndpointSpec, body: str) -> tuple[str, str, dict, dict | None]:
    """Return (method, path, query, form) with {payload} substituted."""
    query = {k: v.replace("{payload}", body) for k, v in (ep.query or {}).items()}
    form = None
    if ep.form:
        form = {k: v.replace("{payload}", body) for k, v in ep.form.items()}
    return ep.method, ep.path, query, form


def _build_httpx_kwargs(
    ep: EndpointSpec | None,
    body: str,
    step: RequestStep | None,
    host: str,
) -> tuple[str, str, dict]:
    """Return (method, path, httpx kwargs) for one request.

    Two modes:
      - ep != None, step == None: default endpoint substitution (Phase 3 path)
      - step != None: replay the RequestStep verbatim; ep is used only as a
        path fallback when step.path_override is None.
    """
    headers: dict[str, str] = {"Host": host, "User-Agent": DEFAULT_USER_AGENT}
    kwargs: dict = {"headers": headers, "follow_redirects": False}

    if step is None:
        assert ep is not None, "default path requires an EndpointSpec"
        method, path, query, form = _build_request(ep, body)
        if query:
            kwargs["params"] = query
        if form:
            kwargs["data"] = form
        return method, path, kwargs

    path = step.path_override or (ep.path if ep else "/")
    if step.query:
        kwargs["params"] = dict(step.query)
    if step.form:
        kwargs["data"] = dict(step.form)
    if step.json_body is not None:
        kwargs["json"] = step.json_body
    if step.raw_body is not None:
        kwargs["content"] = step.raw_body
    if step.file_fields:
        kwargs["files"] = {
            k: (fn, content) for k, (fn, content) in step.file_fields.items()
        }
    if step.content_type:
        headers["Content-Type"] = step.content_type
    headers.update(step.headers)
    return step.method, path, kwargs


async def _send_one(
    client: httpx.AsyncClient,
    base_url: str,
    host: str,
    ep: EndpointSpec | None,
    body: str,
    cookies: dict[str, str] | None,
    step: RequestStep | None = None,
) -> tuple[RouteResult, dict[str, str]]:
    """Send one request. Returns (RouteResult, updated cookie jar)."""
    method, path, kwargs = _build_httpx_kwargs(ep, body, step, host)
    url = f"{base_url}{path}"
    if cookies:
        kwargs["cookies"] = cookies
    try:
        r = await client.request(method, url, **kwargs)
    except httpx.HTTPError as e:
        return RouteResult(
            route=host, status_code=None, response_ms=None,
            response_bytes=None, response_snippet=None, error=repr(e),
        ), dict(cookies or {})
    # Response snippet — capped at SNIPPET_BYTES (default 64 KB, configurable
    # via RESPONSE_SNIPPET_BYTES). Covers every payload class in the corpus
    # plus the Juice Shop SQLite stack trace, without writing MB-scale JSON
    # for pathological responses.
    snippet = r.text[:SNIPPET_BYTES] if r.content else ""
    elapsed_ms = r.elapsed.total_seconds() * 1000.0
    waf_hdrs, waf_header_values = _capture_waf_headers(r.headers)
    updated_jar = dict(cookies or {})
    updated_jar.update(r.cookies)
    return RouteResult(
        route=host,
        status_code=r.status_code,
        response_ms=elapsed_ms,
        response_bytes=len(r.content),
        response_snippet=snippet,
        error=None,
        notes=",".join(waf_hdrs) if waf_hdrs else None,
        waf_headers=waf_header_values,
    ), updated_jar


async def _send(
    client: httpx.AsyncClient,
    base_url: str,
    host: str,
    ep: EndpointSpec | None,
    variant: MutatedPayload | None,
    body: str,
    cookies: dict[str, str] | None,
) -> RouteResult:
    """Dispatch one datapoint — default request OR replay an override chain.

    Cookie jar is shared across all steps in the chain. The *last* step's
    RouteResult is the one the verdict classifier keys off (trigger marker
    in body + status code). If an earlier step errors, the chain short-
    circuits and that error-flagged RouteResult is returned.
    """
    if variant is None or not variant.request_overrides:
        res, _ = await _send_one(client, base_url, host, ep, body, cookies)
        return res

    jar = dict(cookies or {})
    last: RouteResult | None = None
    for step in variant.request_overrides:
        res, jar = await _send_one(client, base_url, host, ep, body, jar, step=step)
        last = res
        if res.error is not None:
            break
    assert last is not None
    return last


def _out_path(results_root: Path, run_id: str, waf: str, target: str, payload_id: str, variant: str) -> Path:
    return results_root / run_id / waf / target / f"{payload_id}__{variant}.json"


async def _auth_for_route(
    client: httpx.AsyncClient,
    base_url: str,
    route: Route,
    tcfg: TargetsConfig,
) -> dict[str, str] | None:
    """Run the login flow if the target's endpoints expect auth.

    The returned cookie dict is the *authoritative* jar for this route. Each
    route has its own ``client`` (see ``run``), so merging with a shared
    client jar is no longer a concern — we still return the dict rather
    than mutating the client, because ``_send_one`` attaches cookies
    explicitly and we want the call graph to stay easy to reason about.
    """
    spec = tcfg.targets[route.target]
    if spec.login is None:
        return None
    if not any(ep.expect_auth for ep in spec.endpoints.values()):
        return None
    if spec.login.kind == "webgoat":
        return await login_webgoat(client, base_url, route.host, spec.login)
    return await login_dvwa(client, base_url, route.host, spec.login)


def _make_client(cfg: "RunConfig") -> httpx.AsyncClient:
    """Construct a per-route ``httpx.AsyncClient``.

    Cookies=None tells httpx to start with a fresh, empty jar — we still
    attach cookies explicitly on each request (see ``_send_one``), but this
    eliminates any cross-route leak if a caller ever forgets.
    """
    return httpx.AsyncClient(
        timeout=cfg.request_timeout_s,
        limits=httpx.Limits(
            max_connections=cfg.max_concurrency * 2,
            max_keepalive_connections=cfg.max_concurrency,
        ),
        cookies=httpx.Cookies(),
    )


async def _process_variant(
    clients_by_host: dict[str, httpx.AsyncClient],
    base_url: str,
    run_id: str,
    results_root: Path,
    route: Route,
    tcfg: TargetsConfig,
    payload: Payload,
    variant: MutatedPayload,
    cookies_by_route: dict[str, dict[str, str] | None],
    baseline_cache: dict[tuple[str, str], RouteResult],
    sem: anyio.Semaphore,
) -> VerdictRecord | None:
    """Send one (variant, route) datapoint, classify, persist."""
    spec = tcfg.targets[route.target]
    ep = spec.endpoints.get(payload.vuln_class)
    if ep is None:
        return None

    # Baseline is keyed on (target, mutated_body). Distinct source payloads
    # whose mutators produced identical bytes collapse to one probe. The
    # previous key included ``variant.variant`` which defeated the cache.
    baseline_host = f"baseline-{route.target}.local"
    cache_key = (route.target, variant.body)
    async with sem:
        baseline = baseline_cache.get(cache_key)
        if baseline is None:
            baseline_client = clients_by_host[baseline_host]
            baseline_cookies = cookies_by_route.get(baseline_host)
            baseline = await _send(baseline_client, base_url, baseline_host, ep, variant, variant.body, baseline_cookies)
            baseline_cache[cache_key] = baseline

        if route.waf == "baseline":
            # Baseline-only row — record it for completeness.
            waf_result = baseline
        else:
            waf_client = clients_by_host[route.host]
            waf_cookies = cookies_by_route.get(route.host)
            waf_result = await _send(waf_client, base_url, route.host, ep, variant, variant.body, waf_cookies)

    verdict = classify(payload, baseline, waf_result, trigger_override=ep.trigger)
    rec = VerdictRecord(
        run_id=run_id,
        waf=route.waf,
        target=route.target,
        payload_id=payload.id,
        vuln_class=payload.vuln_class,
        variant=variant.variant,
        mutator=variant.mutator,
        complexity_rank=variant.complexity_rank,
        mutated_body=variant.body,
        verdict=verdict,
        baseline=baseline,
        waf_route=waf_result,
    )
    out = _out_path(results_root, run_id, route.waf, route.target, payload.id, variant.variant)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rec.model_dump_json(indent=2))
    return rec


async def run(cfg: RunConfig) -> str:
    """Execute one full run. Returns the run_id."""
    run_id = cfg.run_id or _new_run_id()
    if cfg.seed is not None:
        random.seed(cfg.seed)
    log.info(
        "run.start",
        run_id=run_id,
        mutators=cfg.mutators,
        classes=[c.value for c in cfg.classes],
        seed=cfg.seed,
    )

    # 1. Load + filter corpus + mutators
    corpus = load_corpus(classes=cfg.classes, corpus_name=cfg.corpus)
    if not corpus:
        raise RuntimeError("empty payload corpus — nothing to run")
    tcfg = load_targets()
    routes = _pick_routes(tcfg, cfg.wafs, cfg.targets)
    if not routes:
        raise RuntimeError("no matching routes — check --wafs / --targets filters")
    mutators = [REGISTRY[name]() for name in cfg.mutators]

    # 2. Expand variants
    variants: list[tuple[Payload, MutatedPayload]] = []
    for p in corpus:
        for m in mutators:
            for v in m.mutate(p):
                variants.append((p, v))
    log.info("run.plan",
             routes=len(routes), payloads=len(corpus),
             variants_total=len(variants),
             datapoints=len(variants) * len(routes))

    # 3. Per-route httpx clients (+ per-baseline-host client) so cookie jars
    # and connection pools never leak across routes. AsyncExitStack owns the
    # lifetimes; all clients close together when the run finishes or errors.
    clients_by_host: dict[str, httpx.AsyncClient] = {}
    cookies_by_route: dict[str, dict[str, str] | None] = {}

    hosts_needing_client: set[str] = {r.host for r in routes}
    hosts_needing_client.update(f"baseline-{r.target}.local" for r in routes)

    async with AsyncExitStack() as stack:
        for host in sorted(hosts_needing_client):
            clients_by_host[host] = await stack.enter_async_context(_make_client(cfg))

        # Auth per route — each client is brand new, so its jar starts empty
        # and ends up owning exactly the cookies the login flow produces.
        for r in routes:
            cookies_by_route[r.host] = await _auth_for_route(clients_by_host[r.host], cfg.traefik_url, r, tcfg)
        for tgt in {r.target for r in routes}:
            baseline_host = f"baseline-{tgt}.local"
            if baseline_host not in cookies_by_route:
                fake_route = Route(host=baseline_host, waf="baseline", target=tgt)
                cookies_by_route[baseline_host] = await _auth_for_route(
                    clients_by_host[baseline_host], cfg.traefik_url, fake_route, tcfg,
                )

        baseline_cache: dict[tuple[str, str], RouteResult] = {}
        sem = anyio.Semaphore(cfg.max_concurrency)

        verdicts: list[VerdictRecord] = []

        async def _one(p: Payload, v: MutatedPayload, route: Route):
            rec = await _process_variant(
                clients_by_host, cfg.traefik_url, run_id, cfg.results_root,
                route, tcfg, p, v,
                cookies_by_route, baseline_cache, sem,
            )
            if rec is not None:
                verdicts.append(rec)

        async with anyio.create_task_group() as tg:
            for p, v in variants:
                for route in routes:
                    # Skip if the target has no endpoint for this vuln class.
                    if tcfg.targets[route.target].endpoints.get(p.vuln_class) is None:
                        continue
                    tg.start_soon(_one, p, v, route)

    # 4. Summary + manifest
    counts: dict[str, int] = {}
    for rec in verdicts:
        counts[rec.verdict.value] = counts.get(rec.verdict.value, 0) + 1
    manifest = {
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mutators": cfg.mutators,
        "classes": [c.value for c in cfg.classes],
        "routes": [r.model_dump() for r in routes],
        "totals": {"datapoints": len(verdicts), **counts},
        "seed": cfg.seed,
        "environment": capture_environment(),
    }
    manifest_path = cfg.results_root / run_id / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log.info("run.done", run_id=run_id, **counts)
    return run_id


def verdict_rollup(records: Iterable[VerdictRecord]) -> dict[str, int]:
    """Small helper used by tests + the CLI to print a summary line."""
    out: dict[str, int] = {v.value: 0 for v in Verdict}
    for r in records:
        out[r.verdict.value] = out.get(r.verdict.value, 0) + 1
    return out
