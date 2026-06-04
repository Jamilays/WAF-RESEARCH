"""
Shadow Daemon reverse-proxy connector (Phase 7 — real integration).

Shadow Daemon publishes only language-level connectors (PHP / Perl / Python).
To put it in front of arbitrary HTTP apps (WebGoat, Juice Shop, placeholder
backends) the lab ships this small async reverse proxy. It speaks shadowd's
real wire protocol — ``[profile_id]\\n[hmac-sha256(json, key)]\\n[json]\\n``
— exactly like zecure/shadowd_python's connector, so the daemon consults
its 120 bundled blacklist filters for every request and returns an attack
verdict (``status==5`` or ``6``).

Behaviour:
  - /healthz always 200 (bypasses shadowd)
  - Every other request → analyse → forward-or-block
  - SHADOWD_ENFORCE=true (default) translates attack verdicts to 403
  - SHADOWD_FALLBACK_BLOCK kept as an optional safety net — off by default
    now that the real path works; flip back on to compare coverage

For lab repeatability the profile id + HMAC key are fixed at bootstrap time
by ``wafs/shadowdaemon/init/bootstrap.sql``. They are non-secret (the stack
is loopback-only) — rotate via ``.env`` for anything sensitive.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
from typing import Any
from urllib.parse import unquote_plus

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

logger = logging.getLogger("shadowd-proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

BACKEND = os.getenv("BACKEND", "http://whoami:80").rstrip("/")
SHADOWD_HOST = os.getenv("SHADOWD_HOST", "shadowd")
SHADOWD_PORT = int(os.getenv("SHADOWD_PORT", "9115"))
SHADOWD_ENFORCE = os.getenv("SHADOWD_ENFORCE", "false").lower() == "true"
SHADOWD_TIMEOUT = float(os.getenv("SHADOWD_TIMEOUT", "2.0"))
SHADOWD_PROFILE_ID = int(os.getenv("SHADOWD_PROFILE_ID", "1"))
SHADOWD_HMAC_KEY = os.getenv("SHADOWD_HMAC_KEY", "waflab_dev_only_hmac_key_change_me")
SHADOWD_VERSION = os.getenv("SHADOWD_VERSION", "3.0.2-waflab")
SHADOWD_FALLBACK_BLOCK = os.getenv("SHADOWD_FALLBACK_BLOCK", "false").lower() == "true"

# shadowd protocol status codes (from zecure/shadowd_python)
_STATUS_OK              = 1
_STATUS_BAD_REQUEST     = 2
_STATUS_BAD_SIGNATURE   = 3
_STATUS_BAD_JSON        = 4
_STATUS_ATTACK          = 5
_STATUS_CRITICAL_ATTACK = 6

_client: httpx.AsyncClient | None = None


# ---------------------------------------------------------------------------
# Optional in-proxy fallback detector — disabled by default now that the
# real shadowd path is wired. Kept for comparison / smoke-tests when the
# daemon is unreachable. Same patterns as before; see commit history for
# the rationale when it was the primary block path.
# ---------------------------------------------------------------------------

_SQLI_PATTERNS = [
    r"\b(?:union\s+(?:all\s+)?select|select\s+.*?\bfrom\b|insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
    r"['\"]?\s*\b(?:or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    r"\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay\b",
    r"\b(?:extractvalue|updatexml|xpath|xmltype)\s*\(",
    r"\binformation_schema\b|\bsqlite_master\b",
    r"/\*!?\d*.*?\*/",
    r"(?:--|#)[^\n]*$",
    r"\bconcat\s*\(|\bchar\s*\(\s*\d+",
]
_XSS_PATTERNS = [
    r"<\s*script\b",
    r"<\s*/\s*script\s*>",
    r"\bon(?:error|load|click|mouseover|mouseenter|focus|blur|toggle|animationstart)\s*=",
    r"(?:^|['\" >])javascript\s*:",
    r"<\s*(?:img|svg|iframe|object|embed|body|meta|details|math|video|audio|marquee)\b[^>]*\bon\w+\s*=",
    r"(?:alert|confirm|prompt|eval|fromcharcode)\s*[(`]",
]
_CMDI_PATTERNS = [
    r"[;&|`]\s*(?:ls|cat|id|whoami|uname|nc|wget|curl|ping|bash|sh|python|perl|ruby)\b",
    r"\$\([^)]*\)",
    r"`[^`]{1,256}`",
    r"\|\s*(?:nc|curl|wget|bash|sh|python|perl)\s+-",
    r"\b(?:wget|curl)\s+https?://",
    r"/bin/(?:sh|bash|ksh|zsh)\b",
]
_LFI_PATTERNS = [
    r"\.\./|\.\.\\",
    r"(?:^|[/=])/?(?:etc|proc|sys|var/log|root)/[a-z][\w.-]+",
    r"%2e%2e(?:%2f|%5c)|%252e%252e%252f",
    r"php://(?:input|filter|expect|memory)",
    r"(?:file|zip|data|expect|phar)://",
]
_FALLBACK_PATTERNS = [
    ("sqli", re.compile("|".join(_SQLI_PATTERNS), re.IGNORECASE | re.DOTALL)),
    ("xss",  re.compile("|".join(_XSS_PATTERNS),  re.IGNORECASE | re.DOTALL)),
    ("cmdi", re.compile("|".join(_CMDI_PATTERNS), re.IGNORECASE | re.DOTALL)),
    ("lfi",  re.compile("|".join(_LFI_PATTERNS),  re.IGNORECASE)),
]


def fallback_detect(candidates: list[str]) -> tuple[str, str] | None:
    for raw in candidates:
        if not raw:
            continue
        for value in {raw, unquote_plus(raw)}:
            for cat, rx in _FALLBACK_PATTERNS:
                m = rx.search(value)
                if m:
                    return cat, m.group(0)[:80]
    return None


async def _collect_attack_surface(request: Request) -> list[str]:
    surface: list[str] = [request.url.path]
    surface.extend(request.query_params.values())
    body = await request.body()
    if body:
        try:
            surface.append(body.decode("utf-8", "replace"))
        except Exception:
            pass
    return surface


# ---------------------------------------------------------------------------
# Real shadowd wire protocol
# ---------------------------------------------------------------------------

def _hmac_sha256(key: str, data: str) -> str:
    return hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()


def _build_shadowd_payload(request: Request, body: bytes) -> dict[str, Any]:
    """Shape the request into shadowd's canonical ``input`` map.

    Every user-controllable slot is flattened into ``<NAMESPACE>|<key>`` keys
    so shadowd's blacklist filters can scan them independently.
    """
    client_ip = request.client.host if request.client else "0.0.0.0"
    caller = "waflab-proxy"
    resource = request.url.path

    inputs: dict[str, str] = {
        f"SERVER|REQUEST_METHOD": request.method,
        f"SERVER|REQUEST_URI": request.url.path + (f"?{request.url.query}" if request.url.query else ""),
    }
    # Headers → HEADER|NAME. Lowercase the name, then UPPER the namespace
    # half to match what the Python/PHP connectors do on their host apps.
    for k, v in request.headers.items():
        if k.lower() in ("cookie", "authorization"):
            # cookie/auth are noisy; shadowd will scan them via HEADER| too,
            # so keep them in the same bucket rather than splitting each
            # cookie value out.
            inputs[f"HEADER|{k.upper()}"] = v
        else:
            inputs[f"HEADER|{k.upper()}"] = v
    for k, v in request.query_params.multi_items():
        inputs[f"GET|{k}"] = v
    # Best-effort form decode — shadowd filters catch both raw and form slots.
    if body:
        try:
            text = body.decode("utf-8", "replace")
            if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                for part in text.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        inputs[f"POST|{unquote_plus(k)}"] = unquote_plus(v)
            elif "json" in request.headers.get("content-type", "").lower():
                # Give shadowd the raw JSON — its filters regex against values.
                inputs["DATA|json_body"] = text
            else:
                inputs["DATA|body"] = text
        except Exception:
            pass

    return {
        "version": SHADOWD_VERSION,
        "client_ip": client_ip,
        "caller": caller,
        "resource": resource,
        "input": inputs,
        "hashes": {},
    }


async def _analyze(request: Request, body: bytes) -> dict[str, Any] | None:
    """Send the request to shadowd:9115 and return the parsed verdict.

    Wire format (matches zecure/shadowd_python):
        <profile_id>\\n<hmac-sha256-hex(json, key)>\\n<json>\\n
    Response is one JSON object on a single line.
    """
    payload = _build_shadowd_payload(request, body)
    json_data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    sig = _hmac_sha256(SHADOWD_HMAC_KEY, json_data)
    wire = f"{SHADOWD_PROFILE_ID}\n{sig}\n{json_data}\n".encode("utf-8")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SHADOWD_HOST, SHADOWD_PORT),
            timeout=SHADOWD_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as e:
        logger.debug("shadowd connect failed: %s", e)
        return None

    try:
        writer.write(wire)
        await writer.drain()
        # Read until EOF / timeout — shadowd sends one JSON line then closes.
        chunks = []
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=SHADOWD_TIMEOUT)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks).decode("utf-8", "replace").strip()
    except (OSError, asyncio.TimeoutError) as e:
        logger.debug("shadowd read failed: %s", e)
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("shadowd returned non-json: %r", raw[:200])
        return None


async def healthz(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok\n", status_code=200)


async def proxy(request: Request) -> Response:
    assert _client is not None

    body = await request.body()
    verdict = await _analyze(request, body)

    blocked_by: str | None = None
    if verdict and verdict.get("status") in (_STATUS_ATTACK, _STATUS_CRITICAL_ATTACK) and SHADOWD_ENFORCE:
        blocked_by = f"shadowd:status={verdict['status']}"
    elif SHADOWD_FALLBACK_BLOCK and SHADOWD_ENFORCE and (verdict is None or verdict.get("status") != _STATUS_OK):
        # Only engage fallback if the daemon didn't speak or gave us an error
        # status. If shadowd said OK, we trust it — that's the whole point.
        surface = await _collect_attack_surface(request)
        hit = fallback_detect(surface)
        if hit is not None:
            blocked_by = f"proxy_fallback:{hit[0]}"

    if blocked_by:
        threats = ""
        if verdict and verdict.get("threats"):
            threats = ",".join(str(t) for t in verdict["threats"][:10])
        logger.info("BLOCK by=%s %s %s threats=[%s]",
                    blocked_by, request.method, request.url.path, threats)
        return PlainTextResponse(
            f"Request blocked by Shadow Daemon ({blocked_by})\n",
            status_code=403,
            headers={
                "x-waflab-verdict": "blocked",
                "x-waflab-waf":     "shadowdaemon",
                "x-shadowd-verdict": blocked_by,
                "x-shadowd-threats": threats[:200],
            },
        )

    upstream = f"{BACKEND}{request.url.path}"
    if request.url.query:
        upstream += f"?{request.url.query}"

    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}

    try:
        resp = await _client.request(
            request.method, upstream, headers=headers, content=body,
        )
    except httpx.RequestError as e:
        logger.warning("backend error: %s", e)
        return PlainTextResponse(f"Upstream error: {e}\n", status_code=502,
                                 headers={"x-waflab-verdict": "upstream_error"})

    # Preserve multi-value headers (DVWA sends two Set-Cookie headers —
    # PHPSESSID + ``security``; a naive ``dict{k:v}`` would only keep the
    # last one so the engine's session.py couldn't authenticate through
    # shadowd). Starlette's Response only accepts a single-value-per-key
    # dict up front, so we append Set-Cookie and other repeatable headers
    # after construction via the MutableHeaders append().
    drop = {"content-encoding", "transfer-encoding", "content-length", "connection"}
    single: dict[str, str] = {}
    repeatable: list[tuple[str, str]] = []
    for k, v in resp.headers.raw:
        ks = k.decode("latin-1")
        vs = v.decode("latin-1")
        if ks.lower() in drop:
            continue
        if ks.lower() in ("set-cookie", "proxy-authenticate", "www-authenticate"):
            repeatable.append((ks, vs))
        else:
            single[ks] = vs
    single["x-waflab-verdict"] = (
        "allowed" if not verdict else f"analyzed:status={verdict.get('status')}"
    )
    single["x-waflab-waf"] = "shadowdaemon"
    out = Response(content=resp.content, status_code=resp.status_code,
                   headers=single, media_type=resp.headers.get("content-type"))
    for k, v in repeatable:
        out.headers.append(k, v)
    return out


async def _on_startup() -> None:
    global _client
    _client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    logger.info(
        "shadowd-proxy up — backend=%s shadowd=%s:%d enforce=%s fallback=%s profile=%d",
        BACKEND, SHADOWD_HOST, SHADOWD_PORT, SHADOWD_ENFORCE, SHADOWD_FALLBACK_BLOCK,
        SHADOWD_PROFILE_ID,
    )


async def _on_shutdown() -> None:
    if _client is not None:
        await _client.aclose()


app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/{path:path}", proxy,
              methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
    ],
    on_startup=[_on_startup],
    on_shutdown=[_on_shutdown],
)
