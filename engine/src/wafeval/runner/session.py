"""Per-target session bootstrappers.

Vulnerable apps that gate the sink behind a login need a one-shot auth dance
before the engine can hit them. The runner calls the right bootstrapper per
route based on ``login.kind`` in ``targets.yaml`` and caches the returned
cookie jar for every request against that route.

Implementations:

* ``login_dvwa`` — scrape CSRF ``user_token`` from GET /login.php, POST it,
  stamp ``security=low`` client-side (DVWA's GET /security.php redirect
  silently drops the cookie when ``follow_redirects=False``).
* ``login_webgoat`` — POST /WebGoat/register.mvc (idempotent; ignored if the
  user exists), POST /WebGoat/login, then GET each lesson prime path so
  subsequent attack endpoints find an initialised lesson state. The
  registration form caps passwords at 10 characters and requires
  ``agree=agree``.
"""
from __future__ import annotations

import re

import httpx
import structlog

from wafeval.config import LoginSpec

log = structlog.get_logger(__name__)

# Quote-agnostic: DVWA emits ``value='...'`` but a fork could switch to ``"``.
# The regex also tolerates attribute-order flips (``value=...`` appearing
# before ``name=``) by scanning for the two anchors in either order.
_TOKEN_RE = re.compile(
    r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]{16,64})['"]""",
    re.IGNORECASE,
)

# A benign, modern UA — survives CRS rule 913100 (bad-bot UA) at every
# paranoia level we ship (PL1 default + PL4 --profile paranoia-high).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


def parse_user_token(html: str) -> str | None:
    """Extract DVWA's ``user_token`` from a login-page body.

    Exposed so the test suite can exercise the regex against fixture HTML
    without standing up a full DVWA.
    """
    m = _TOKEN_RE.search(html)
    return m.group(1) if m else None


async def login_dvwa(
    client: httpx.AsyncClient,
    base_url: str,
    host: str,
    login: LoginSpec,
) -> dict[str, str]:
    """Authenticate against DVWA through ``host`` and return cookies.

    Called once per route that has ``expect_auth=True`` endpoints. DVWA
    tracks sessions by a PHPSESSID cookie — the returned dict is the
    authoritative jar for that route and should not be merged with a shared
    client jar (see runner/engine.py for the per-route isolation).
    """
    headers = {"Host": host, "User-Agent": DEFAULT_USER_AGENT}

    r1 = await client.get(f"{base_url}{login.path}", headers=headers, follow_redirects=False)
    token = parse_user_token(r1.text) or ""
    if not token:
        log.warning("dvwa.login.no_token", host=host, status=r1.status_code)

    cookies = dict(r1.cookies)
    # DVWA's install flow stamps the PHPSESSID on the login-page GET when the
    # client arrives without one. If the shared-jar case in the past nuked
    # Set-Cookie, the login POST below would fail; a per-route client jar
    # (Bundle 3) plus this direct ``cookies`` dict makes the flow robust.

    form = {
        "username": login.username,
        "password": login.password,
        "Login": "Login",
        "user_token": token,
    }
    r2 = await client.post(
        f"{base_url}{login.path}",
        data=form,
        headers=headers,
        cookies=cookies,
        follow_redirects=False,
    )
    cookies.update(r2.cookies)

    # Set security=low directly — the previous GET /security.php?security=low
    # flow relied on DVWA's 302 redirect stamping the cookie, which doesn't
    # happen reliably when follow_redirects is off. Setting it client-side is
    # deterministic and matches what DVWA's own form would do.
    cookies["security"] = "low"

    log.info(
        "dvwa.login.done",
        host=host,
        status=r2.status_code,
        have_phpsessid="PHPSESSID" in cookies,
        have_token=bool(token),
    )
    return cookies


async def login_webgoat(
    client: httpx.AsyncClient,
    base_url: str,
    host: str,
    login: LoginSpec,
) -> dict[str, str]:
    """Authenticate against WebGoat through ``host`` and return cookies.

    WebGoat requires a registered user; there is no default admin. The
    registration form is idempotent at the HTTP level (re-registering with a
    username that already exists quietly returns 200 with the form re-rendered
    instead of an error status), so we always POST /register.mvc and discard
    the response — if the user didn't exist we just created them, and if they
    did, the subsequent POST /login proves it. Passwords are length-capped at
    10 characters by Spring's validator, and the Ts&Cs checkbox must be
    ``agree=agree``.

    Lesson state is per-session: hitting ``/SqlInjection/attack2`` before
    GETting ``/SqlInjection.lesson`` returns 404 ("no such route registered
    for this session") even though the controller exists. We prime every
    ``prime_paths`` URL after login so attack endpoints find an initialised
    lesson and return 200 with the JSON contract (``attemptWasMade`` etc.).
    """
    headers = {"Host": host, "User-Agent": DEFAULT_USER_AGENT}

    # All three phases (register, login, prime) share ``client.cookies`` as
    # the running jar: httpx auto-captures Set-Cookie on every response and
    # auto-attaches the jar on every subsequent request, so we don't pass
    # ``cookies=`` per-request (deprecated in httpx ≥0.28).
    if login.register_path:
        reg_form = {
            "username": login.username,
            "password": login.password,
            "matchingPassword": login.password,
            "agree": "agree",
        }
        r_reg = await client.post(
            f"{base_url}{login.register_path}",
            data=reg_form,
            headers=headers,
            follow_redirects=False,
        )
        log.info("webgoat.register.done", host=host, status=r_reg.status_code)

    r_login = await client.post(
        f"{base_url}{login.path}",
        data={"username": login.username, "password": login.password},
        headers=headers,
        follow_redirects=False,
    )
    # Login success = 302 to /welcome.mvc; failure = 302 to /login?error.
    login_ok = (
        r_login.status_code == 302
        and "error" not in (r_login.headers.get("location") or "")
    )
    if not login_ok:
        log.warning(
            "webgoat.login.fail",
            host=host,
            status=r_login.status_code,
            location=r_login.headers.get("location"),
        )

    for prime in login.prime_paths:
        r_prime = await client.get(
            f"{base_url}{prime}",
            headers=headers,
            follow_redirects=False,
        )
        # Prime GETs should 200 when the session is authenticated. A 302 to
        # /login indicates the session evaporated; log and continue so the
        # caller can see the downstream failure in per-datapoint logs rather
        # than abort the whole run.
        if r_prime.status_code != 200:
            log.warning(
                "webgoat.prime.fail",
                host=host,
                path=prime,
                status=r_prime.status_code,
            )

    cookies = dict(client.cookies)
    log.info(
        "webgoat.login.done",
        host=host,
        status=r_login.status_code,
        have_jsessionid="JSESSIONID" in cookies,
        lessons_primed=len(login.prime_paths),
    )
    return cookies
