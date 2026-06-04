"""Tests for runner/session.py helpers — keep the DVWA login-token regex
locked against a frozen fixture so a future DVWA upgrade that rearranges the
login form can't silently break authentication."""
from __future__ import annotations

import textwrap

from wafeval.runner.session import DEFAULT_USER_AGENT, parse_user_token


def test_parse_user_token_single_quotes():
    # Matches the live DVWA v1.10 body shipped with vulnerables/web-dvwa.
    html = textwrap.dedent("""
        <form action="login.php" method="post">
          <input type="submit" value="Login" name="Login">
          <input type='hidden' name='user_token' value='93106c62957de7d146b717296dab4d08' />
        </form>
    """)
    assert parse_user_token(html) == "93106c62957de7d146b717296dab4d08"


def test_parse_user_token_double_quotes():
    html = '<input type="hidden" name="user_token" value="deadbeefcafef00d" />'
    assert parse_user_token(html) == "deadbeefcafef00d"


def test_parse_user_token_missing_returns_none():
    assert parse_user_token("<html>no form here</html>") is None


def test_parse_user_token_non_hex_rejected():
    # Must be a hex string — a decoy ``value='notatoken!'`` shouldn't match.
    assert parse_user_token("name='user_token' value='notatoken!'") is None


def test_default_user_agent_is_not_scripted():
    ua = DEFAULT_USER_AGENT.lower()
    # CRS rule 913100 flags common scripted UAs — keep us out of the list.
    for bad in ("httpx", "wafeval", "python-requests", "curl", "wget", "nikto"):
        assert bad not in ua
    assert "mozilla" in ua


# ---------- WebGoat login bootstrapper ----------------------------------------

import httpx  # noqa: E402
import pytest  # noqa: E402

from wafeval.config import LoginSpec  # noqa: E402
from wafeval.runner.session import login_webgoat  # noqa: E402


def _webgoat_transport(login_location: str = "/WebGoat/welcome.mvc"):
    """Build an httpx.MockTransport that mimics WebGoat's auth endpoints.

    - POST /WebGoat/register.mvc → 200 (WebGoat quietly re-renders the form
      whether the user is new or exists — we don't branch on it).
    - POST /WebGoat/login → 302 to ``login_location`` with a JSESSIONID
      cookie. If ``login_location`` contains ``login?error`` the caller is
      simulating a bad-password response.
    - GET  /WebGoat/*.lesson → 200.
    Any other request returns 500 so the test fails loudly.
    """
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "POST" and request.url.path == "/WebGoat/register.mvc":
            return httpx.Response(200, html="<html>registered (or already existed)</html>")
        if request.method == "POST" and request.url.path == "/WebGoat/login":
            return httpx.Response(
                302,
                headers={
                    "Location": f"http://webgoat.example{login_location}",
                    "Set-Cookie": "JSESSIONID=ABCDEF123; Path=/WebGoat; HttpOnly",
                },
            )
        if request.method == "GET" and request.url.path.endswith(".lesson"):
            return httpx.Response(200, text="lesson html")
        return httpx.Response(500, text=f"unexpected {request.method} {request.url.path}")

    return httpx.MockTransport(handler), calls


@pytest.fixture
def webgoat_login() -> LoginSpec:
    return LoginSpec(
        kind="webgoat",
        path="/WebGoat/login",
        register_path="/WebGoat/register.mvc",
        username="waflab",
        password="wafpw123",
        prime_paths=["/WebGoat/SqlInjection.lesson", "/WebGoat/CrossSiteScripting.lesson"],
    )


async def test_login_webgoat_happy_path(webgoat_login):
    transport, calls = _webgoat_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        cookies = await login_webgoat(client, "http://webgoat.example", "baseline-webgoat.local", webgoat_login)
    assert cookies.get("JSESSIONID") == "ABCDEF123"
    # Order matters: register must precede login, login must precede every prime.
    assert calls == [
        ("POST", "/WebGoat/register.mvc"),
        ("POST", "/WebGoat/login"),
        ("GET", "/WebGoat/SqlInjection.lesson"),
        ("GET", "/WebGoat/CrossSiteScripting.lesson"),
    ]


async def test_login_webgoat_skips_register_when_path_missing(webgoat_login):
    webgoat_login = webgoat_login.model_copy(update={"register_path": None})
    transport, calls = _webgoat_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        await login_webgoat(client, "http://webgoat.example", "baseline-webgoat.local", webgoat_login)
    assert calls[0] == ("POST", "/WebGoat/login")


async def test_login_webgoat_warns_on_bad_credentials(webgoat_login, caplog):
    # 302 to /login?error indicates Spring Security rejected the creds.
    transport, _ = _webgoat_transport(login_location="/WebGoat/login?error")
    async with httpx.AsyncClient(transport=transport) as client:
        # No raise — the run continues, but the warning is emitted for the log.
        cookies = await login_webgoat(client, "http://webgoat.example", "host", webgoat_login)
    # We still return whatever cookies the server stamped; the engine's per-
    # datapoint 401/302 will then show up as baseline_fail noise.
    assert "JSESSIONID" in cookies
