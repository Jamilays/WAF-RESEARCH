"""Target endpoint + route map loader.

Parses ``targets.yaml`` (shipped with the package) into typed config objects
the runner can consume. Keeps the YAML path a single source of truth so the
engine and docs don't drift.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from wafeval.models import Trigger, VulnClass


class LoginSpec(BaseModel):
    """Per-target authentication bootstrapper spec.

    ``kind`` picks the concrete bootstrapper implementation in ``runner/session.py``:

      * ``dvwa``    — GET login-page, scrape CSRF ``user_token``, POST form,
                      stamp ``security=low`` cookie client-side.
      * ``webgoat`` — POST register (idempotent — WebGoat 409s on re-use,
                      handled as "user already exists"), POST login, then GET
                      each ``prime_paths`` URL to initialise lesson state.
                      WebGoat's password validator caps length at 10 characters.
    """
    model_config = ConfigDict(extra="forbid")
    kind: Literal["dvwa", "webgoat"] = "dvwa"
    method: Literal["POST"] = "POST"
    path: str
    form_tokenized: bool = False
    username: str
    password: str
    # WebGoat-only fields (ignored for kind="dvwa").
    register_path: str | None = None
    prime_paths: list[str] = []


class EndpointSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["GET", "POST"]
    path: str
    query: dict[str, str] = {}
    form: dict[str, str] = {}
    expect_auth: bool = False
    notes: str | None = None
    # Per-endpoint trigger override. Some backends (e.g. WebGoat lesson API)
    # have a success signature that's independent of the payload body (a
    # JSON field like ``"attemptWasMade" : true``) — a single payload's
    # trigger can't match both that and the DVWA / Juice Shop sinks, so the
    # endpoint specifies its own. Falls back to ``payload.trigger`` when None.
    trigger: Trigger | None = None


class TargetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_path: str = ""
    login: LoginSpec | None = None
    endpoints: dict[VulnClass, EndpointSpec]


class Route(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str
    waf: str
    target: str


class TargetsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: dict[str, TargetSpec]
    routes: list[Route]

    def endpoint_for(self, target: str, vuln_class: VulnClass) -> EndpointSpec | None:
        spec = self.targets.get(target)
        if spec is None:
            return None
        return spec.endpoints.get(vuln_class)


_DEFAULT = Path(__file__).with_name("targets.yaml")


def load_targets(path: Path | None = None) -> TargetsConfig:
    data = yaml.safe_load((path or _DEFAULT).read_text())
    return TargetsConfig.model_validate(data)
