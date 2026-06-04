"""Entrypoint: ``python -m wafeval.api`` or ``uvicorn wafeval.api:app --factory``."""
from __future__ import annotations

import os

import uvicorn

from wafeval.api.app import build_app


def main() -> None:
    host = os.environ.get("API_HOST", "127.0.0.1")
    port = int(os.environ.get("API_PORT", "8001"))
    uvicorn.run(build_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
