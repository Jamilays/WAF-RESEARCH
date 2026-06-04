"""Runtime environment capture for manifest.json.

Lets cross-machine runs be correlated after the fact: "this bypass rate
came from a run on kernel X with CPU Y on Python Z." Every field is
best-effort — if the filesystem probe fails (/proc missing on macOS,
Docker CLI absent inside the engine container, etc.) the field is just
omitted rather than crashing the run.

Kept narrow on purpose: hostname / username are privacy-sensitive and
don't add reproducibility signal, so they're excluded. Docker image
digests already live in docker-compose.yml (every image SHA256-pinned),
so capturing them here would be redundant.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from typing import Any

from wafeval import __version__


def capture_environment() -> dict[str, Any]:
    """Return a dict of reproducibility fields for the current run.

    Always present: ``platform`` (os + arch), ``python_version``,
    ``wafeval_version``. Best-effort: ``cpu_model``, ``cpu_count``,
    ``memory_total_gb``, ``docker_version``.
    """
    env: dict[str, Any] = {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "python_version": sys.version.split()[0],
        "wafeval_version": __version__,
    }

    cpu_model = _read_cpu_model()
    if cpu_model:
        env["cpu_model"] = cpu_model

    cpu_count = os.cpu_count()
    if cpu_count:
        env["cpu_count"] = cpu_count

    mem_gb = _read_mem_total_gb()
    if mem_gb is not None:
        env["memory_total_gb"] = mem_gb

    docker_version = _docker_version()
    if docker_version:
        env["docker_version"] = docker_version

    return env


def _read_cpu_model() -> str | None:
    """First ``model name`` line from /proc/cpuinfo (Linux-only)."""
    path = "/proc/cpuinfo"
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _read_mem_total_gb() -> float | None:
    """Parse ``MemTotal`` from /proc/meminfo, return GB (Linux-only)."""
    path = "/proc/meminfo"
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 * 1024), 2)
    except (OSError, ValueError):
        return None
    return None


def _docker_version() -> str | None:
    """``docker --version`` output, or None if docker CLI is unavailable.

    Returns None inside the engine container (no docker CLI on the
    wheel-installed image), which is fine — the containerised run will
    just record everything else and users can eyeball the image tag.
    """
    try:
        out = subprocess.check_output(
            ["docker", "--version"],
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        return out.decode().strip()
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
