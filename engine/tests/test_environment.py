"""Tests for runner/environment.py — reproducibility metadata capture.

Locks the contract: ``platform`` + ``python_version`` + ``wafeval_version``
are always present (they back the manifest-field invariants the paper
write-up depends on); everything else is best-effort and may be absent
on non-Linux hosts / inside the engine container.
"""
from __future__ import annotations

import builtins
import subprocess

import pytest

from wafeval import __version__
from wafeval.runner import environment as env_mod


def test_core_fields_always_present():
    env = env_mod.capture_environment()
    assert "platform" in env
    assert set(env["platform"]) == {"system", "release", "machine"}
    assert env["python_version"].startswith("3.")
    assert env["wafeval_version"] == __version__


def test_cpu_model_read_from_proc_when_available():
    # We're on Linux in CI + local dev, so the file should exist. If this
    # test ever runs on a non-Linux host, _read_cpu_model returns None —
    # assert accordingly.
    got = env_mod._read_cpu_model()
    import os
    if os.path.isfile("/proc/cpuinfo"):
        assert got, "/proc/cpuinfo exists but no model name line parsed"
        assert isinstance(got, str) and got.strip()
    else:
        assert got is None


def test_cpu_model_returns_none_when_proc_missing(monkeypatch):
    monkeypatch.setattr(env_mod.os.path, "isfile", lambda p: False)
    assert env_mod._read_cpu_model() is None


def test_cpu_model_tolerates_missing_field(monkeypatch, tmp_path):
    # /proc/cpuinfo exists but has no ``model name`` line (observed on some
    # ARM boards). Must return None, not raise.
    fake = tmp_path / "cpuinfo"
    fake.write_text("processor\t: 0\nflags\t\t: fpu\n")
    monkeypatch.setattr(env_mod, "_read_cpu_model", env_mod._read_cpu_model)
    monkeypatch.setattr(env_mod.os.path, "isfile",
                        lambda p: True if p == "/proc/cpuinfo" else False)
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open",
                        lambda p, *a, **kw: real_open(fake) if p == "/proc/cpuinfo"
                                           else real_open(p, *a, **kw))
    assert env_mod._read_cpu_model() is None


def test_memory_total_parse(monkeypatch, tmp_path):
    fake = tmp_path / "meminfo"
    fake.write_text("MemTotal:       16384000 kB\nMemFree: 1000 kB\n")
    monkeypatch.setattr(env_mod.os.path, "isfile",
                        lambda p: True if p == "/proc/meminfo" else False)
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open",
                        lambda p, *a, **kw: real_open(fake) if p == "/proc/meminfo"
                                           else real_open(p, *a, **kw))
    # 16_384_000 kB → 16384000 / (1024*1024) = 15.6249… → round(…, 2) = 15.62
    assert env_mod._read_mem_total_gb() == pytest.approx(15.62, abs=0.005)


def test_memory_returns_none_when_proc_missing(monkeypatch):
    monkeypatch.setattr(env_mod.os.path, "isfile", lambda p: False)
    assert env_mod._read_mem_total_gb() is None


def test_docker_version_absent_when_binary_missing(monkeypatch):
    def _raise(*a, **kw):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(subprocess, "check_output", _raise)
    assert env_mod._docker_version() is None


def test_docker_version_absent_on_timeout(monkeypatch):
    def _raise(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=2.0)
    monkeypatch.setattr(subprocess, "check_output", _raise)
    assert env_mod._docker_version() is None


def test_docker_version_strips_output(monkeypatch):
    monkeypatch.setattr(subprocess, "check_output",
                        lambda *a, **kw: b"Docker version 27.0.1, build abc\n")
    assert env_mod._docker_version() == "Docker version 27.0.1, build abc"


def test_capture_environment_has_cpu_count():
    env = env_mod.capture_environment()
    # os.cpu_count() returns None in truly degenerate environments — we
    # skip the field in that case. Assume CI / dev host has at least 1 CPU.
    assert env.get("cpu_count", 0) >= 1
