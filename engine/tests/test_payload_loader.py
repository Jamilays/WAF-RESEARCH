"""Corpus loader tests — schema + destructive-pattern rejection."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from wafeval.models import VulnClass
from wafeval.payloads.loader import load_corpus, load_yaml_file


def test_seed_corpus_loads():
    corpus = load_corpus(classes=[VulnClass.SQLI, VulnClass.XSS])
    assert len(corpus) >= 20, f"expected ≥20 sqli+xss payloads, got {len(corpus)}"
    ids = {p.id for p in corpus}
    assert len(ids) == len(corpus), "duplicate payload IDs in seed corpus"


def test_full_corpus_meets_charter_minima():
    """prompt.md §6: SQLi≥25, XSS≥25, cmdi≥15, LFI≥15, SSTI≥10, XXE≥10 = 100+."""
    minima = {
        VulnClass.SQLI: 25, VulnClass.XSS: 25, VulnClass.CMDI: 15,
        VulnClass.LFI: 15, VulnClass.SSTI: 10, VulnClass.XXE: 10,
    }
    for cls, n in minima.items():
        got = len(load_corpus(classes=[cls]))
        assert got >= n, f"{cls.value}: {got} payloads, charter requires ≥{n}"
    assert len(load_corpus()) >= 100


def test_every_payload_has_trigger():
    corpus = load_corpus(classes=[VulnClass.SQLI, VulnClass.XSS])
    for p in corpus:
        assert p.trigger is not None


def test_rejects_destructive(tmp_path: Path):
    bad = tmp_path / "evil.yaml"
    bad.write_text(yaml.safe_dump([{
        "id": "x",
        "class": "sqli",
        "payload": "1'; DROP TABLE users --",
        "trigger": {"kind": "contains", "needle": "y"},
    }]))
    with pytest.raises(Exception):
        load_yaml_file(bad)


def test_missing_requested_class_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_corpus(classes=[VulnClass.XXE], corpus_dir=tmp_path)


# ---------- paper_subset / named-corpus (single-file) loader ----------------


def test_paper_subset_is_20_sqli_plus_20_xss():
    """The replication subset is a fixed point: 20 SQLi + 20 XSS exactly.

    Drift here would silently invalidate the apples-to-apples vs-paper
    comparison the subset exists for, so the test pins the count."""
    corpus = load_corpus(corpus_name="paper_subset")
    assert len(corpus) == 40
    counts = {}
    for p in corpus:
        counts[p.vuln_class] = counts.get(p.vuln_class, 0) + 1
    assert counts == {VulnClass.SQLI: 20, VulnClass.XSS: 20}, counts


def test_paper_subset_filters_by_class():
    sqli_only = load_corpus(corpus_name="paper_subset", classes=[VulnClass.SQLI])
    assert len(sqli_only) == 20
    assert all(p.vuln_class is VulnClass.SQLI for p in sqli_only)


def test_named_corpus_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_corpus(corpus_name="does-not-exist", corpus_dir=tmp_path)
