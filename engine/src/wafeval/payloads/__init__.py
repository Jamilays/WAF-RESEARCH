"""Payload corpus + loader.

Phase 3 ships a small seed corpus (SQLi + XSS) sufficient to validate the
mutator → runner → verdict pipeline end-to-end. The full 100+ corpus across
6 vuln classes (prompt.md §6) lands in Phase 4.
"""
from wafeval.payloads.loader import load_corpus, load_yaml_file

__all__ = ["load_corpus", "load_yaml_file"]
