"""Analyzer — aggregates raw verdict records into bypass-rate tables + charts.

Implements prompt.md §9. Two lenses (see ``bypass.compute_rates``):

  true_bypass  — allowed / (allowed + blocked), conditional on baseline trigger
                (matches the paper's definition; DVWA is our anchor target)
  waf_view     — (non-blocked) / total, baseline-agnostic. Useful for
                context_displacement / multi_request variants where the
                transformed payload can't exploit the specific app but the
                WAF's response is still informative.
"""
from wafeval.analyzer.aggregate import load_run
from wafeval.analyzer.bypass import compute_rates, wilson_ci
from wafeval.analyzer.export import write_csvs
from wafeval.analyzer.latency import latency_stats

__all__ = ["load_run", "compute_rates", "wilson_ci", "write_csvs", "latency_stats"]
