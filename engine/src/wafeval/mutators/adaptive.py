"""Adaptive (compositional) mutator.

Stacks pairs of the three string-body base mutators (``lexical``,
``encoding``, ``structural``) to produce variants no single category can
reach. The core research hypothesis (TODO.md #1 "adaptive / genetic
mutator"): a WAF tuned to catch, say, single-layer URL encoding can still
be defeated by lexical casing *applied on top of* encoded output — and the
lab should be able to systematically produce those stacks.

Two modes, both invoked via the standard ``Mutator`` contract
(``mutate(payload) -> list[MutatedPayload]``). The engine instantiates
mutators with no args, so parameters come in through env vars.

* **Default (no seed)** — emit every ordered (A, B) pair where A != B,
  capped by ``ADAPTIVE_TOP_K`` (default 6 = all pairs). Variant count per
  payload is bounded by ``_A_PER_PAIR`` × ``_B_PER_PAIR`` × number of
  pairs. With defaults: 6 × 3 × 2 = 36 variants max, deduplicated to
  usually ~20 after overlap.
* **Seed-ranked (``ADAPTIVE_SEED_RUN=<run_id>``)** — load that run's
  per-mutator bypass rate (``k/n`` from the analyzer), rank the pairs by
  the product ``rate(A) × rate(B)``, then emit the top-K. Pairs whose
  component mutators didn't appear in the seed run get rate 0 and rank
  last. This is the "observe, then compose the winners" story from TODO.

Skipped: ``context_displacement`` and ``multi_request`` — their
``request_overrides`` chains carry RequestStep lists that are not simply
re-inputable as ``payload.payload`` strings. Composing those with string
mutators would require a new cross-mutator interface and is out of scope
for this iteration.
"""
from __future__ import annotations

import os
from functools import cache
from pathlib import Path
from typing import ClassVar

from wafeval.models import MutatedPayload, Payload
from wafeval.mutators.base import REGISTRY, Mutator, register


# Only the string-body mutators compose cleanly (see module docstring).
_COMPOSABLE_BASES: tuple[str, ...] = ("lexical", "encoding", "structural")

# Per-pair caps keep the combinatorial explosion bounded.
# 6 pairs × _A_PER_PAIR × _B_PER_PAIR is the upper bound per payload.
_A_PER_PAIR = 3
_B_PER_PAIR = 2

# Per-triple caps. 6 permutations × _A × _B × _C upper bound per payload.
# Tighter than the pair caps because the body size grows combinatorially
# (encoding of encoding of encoding = URL-quad-encoded) and we want the
# total variant budget per payload bounded to ~40 after dedup.
_A_PER_TRIPLE = 2
_B_PER_TRIPLE = 2
_C_PER_TRIPLE = 1


def _parse_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _rate_by_mutator_from_seed(seed_run: str, results_root: str) -> dict[str, float] | None:
    """Load per-mutator waf_view bypass rates from a prior run.

    Returns None if the seed run is missing / empty / analyser deps
    unavailable. Shared between pair-ranker and triple-ranker so both
    rank off identical data.
    """
    # Late import so the mutator module load doesn't drag pandas in
    # unless ranking is actually requested.
    try:
        from wafeval.analyzer.aggregate import load_run
        from wafeval.analyzer.bypass import compute_rates
    except Exception:  # pragma: no cover — optional dep path
        return None

    try:
        df = load_run(Path(results_root), seed_run)
    except (FileNotFoundError, ValueError):
        return None
    if df.empty:
        return None

    waf_only = df[df["waf"] != "baseline"]
    rates = compute_rates(waf_only, ["mutator"], lens="waf_view")
    return {row["mutator"]: row["rate"] for _, row in rates.iterrows()}


@cache
def _rank_pairs(seed_run: str | None, results_root: str) -> list[tuple[str, str]]:
    """Return ordered (A, B) pairs, ranked by observed bypass likelihood.

    Cached on (seed_run, results_root) so repeated instantiations of
    ``AdaptiveMutator`` during one engine run only load the seed data
    once. Falls back to a fixed alphabetical ordering when no seed is
    available, so variant streams are deterministic across runs.
    """
    pairs = [(a, b) for a in _COMPOSABLE_BASES for b in _COMPOSABLE_BASES if a != b]
    if not seed_run:
        return pairs

    rate_by_mutator = _rate_by_mutator_from_seed(seed_run, results_root)
    if not rate_by_mutator:
        return pairs

    def score(pair: tuple[str, str]) -> float:
        return rate_by_mutator.get(pair[0], 0.0) * rate_by_mutator.get(pair[1], 0.0)

    # Sort descending by score; ties keep the fixed-order fallback so the
    # output is deterministic run-to-run.
    return sorted(pairs, key=lambda p: (-score(p), p))


@cache
def _rank_triples(
    seed_run: str | None, results_root: str,
) -> list[tuple[str, str, str]]:
    """Return ordered (A, B, C) triples over distinct composable bases.

    Cross-product over ``_COMPOSABLE_BASES`` with ``A != B != C != A``.
    With three bases there are ``3! = 6`` permutations. Seed-ranked by
    ``rate(A) × rate(B) × rate(C)`` when the seed run exists, with a
    fixed lexicographic fallback.
    """
    triples = [
        (a, b, c)
        for a in _COMPOSABLE_BASES
        for b in _COMPOSABLE_BASES
        for c in _COMPOSABLE_BASES
        if a != b and b != c and a != c
    ]
    if not seed_run:
        return triples

    rate_by_mutator = _rate_by_mutator_from_seed(seed_run, results_root)
    if not rate_by_mutator:
        return triples

    def score(t: tuple[str, str, str]) -> float:
        return (
            rate_by_mutator.get(t[0], 0.0)
            * rate_by_mutator.get(t[1], 0.0)
            * rate_by_mutator.get(t[2], 0.0)
        )

    return sorted(triples, key=lambda t: (-score(t), t))


@register
class AdaptiveMutator(Mutator):
    """Compose two string-body base mutators; optionally rank by seed run."""

    category: ClassVar[str] = "adaptive"
    complexity_rank: ClassVar[int] = 6

    def __init__(self) -> None:
        self._seed_run = os.environ.get("ADAPTIVE_SEED_RUN") or None
        self._results_root = os.environ.get("RESULTS_ROOT", "results/raw")
        self._top_k = _parse_env_int("ADAPTIVE_TOP_K", len(_COMPOSABLE_BASES) * (len(_COMPOSABLE_BASES) - 1))

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        pairs = _rank_pairs(self._seed_run, self._results_root)[: max(1, self._top_k)]

        out: list[MutatedPayload] = []
        seen_bodies: set[str] = {payload.payload}

        for a_name, b_name in pairs:
            a = REGISTRY[a_name]()
            b = REGISTRY[b_name]()

            # Skip any A-variant that carries request_overrides; composing
            # on a RequestStep chain doesn't round-trip through the second
            # mutator's payload.payload-only interface.
            a_variants = [v for v in a.mutate(payload) if v.request_overrides is None][:_A_PER_PAIR]

            for av in a_variants:
                intermediate = payload.model_copy(update={"payload": av.body})
                b_variants = [v for v in b.mutate(intermediate) if v.request_overrides is None][:_B_PER_PAIR]

                for bv in b_variants:
                    if bv.body in seen_bodies:
                        continue
                    seen_bodies.add(bv.body)
                    out.append(MutatedPayload(
                        source_id=payload.id,
                        variant=f"{a_name}>{av.variant}|{b_name}>{bv.variant}",
                        mutator=self.category,
                        complexity_rank=self.complexity_rank,
                        body=bv.body,
                    ))

        return out


@register
class AdaptiveTripleMutator(Mutator):
    """Compose THREE string-body base mutators; optionally seed-ranked.

    Rank 7 — slots above ``AdaptiveMutator`` on the complexity ladder.
    Enumerates ordered triples ``(A, B, C)`` over
    ``{lexical, encoding, structural}`` where ``A != B != C != A`` (6
    permutations). With ``ADAPTIVE_SEED_RUN`` set, orders the triples
    by ``rate(A) × rate(B) × rate(C)`` so the most-likely-to-bypass
    combinations come first; otherwise falls back to lexicographic
    permutation order.

    Per-slot variant caps (``_A_PER_TRIPLE``, ``_B_PER_TRIPLE``,
    ``_C_PER_TRIPLE``) keep the per-payload variant count bounded to
    ~40 after dedup — important because each composition layer can
    expand the body size (URL-encode of URL-encode of …), so unbounded
    fan-out here would blow up runtime.

    ``ADAPTIVE_TOP_K_TRIPLES`` caps the triple count for faster
    iteration; default is all 6.
    """

    category: ClassVar[str] = "adaptive3"
    complexity_rank: ClassVar[int] = 7

    def __init__(self) -> None:
        self._seed_run = os.environ.get("ADAPTIVE_SEED_RUN") or None
        self._results_root = os.environ.get("RESULTS_ROOT", "results/raw")
        # 6 = 3! permutations of distinct elements from the three bases.
        self._top_k = _parse_env_int("ADAPTIVE_TOP_K_TRIPLES", 6)

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        triples = _rank_triples(self._seed_run, self._results_root)[: max(1, self._top_k)]

        out: list[MutatedPayload] = []
        seen_bodies: set[str] = {payload.payload}

        for a_name, b_name, c_name in triples:
            a = REGISTRY[a_name]()
            b = REGISTRY[b_name]()
            c = REGISTRY[c_name]()

            a_variants = [v for v in a.mutate(payload) if v.request_overrides is None][:_A_PER_TRIPLE]

            for av in a_variants:
                intermediate_ab = payload.model_copy(update={"payload": av.body})
                b_variants = [v for v in b.mutate(intermediate_ab) if v.request_overrides is None][:_B_PER_TRIPLE]

                for bv in b_variants:
                    intermediate_bc = payload.model_copy(update={"payload": bv.body})
                    c_variants = [v for v in c.mutate(intermediate_bc) if v.request_overrides is None][:_C_PER_TRIPLE]

                    for cv in c_variants:
                        if cv.body in seen_bodies:
                            continue
                        seen_bodies.add(cv.body)
                        out.append(MutatedPayload(
                            source_id=payload.id,
                            variant=f"{a_name}>{av.variant}|{b_name}>{bv.variant}|{c_name}>{cv.variant}",
                            mutator=self.category,
                            complexity_rank=self.complexity_rank,
                            body=cv.body,
                        ))

        return out
