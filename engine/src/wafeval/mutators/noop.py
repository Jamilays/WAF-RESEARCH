"""Pass-through mutator — emits the payload verbatim.

Used for benign-corpus runs (FPR / ROC measurement): a real user never
submits ``ApPlE jUiCE`` to a product search, so stacking the lexical or
encoding mutators on top of benign payloads would conflate "WAF over-
blocks realistic traffic" with "WAF over-blocks weird-but-benign
traffic". The noop mutator keeps benign bodies byte-identical to the
YAML corpus so the measured BLOCKED fraction is a clean false-positive
rate.

Returns exactly one MutatedPayload per input. The paper's ≥5-variants
rule applies to attack mutators only — noop intentionally doesn't
synthesise variants, so the per-mutator test suite for noop drops that
assertion.
"""
from __future__ import annotations

from typing import ClassVar

from wafeval.models import MutatedPayload, Payload
from wafeval.mutators.base import Mutator, register


@register
class NoOpMutator(Mutator):
    category: ClassVar[str] = "noop"
    # Rank 0 = "no mutation at all"; slots below lexical (rank 1). Matters
    # only for the complexity-vs-rate line chart, which skips ranks it
    # doesn't see in the data (range(1, 7) stays correct for attack runs).
    complexity_rank: ClassVar[int] = 0

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        return [MutatedPayload(
            source_id=payload.id,
            variant="identity",
            mutator=self.category,
            complexity_rank=self.complexity_rank,
            body=payload.payload,
        )]
