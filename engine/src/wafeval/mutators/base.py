"""Mutator plugin interface.

Implements prompt.md §7 (Mutation Engine — pluggable architecture). A new
category = drop a new file in this directory, decorate with ``@register``,
return >=5 MutatedPayloads per input.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from wafeval.models import MutatedPayload, Payload

REGISTRY: dict[str, type["Mutator"]] = {}


def register(cls: type["Mutator"]) -> type["Mutator"]:
    """Class decorator registering a Mutator under its ``category`` key.

    Double-registration raises — it usually means two files set the same
    category by mistake.
    """
    if not issubclass(cls, Mutator):
        raise TypeError(f"{cls!r} is not a Mutator subclass")
    category = cls.category
    if category in REGISTRY:
        raise ValueError(
            f"mutator category {category!r} already registered by "
            f"{REGISTRY[category].__name__}; picked a duplicate name?"
        )
    REGISTRY[category] = cls
    return cls


class Mutator(ABC):
    category: ClassVar[str]
    complexity_rank: ClassVar[int]  # 1-5, per prompt.md §15

    @abstractmethod
    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        """Return >=1 MutatedPayloads. Paper requires >=5; enforced by tests."""
        raise NotImplementedError
