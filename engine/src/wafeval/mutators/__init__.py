"""Mutator registry.

Importing this subpackage causes every module with ``@register`` to populate
`REGISTRY`. Adding a sixth category = drop a new file here, decorate, done.
See ``docs/ADDING_MUTATORS.md``.
"""
from wafeval.mutators.base import REGISTRY, Mutator, register

# Import every concrete mutator module so its @register side-effect runs.
# Order matters only by complexity_rank for display — registration is by name.
from wafeval.mutators import lexical               # noqa: F401
from wafeval.mutators import encoding              # noqa: F401
from wafeval.mutators import structural            # noqa: F401
from wafeval.mutators import context_displacement  # noqa: F401
from wafeval.mutators import multi_request         # noqa: F401
from wafeval.mutators import adaptive              # noqa: F401
from wafeval.mutators import noop                  # noqa: F401

__all__ = ["REGISTRY", "Mutator", "register"]
