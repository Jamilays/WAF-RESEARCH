# Adding a mutator

The mutator plugin interface lands in Phase 3 and is finalised in Phase 4.
Contract:

```python
# engine/src/wafeval/mutators/base.py
class Mutator(ABC):
    category: ClassVar[str]          # unique key, e.g. "lexical"
    complexity_rank: ClassVar[int]   # 1–5, used for ordering in the results table

    @abstractmethod
    def mutate(self, payload: Payload) -> list[MutatedPayload]: ...

REGISTRY: dict[str, type[Mutator]] = {}
def register(cls): REGISTRY[cls.category] = cls; return cls
```

## Single-request vs override-chain mutators

Three shapes are supported:

1. **String rewrite** (lexical, encoding, structural) — leave
   `request_overrides=None` on each `MutatedPayload`. The runner substitutes
   your mutated `body` into the default endpoint template from
   `engine/src/wafeval/targets.yaml` for the given `(target, vuln_class)`.

2. **Override chain** (context_displacement, multi_request) — populate
   `request_overrides` with one or more `RequestStep`s. The runner replays
   them in order, threading a shared cookie jar between steps, and evaluates
   the verdict against the *last* step's response.

3. **Compositional** (adaptive) — build a new `Payload` via
   `payload.model_copy(update={"payload": <variant_body>})` and re-invoke
   another registered mutator on it. Emit the stacked output as your own
   `MutatedPayload`s with a distinctive `variant` tag so the analyzer can
   trace the pair. See `mutators/adaptive.py` for the canonical example —
   it composes pairs of string-rewrite mutators, skips override-chain
   ones (their `request_overrides` lists can't round-trip through a
   second mutator's `payload.payload`-only interface), and optionally
   ranks pairs via `ADAPTIVE_SEED_RUN=<run_id>` using past bypass data.

`RequestStep` fields:

- `method` — `"GET"` or `"POST"`
- `path_override` — optional; falls back to the endpoint default path
- `query` — dict added as `?k=v`
- `form` — dict sent as `application/x-www-form-urlencoded`
- `json_body` — dict/list/str serialised as `application/json`
- `raw_body` + `content_type` — for text/plain, XML, etc.
- `file_fields` — `{name: (filename, content)}` multipart parts
- `headers` — override or add any header

## Steps to add a seventh category

1. Create `engine/src/wafeval/mutators/<name>.py`, subclass `Mutator`, pick
   a unique `category` and `complexity_rank` (7+; the adaptive compositional
   mutator currently holds rank 6). Update `analyzer/charts.py`'s x-axis
   range — `range(1, N+1)` — so the complexity line chart includes your
   rank.
2. Decorate with `@register`. Produce **≥5 variants per input payload** —
   the Phase 4 acceptance test enforces this invariant.
3. Import the module in `engine/src/wafeval/mutators/__init__.py` so the
   registration side-effect runs.
4. Add `engine/tests/test_<name>_mutator.py`. Cover:
   - registration under the category key
   - ≥5 variants for SQLi and XSS fixtures
   - variant-body distinctness from source
   - any class-specific invariants (encoding round-trip, multi-request
     destructive-safety, override-step shape)
5. If your variants use `request_overrides` to reach a novel transport
   (e.g. WebSocket upgrade, HTTP/2 pseudo-headers), add matching fields to
   `RequestStep` and the runner's `_build_httpx_kwargs` first.

## Safety

- Never emit a destructive variant — the `Payload` loader rejects inputs
  containing `DROP TABLE`, `rm -rf`, fork bombs, etc. Mutators that build
  multi-step chains (see `multi_request.py`) also re-scan each step's
  rendered body with the same list.
- Multi-step cookie jars are per-variant and disposed after the verdict is
  written; cross-variant state sharing is a Phase 5+ optimisation.
