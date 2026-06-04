# Adding payloads

The payload schema is finalised in Phase 3 and lives at
`engine/src/wafeval/models.py::Payload`. Shape of each YAML entry:

```yaml
- id: sqli-union-001
  class: sqli              # sqli | xss | cmdi | lfi | ssti | xxe | nosql |
                           # ldap | ssrf | jndi | graphql | crlf | benign
  payload: "' UNION SELECT null,version()-- -"
  trigger:                 # how to confirm baseline fired — see below
    kind: any_of
    any_of:
      - { kind: contains, needle: "First name" }
      - { kind: regex, pattern: "SQLITE_ERROR|syntax error" }
  cwe: CWE-89
  source: "PayloadsAllTheThings / sqli/union.txt"
  notes: "Classic union-based SQLi against DVWA 'id' param."
```

Trigger kinds: `contains`, `regex`, `reflected`, `status`, `any_of`
(see `models.py` for exact fields). Destructive patterns (DROP TABLE,
rm -rf, fork bombs, `/etc/shadow`) are rejected at load time by a
`Payload.payload` field validator.

## Where the files live

`engine/src/wafeval/payloads/<class>.yaml` — one file per vuln class.
The default loader (`load_corpus`) iterates VulnClass and loads
whichever files exist. If you add a new class, add an enum value in
`models.py::VulnClass` and ship the matching YAML.

### Corpus inventory (post-Phase-7+ expansion)

| Class | Count | Class | Count |
|---|---:|---|---:|
| sqli | 42 | nosql | 25 |
| xss | 35 | ldap | 25 |
| ssti | 25 | ssrf | 25 |
| xxe | 25 | jndi | 25 |
| crlf | 25 | graphql | 25 |
| cmdi | 15 | lfi | 15 |
| benign | 15 | | |

297 attack payloads + 15 benign. Eight thin classes were taken from
10–15 entries each up to 25 each in the 2026-04-29 expansion to give
every class enough Wilson-CI-narrow datapoints to support the consolidated
headline reporter's per-class drill-down.

## Single-file corpora

Some runs need a *fixed* curated subset rather than the full per-class
split — e.g. apples-to-apples paper replication. Drop a standalone file
into the same dir (e.g. `payloads/paper_subset.yaml`), populate it with
self-contained entries, and invoke the engine with
`--corpus paper_subset`. Inside the file, every entry still declares its
`class:` (so `--classes sqli` filters the single-file output too).
Duplicating content from the per-class files is deliberate: a fixed
subset shouldn't drift when the main corpus grows.

The `benign` corpus is a related case — it's loaded via
`--classes benign` rather than `--corpus` because it shares the
per-class-file convention, but it's excluded from default runs because
`VulnClass.BENIGN` is never in the default `[SQLI, XSS]` filter.

## When a class has no real backend sink

SSTI, XXE, GraphQL, JNDI, LDAP, NoSQL, SSRF, and CRLF do not have a
genuine vulnerable backend in the lab — DVWA / WebGoat / Juice Shop
were not built to be exploited via Jinja templates or XML entities,
so the *attack* never actually fires. The lab still exercises these
classes as a **WAF-view-only** measurement: we route the payload
through a reflective sink (DVWA's `/vulnerabilities/xss_r/`, Juice
Shop's `/rest/products/search`, or WebGoat's `SqlInjection/attack2`
lesson) with a per-endpoint trigger of `{ kind: status, code: 200 }`.

The trigger fires for any 200 response, which means: "the request
reached the application's reflective sink — the WAF either let it
through (`allowed`) or blocked it (`blocked`)". The waf-view bypass
rate is then `allowed / (allowed + blocked)` per WAF, which is the
question we actually want to answer for these classes ("does the WAF
recognise the *shape* of an SSTI / XXE / SSRF payload on the wire?").

The trigger override lives in `targets.yaml` per `(target, class)` —
it overrides whatever per-payload trigger the YAML entry declares.
That keeps individual payload triggers honest in contexts that *do*
have a real sink (e.g. a future XXE-aware endpoint) without
duplicating trigger configs across YAMLs.

## A note on cmdi / lfi DVWA triggers

DVWA *does* have real cmdi and LFI sinks, but the per-payload regex
triggers (`uid=\d+`, `root:`) were producing 83% / 94% baseline_fail
in earlier runs. Two reasons:

- DVWA's PHP shells out to `/bin/sh` (dash on Debian), not bash.
  The brace-expansion (`{cat,/etc/passwd}`) and `${IFS}` payloads in
  the corpus expand differently under dash and so `cat` never runs,
  the trigger never fires, and the row is recorded as `baseline_fail`.
- DVWA has `open_basedir` set in the PHP config, so relative
  `../../../../etc/passwd` traversals don't actually leak the file
  even at security=low. Only the absolute `/etc/passwd` path works.

Rather than rewrite every cmdi / LFI payload to be dash- and
open-basedir-safe (which would lose the WAF-detection signal — those
payloads are exactly the kind a WAF *should* catch), `targets.yaml`
overrides the trigger to `{ kind: status, code: 200 }` for cmdi and
lfi on DVWA. Same justification as the WAF-view-only classes: we are
measuring whether the WAF recognises the payload shape, not whether
the OS actually executed the appended command.
