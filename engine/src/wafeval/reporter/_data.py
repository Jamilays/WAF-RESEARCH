"""Shared fixtures the MD and LaTeX reporters both consume.

  PAPER_TABLE1      — Yusifova (2024) §Results, Table 1 aggregate bypass
                      rates per mutator category. Used for delta cells.
  BIBLIOGRAPHY      — the six references from the paper (prompt.md §10).
  MUTATOR_SECTIONS  — short prose headings for each mutator in the report.
"""
from __future__ import annotations

# Paper numbers (approximate, as quoted in prompt.md §15):
#   lexical ~12%, encoding ~27%, structural ~46%, context_displacement ~62%,
#   multi_request ~80%. Aggregate across WAFs in the paper.
PAPER_TABLE1: dict[str, float] = {
    "lexical":              0.12,
    "encoding":             0.27,
    "structural":           0.46,
    "context_displacement": 0.62,
    "multi_request":        0.80,
}

MUTATOR_SECTIONS: list[tuple[str, str]] = [
    ("lexical",
     "Case permutation, whitespace inflation, inline comments (`/**/`), "
     "clause reordering. Complexity rank 1."),
    ("encoding",
     "URL single/double percent-encoding, Unicode escapes, HTML entities, "
     "base64 reconstruction, stacked layers. Complexity rank 2."),
    ("structural",
     "`CONCAT`/`CHAR` literal splitting, hex literals, JS "
     "`String.fromCharCode` + `atob(eval(…))`. Complexity rank 3."),
    ("context_displacement",
     "Payload relocated to JSON body, XML attribute, custom header, "
     "multipart field, or cookie. Complexity rank 4."),
    ("multi_request",
     "Exploit split across N sequential requests with shared session cookies. "
     "Non-destructive only. Complexity rank 5."),
]

BIBLIOGRAPHY: list[str] = [
    "Yusifova, J. (2024). *Evasion of Web Application Firewalls Through Payload "
    "Obfuscation: A Black-Box Study.* MSc thesis / technical report.",
    "OWASP ModSecurity Core Rule Set Project. *CRS v4.*  "
    "https://coreruleset.org/",
    "The Coraza Project. *Coraza Web Application Firewall.*  "
    "https://coraza.io/",
    "Zeppelin Cure. *Shadow Daemon.*  https://shadowd.zecure.org/",
    "Check Point Software. *open-appsec.*  https://www.openappsec.io/",
    "PortSwigger. *Web Security Academy — Client-side / SQL Injection.*  "
    "https://portswigger.net/web-security",
]
