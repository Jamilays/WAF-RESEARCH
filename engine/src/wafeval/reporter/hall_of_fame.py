"""Per-payload "hall of fame" — payloads ranked by how many (WAF × target)
cells they got allowed through.

Attached to the Markdown reporter so every generated ``report.md`` lists
the top-N most effective payloads alongside the mutator × WAF rate table.
Helpful for reviewers who want concrete exploit strings to cite rather
than aggregate percentages.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd


def hall_of_fame(df: pd.DataFrame, top_n: int = 20,
                  dedup_by_payload: bool = False) -> pd.DataFrame:
    """Return the top ``top_n`` (payload × variant) rows sorted by bypass count.

    A row in the returned frame represents one mutator variant of one
    source payload and tallies:
      - ``bypasses`` — cells where the variant was ``allowed`` against a
        non-baseline WAF. A higher number means more WAFs leaked it.
      - ``cells`` — the count of (waf, target) cells that reached a
        baseline-confirmed verdict (so the denominator is comparable).
      - ``waf_targets`` — a short human-readable list of which (waf,target)
        cells let the variant through.

    ``dedup_by_payload=True`` keeps only the *best* variant per source
    payload (highest bypass count, ties broken by bypass rate). Useful for
    the headline gallery where eleven variants of ``admin'-- -`` taking
    rows 2-12 isn't more informative than one entry showing ``admin'-- -``
    with its winning mutator. The full per-variant ranking stays
    available via ``dedup_by_payload=False`` (the default, kept for the
    per-run reporter).
    """
    if df.empty:
        return pd.DataFrame(columns=["payload_id", "variant", "mutator",
                                     "vuln_class", "cells", "bypasses",
                                     "bypass_rate", "waf_targets", "body"])

    non_baseline = df[df["waf"] != "baseline"]
    # Only count a (variant × waf × target) cell if the baseline actually
    # fired — otherwise "allowed" is baseline_fail disguised.
    eligible = non_baseline[non_baseline["verdict"].isin(
        ["allowed", "blocked", "blocked_silent", "flagged"]
    )]

    if eligible.empty:
        return pd.DataFrame(columns=["payload_id", "variant", "mutator",
                                     "vuln_class", "cells", "bypasses",
                                     "bypass_rate", "waf_targets", "body"])

    grouped = (
        eligible
        .assign(allowed=(eligible["verdict"] == "allowed").astype(int))
        .groupby(["payload_id", "variant", "mutator", "vuln_class"], as_index=False)
        .agg(
            cells=("verdict", "count"),
            bypasses=("allowed", "sum"),
            # Sample mutated body — first one we see is representative.
            body=("mutated_body", lambda s: (next(iter(s), "") or "")[:120]),
        )
    )

    # Concatenate the set of (waf, target) cells that let it through.
    def _wt(sub: pd.DataFrame) -> str:
        hits = sub[sub["verdict"] == "allowed"]
        if hits.empty:
            return ""
        return ", ".join(sorted(
            f"{r['waf']}×{r['target']}" for _, r in hits.iterrows()
        ))

    wt = (
        eligible.groupby(["payload_id", "variant", "mutator", "vuln_class"])
        .apply(_wt, include_groups=False)
        .reset_index(name="waf_targets")
    )
    grouped = grouped.merge(wt, on=["payload_id", "variant", "mutator", "vuln_class"])

    grouped["bypass_rate"] = grouped["bypasses"] / grouped["cells"].clip(lower=1)

    ranked = grouped.sort_values(["bypasses", "bypass_rate"], ascending=[False, False])

    if dedup_by_payload:
        # Keep the row with the highest (bypasses, bypass_rate) per payload_id.
        # The sort above already orders by that key, so ``drop_duplicates`` on
        # ``payload_id`` keeps the leader of each group.
        ranked = ranked.drop_duplicates("payload_id", keep="first")

    return ranked.head(top_n).reset_index(drop=True)


def render_markdown(rows: pd.DataFrame) -> str:
    """Format the hall-of-fame dataframe as a Markdown section."""
    if rows.empty:
        return "*(no variant reached a baseline-confirmed bypass)*"
    lines = ["| # | payload / variant | class · mutator | bypasses | cells | body |",
             "|---:|---|---|---:|---:|---|"]
    for i, r in rows.iterrows():
        body = r["body"].replace("|", "\\|").replace("\n", "\\n")
        if len(body) > 80:
            body = body[:77] + "…"
        lines.append(
            f"| {i+1} | `{r['payload_id']}` / `{r['variant']}` "
            f"| {r['vuln_class']} · {r['mutator']} "
            f"| **{int(r['bypasses'])}** / {int(r['cells'])} "
            f"| {r['bypass_rate']*100:.0f}% "
            f"| `{body}` |"
        )
    return "\n".join(lines)


def write_markdown_section(df: pd.DataFrame, out_path: Path, top_n: int = 20) -> Path:
    """Render the hall-of-fame section to ``out_path`` as a standalone file."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = hall_of_fame(df, top_n=top_n)
    body = render_markdown(rows)
    out_path.write_text(
        f"# Hall of Fame — top {top_n} WAF-evading variants\n\n"
        "Variants are ranked by the number of (WAF × target) cells that "
        "let them through as an `allowed` verdict. Ties broken by raw "
        "bypass rate. Only baseline-confirmed cells count toward either "
        "metric — a variant that baseline_fails everywhere doesn't appear.\n\n"
        f"{body}\n"
    )
    return out_path
