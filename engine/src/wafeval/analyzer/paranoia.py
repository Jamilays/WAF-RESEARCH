"""Paranoia-ablation pivot from a single run.

Given one DataFrame that contains *both* PL1 and PL4 variants of a WAF
(e.g. ``modsec`` + ``modsec-ph`` or ``coraza`` + ``coraza-ph``), produce a
side-by-side table of bypass rates and a delta column. This is the
single-run analogue of ``analyzer.ladder`` — the ladder module needs one
run_id per ablation step, but our headline scan deliberately includes
both PL levels in the same run, so we pivot in-frame instead.

Output shape:

    | family | mutator | rate_pl1 | rate_pl4 |   delta_pp | n_pl1 | n_pl4 |

``family`` is the operator-recognisable name (``modsec``, ``coraza``);
``rate_pl1`` / ``rate_pl4`` are the ``waf_view`` rates on the chosen
target. The reporter renders this as a table plus a small bar chart so
the "Coraza closes the JSON-SQL gap; ModSec env-var doesn't reach those
rules" finding is one glance away from the headline.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from wafeval.analyzer.bypass import compute_rates


# (PL1 waf-name, PL4 waf-name, display family) — the two CRS-derived
# WAFs the lab ships paranoia-high variants for.
_FAMILIES: tuple[tuple[str, str, str], ...] = (
    ("modsec", "modsec-ph", "ModSec"),
    ("coraza", "coraza-ph", "Coraza"),
)


@dataclass(frozen=True)
class ParanoiaRow:
    family: str
    mutator: str
    rate_pl1: float | None
    rate_pl4: float | None
    n_pl1: int
    n_pl4: int

    @property
    def delta_pp(self) -> float | None:
        if self.rate_pl1 is None or self.rate_pl4 is None:
            return None
        return (self.rate_pl4 - self.rate_pl1) * 100.0


def build_paranoia_table(
    df: pd.DataFrame,
    target: str = "juiceshop",
    lens: str = "waf_view",
    families: tuple[tuple[str, str, str], ...] = _FAMILIES,
) -> pd.DataFrame:
    """Pivot a single DataFrame into a (family, mutator) PL1-vs-PL4 table.

    Returns columns: ``family, mutator, rate_pl1, rate_pl4, delta_pp,
    n_pl1, n_pl4``. Rows where neither level produced data are dropped.
    Rows where one level is missing are kept with the missing rate as
    ``None`` (the reporter renders a dash there) — that's how we surface
    "this paranoia variant didn't run for this mutator" without silently
    omitting the mutator from the table.
    """
    if df.empty or "waf" not in df.columns:
        return pd.DataFrame(columns=[
            "family", "mutator", "rate_pl1", "rate_pl4",
            "delta_pp", "n_pl1", "n_pl4",
        ])

    sub = df[(df["target"] == target) & (df["waf"] != "baseline")]
    if sub.empty:
        return pd.DataFrame(columns=[
            "family", "mutator", "rate_pl1", "rate_pl4",
            "delta_pp", "n_pl1", "n_pl4",
        ])

    rates = compute_rates(sub, ["waf", "mutator"], lens=lens)
    if rates.empty:
        return pd.DataFrame(columns=[
            "family", "mutator", "rate_pl1", "rate_pl4",
            "delta_pp", "n_pl1", "n_pl4",
        ])

    out_rows: list[dict] = []
    for pl1, pl4, family in families:
        # Mutators present for *either* level — using the union keeps a
        # mutator visible even if one level didn't exercise it.
        mutators_pl1 = set(rates[rates["waf"] == pl1]["mutator"]) if pl1 in rates["waf"].unique() else set()
        mutators_pl4 = set(rates[rates["waf"] == pl4]["mutator"]) if pl4 in rates["waf"].unique() else set()
        mutators = mutators_pl1 | mutators_pl4
        for mut in sorted(mutators):
            r1 = rates[(rates["waf"] == pl1) & (rates["mutator"] == mut)]
            r4 = rates[(rates["waf"] == pl4) & (rates["mutator"] == mut)]
            rate_pl1 = float(r1["rate"].iloc[0]) if not r1.empty else None
            rate_pl4 = float(r4["rate"].iloc[0]) if not r4.empty else None
            n_pl1 = int(r1["n"].iloc[0]) if not r1.empty else 0
            n_pl4 = int(r4["n"].iloc[0]) if not r4.empty else 0
            delta = None
            if rate_pl1 is not None and rate_pl4 is not None:
                delta = (rate_pl4 - rate_pl1) * 100.0
            out_rows.append({
                "family": family,
                "mutator": mut,
                "rate_pl1": rate_pl1,
                "rate_pl4": rate_pl4,
                "delta_pp": delta,
                "n_pl1": n_pl1,
                "n_pl4": n_pl4,
            })

    return pd.DataFrame(out_rows)


def render_markdown(table: pd.DataFrame) -> str:
    """Format the paranoia table as a Markdown section."""
    if table.empty:
        return "*(no paranoia-high variants present in this run)*"

    lines = [
        "| Family | Mutator | PL1 rate | PL4 rate | Δ (pp) | n (PL1) | n (PL4) |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for _, r in table.iterrows():
        rate_pl1 = "—" if r["rate_pl1"] is None or pd.isna(r["rate_pl1"]) else f"{r['rate_pl1']*100:.1f}%"
        rate_pl4 = "—" if r["rate_pl4"] is None or pd.isna(r["rate_pl4"]) else f"{r['rate_pl4']*100:.1f}%"
        if r["delta_pp"] is None or pd.isna(r["delta_pp"]):
            delta = "—"
        else:
            d = float(r["delta_pp"])
            sign = "+" if d > 0 else ""
            delta = f"**{sign}{d:.1f}**" if abs(d) >= 5 else f"{sign}{d:.1f}"
        lines.append(
            f"| {r['family']} | `{r['mutator']}` | {rate_pl1} | {rate_pl4} "
            f"| {delta} | {int(r['n_pl1'])} | {int(r['n_pl4'])} |"
        )
    return "\n".join(lines)
