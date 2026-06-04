"""wafeval CLI — ``python -m wafeval`` / ``wafeval``."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import anyio
import structlog

from wafeval import __version__
from wafeval.models import VulnClass
from wafeval.runner import RunConfig, run
from wafeval.analyzer.aggregate import latest_run_id, load_run
from wafeval.analyzer.charts import render_all as render_charts
from wafeval.analyzer.combined import combine_runs
from wafeval.analyzer.export import write_csvs
from wafeval.analyzer.ladder import (
    build_fpr_table,
    build_ladder_table,
    render_ladder_chart,
    render_ladder_markdown,
)
from wafeval.reporter import (
    render_combined_latex,
    render_combined_markdown,
    render_consolidated,
    render_latex,
    render_markdown,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wafeval", description="WAF Evasion Lab engine")
    p.add_argument("--version", action="version", version=f"wafeval {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Execute one test run end-to-end")
    r.add_argument("--traefik-url", default=os.environ.get("TRAEFIK_URL", "http://127.0.0.1:8000"))
    r.add_argument(
        "--mutators", default="lexical",
        help="comma-separated mutator categories (registered in wafeval.mutators)",
    )
    r.add_argument(
        "--classes", default="sqli,xss",
        help="comma-separated vuln classes to load from the corpus",
    )
    r.add_argument(
        "--corpus", default=None,
        help="named corpus file to load verbatim from engine/src/wafeval/payloads/<name>.yaml "
             "(e.g. --corpus paper_subset). When set, the per-class split is bypassed; "
             "--classes still filters inside the single file. Default: load the per-class YAMLs.",
    )
    r.add_argument("--wafs", default=None, help="comma-separated WAFs (default: all)")
    r.add_argument("--targets", default=None, help="comma-separated targets (default: all)")
    r.add_argument("--max-concurrency", type=int, default=int(os.environ.get("MAX_CONCURRENCY", "10")))
    r.add_argument("--timeout", type=float, default=float(os.environ.get("REQUEST_TIMEOUT_S", "30")))
    r.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    r.add_argument("--run-id", default=None)
    r.add_argument(
        "--seed", type=int, default=None,
        help="seed Python's `random` at run start; recorded in manifest.json "
             "so any future randomised flow (sampling, GA mutator, tiebreaks) "
             "reproduces on rerun",
    )

    rep = sub.add_parser("report", help="Regenerate analyzer outputs + Markdown/LaTeX report")
    rep.add_argument("--run-id", default=None, help="run id under results/raw (default: latest)")
    rep.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    rep.add_argument("--processed-dir", type=Path, default=Path("results/processed"))
    rep.add_argument("--figures-dir", type=Path, default=Path("results/figures"))
    rep.add_argument("--reports-dir", type=Path, default=Path("results/reports"))
    rep.add_argument("--anchor-target", default="dvwa",
                     help="target whose baseline triggers anchor the true-bypass table")

    rc = sub.add_parser(
        "report-combined",
        help="Merge N runs into a single cross-run report (report-combined.md/.tex + bypass_rates.csv)",
    )
    rc.add_argument(
        "--run-ids", required=True,
        help="comma-separated run_ids to merge; later run_ids override earlier on WAF overlap",
    )
    rc.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    rc.add_argument("--processed-dir", type=Path, default=Path("results/processed"))
    rc.add_argument("--reports-dir", type=Path, default=Path("results/reports"))
    rc.add_argument("--out-id", default="combined",
                    help="directory name under processed/ and reports/ where the merged outputs land")
    rc.add_argument("--anchor-target", default="dvwa")

    la = sub.add_parser(
        "ladder",
        help="Render an ordered-ablation line chart (e.g. open-appsec "
             "min-confidence critical→low) from N runs.",
    )
    la.add_argument(
        "--steps", required=True,
        help="comma-separated step_label:run_id pairs; preserves order. "
             "Example: --steps critical:run-a,high:run-b,medium:run-c,low:run-d",
    )
    la.add_argument("--target", default="juiceshop",
                    help="target to anchor the ladder on (default: juiceshop — "
                         "more informative than DVWA where rates collapse to 0%)")
    la.add_argument("--lens", default="waf_view", choices=("true_bypass", "waf_view"))
    la.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    la.add_argument("--processed-dir", type=Path, default=Path("results/processed"))
    la.add_argument("--figures-dir", type=Path, default=Path("results/figures"))
    la.add_argument("--reports-dir", type=Path, default=Path("results/reports"))
    la.add_argument("--out-id", default="ladder",
                    help="directory under processed/, figures/, reports/ for the ladder artefacts")
    la.add_argument("--title", default="Ladder ablation")
    la.add_argument(
        "--fpr-steps", default=None,
        help="optional benign-corpus counterparts keyed on the same step labels, "
             "e.g. --fpr-steps pl1:bench-run-a,pl2:bench-run-b. Produces a second "
             "FPR table + dashed overlay lines on the chart.",
    )

    rh = sub.add_parser(
        "report-headline",
        help="Consolidated headline report — combines an attack run with optional "
             "adaptive (rank 6/7) and benign (FPR) runs into a single rich Markdown "
             "+ figures bundle anchored on the differentiating target.",
    )
    rh.add_argument("--attack-run-id", required=True,
                    help="canonical attack run (12 classes × 5 base mutators × all WAFs)")
    rh.add_argument("--adaptive-run-id", default=None,
                    help="run with mutators=adaptive,adaptive3 seeded on the attack run")
    rh.add_argument("--benign-run-id", default=None,
                    help="run with --classes benign --mutators noop, used for FPR overlay")
    rh.add_argument("--anchor-target", default="juiceshop",
                    help="target to anchor headline numbers on (default: juiceshop — "
                         "DVWA collapses to 0%% so it hides the differentiation)")
    rh.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    rh.add_argument("--reports-dir", type=Path, default=Path("results/reports"))
    rh.add_argument("--figures-dir", type=Path, default=Path("results/figures"))
    rh.add_argument("--out-id", default="headline",
                    help="directory name under reports/ and figures/ for the bundle")
    return p


def _configure_logging():
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
    )


def main(argv: list[str] | None = None) -> int:
    _configure_logging()
    args = _build_parser().parse_args(argv)

    if args.cmd == "run":
        classes = [VulnClass(c.strip()) for c in args.classes.split(",") if c.strip()]
        mutators = [m.strip() for m in args.mutators.split(",") if m.strip()]
        wafs = [w.strip() for w in args.wafs.split(",")] if args.wafs else None
        targets = [t.strip() for t in args.targets.split(",")] if args.targets else None

        cfg = RunConfig(
            traefik_url=args.traefik_url,
            mutators=mutators,
            classes=classes,
            wafs=wafs,
            targets=targets,
            max_concurrency=args.max_concurrency,
            request_timeout_s=args.timeout,
            results_root=args.results_root,
            run_id=args.run_id,
            corpus=args.corpus,
            seed=args.seed,
        )
        run_id = anyio.run(run, cfg)
        print(f"run_id={run_id} results={args.results_root / run_id}")
        return 0

    if args.cmd == "report":
        import json as _json
        run_id = args.run_id or latest_run_id(args.results_root)
        df = load_run(args.results_root, run_id)
        if df.empty:
            print(f"[report] no datapoints under {args.results_root / run_id}", file=sys.stderr)
            return 1

        processed_dir = args.processed_dir / run_id
        figures_dir = args.figures_dir / run_id
        report_dir = args.reports_dir / run_id

        csvs = write_csvs(df, processed_dir, anchor_target=args.anchor_target)
        figures = render_charts(df, figures_dir, target=args.anchor_target)

        manifest_path = args.results_root / run_id / "manifest.json"
        manifest = _json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

        md = render_markdown(
            df, report_dir / "report.md", run_id, figures,
            manifest=manifest, anchor_target=args.anchor_target,
        )
        tex = render_latex(
            df, report_dir / "report.tex", run_id, figures,
            manifest=manifest, anchor_target=args.anchor_target,
        )
        print(f"run_id={run_id}")
        for name, path in csvs.items():
            print(f"  csv.{name}: {path}")
        print(f"  figures: {len(figures)} files under {figures_dir}")
        print(f"  report.md: {md}")
        print(f"  report.tex: {tex}")
        return 0

    if args.cmd == "report-combined":
        run_ids = [r.strip() for r in args.run_ids.split(",") if r.strip()]
        if not run_ids:
            print("[report-combined] --run-ids is empty", file=sys.stderr)
            return 2

        df, provenance = combine_runs(args.results_root, run_ids)
        if df.empty:
            print(
                f"[report-combined] no datapoints across run_ids={run_ids} "
                f"under {args.results_root}",
                file=sys.stderr,
            )
            return 1

        processed_dir = args.processed_dir / args.out_id
        report_dir = args.reports_dir / args.out_id

        csvs = write_csvs(df, processed_dir, anchor_target=args.anchor_target)
        md = render_combined_markdown(
            df, provenance, report_dir / "report-combined.md",
            run_ids=run_ids, anchor_target=args.anchor_target,
        )
        tex = render_combined_latex(
            df, provenance, report_dir / "report-combined.tex",
            run_ids=run_ids, anchor_target=args.anchor_target,
        )
        print(f"out_id={args.out_id}")
        print(f"  merged run_ids: {', '.join(run_ids)}")
        print(f"  WAFs merged:    {', '.join(sorted(provenance))}")
        for name, path in csvs.items():
            print(f"  csv.{name}: {path}")
        print(f"  report-combined.md: {md}")
        print(f"  report-combined.tex: {tex}")
        return 0

    if args.cmd == "ladder":
        def _parse_steps(arg: str, flag_name: str) -> list[tuple[str, str]]:
            out: list[tuple[str, str]] = []
            for item in arg.split(","):
                item = item.strip()
                if not item:
                    continue
                if ":" not in item:
                    print(f"[ladder] bad {flag_name} {item!r}; expected label:run_id",
                          file=sys.stderr)
                    raise ValueError(item)
                label, rid = item.split(":", 1)
                out.append((label.strip(), rid.strip()))
            return out

        try:
            steps = _parse_steps(args.steps, "--steps")
        except ValueError:
            return 2
        if not steps:
            print("[ladder] --steps is empty", file=sys.stderr)
            return 2

        fpr_steps: list[tuple[str, str]] | None = None
        if getattr(args, "fpr_steps", None):
            try:
                fpr_steps = _parse_steps(args.fpr_steps, "--fpr-steps") or None
            except ValueError:
                return 2

        table = build_ladder_table(args.results_root, steps, target=args.target, lens=args.lens)
        if table.empty:
            print(f"[ladder] no datapoints across steps={steps} on target={args.target}",
                  file=sys.stderr)
            return 1

        fpr_table = None
        if fpr_steps is not None:
            fpr_table = build_fpr_table(args.results_root, fpr_steps, target=args.target)
            if fpr_table.empty:
                print(
                    f"[ladder] --fpr-steps supplied but benign corpus produced no rows on "
                    f"target={args.target}; check the fpr run_ids include `class=benign` records",
                    file=sys.stderr,
                )
                fpr_table = None

        processed_dir = args.processed_dir / args.out_id
        figures_dir = args.figures_dir / args.out_id
        report_dir = args.reports_dir / args.out_id
        processed_dir.mkdir(parents=True, exist_ok=True)
        table_csv = processed_dir / "ladder.csv"
        table.to_csv(table_csv, index=False)
        if fpr_table is not None:
            (processed_dir / "ladder-fpr.csv").write_text(fpr_table.to_csv(index=False))

        figures = render_ladder_chart(
            table, steps, figures_dir,
            stem="ladder", title=args.title,
            fpr_table=fpr_table,
        )
        md = render_ladder_markdown(
            table, steps, report_dir / "report-ladder.md",
            figures=figures, title=args.title,
            fpr_table=fpr_table, fpr_steps=fpr_steps,
        )
        print(f"out_id={args.out_id}")
        print(f"  target:         {args.target}")
        print(f"  lens:           {args.lens}")
        print(f"  steps:          {', '.join(f'{l}:{r}' for l, r in steps)}")
        if fpr_steps:
            print(f"  fpr_steps:      {', '.join(f'{l}:{r}' for l, r in fpr_steps)}")
        print(f"  csv.ladder:     {table_csv}")
        if fpr_table is not None:
            print(f"  csv.ladder-fpr: {processed_dir / 'ladder-fpr.csv'}")
        for p in figures:
            print(f"  figure:         {p}")
        print(f"  report-ladder.md: {md}")
        return 0

    if args.cmd == "report-headline":
        report_dir = args.reports_dir / args.out_id
        figures_dir = args.figures_dir / args.out_id
        try:
            md_path = render_consolidated(
                raw_root=args.results_root,
                attack_run_id=args.attack_run_id,
                adaptive_run_id=args.adaptive_run_id,
                benign_run_id=args.benign_run_id,
                out_dir=report_dir,
                figures_dir=figures_dir,
                anchor_target=args.anchor_target,
            )
        except FileNotFoundError as e:
            print(f"[report-headline] {e}", file=sys.stderr)
            return 1
        print(f"out_id={args.out_id}")
        print(f"  attack:    {args.attack_run_id}")
        print(f"  adaptive:  {args.adaptive_run_id or '(skipped)'}")
        print(f"  benign:    {args.benign_run_id or '(skipped)'}")
        print(f"  anchor:    {args.anchor_target}")
        print(f"  report:    {md_path}")
        print(f"  figures:   {figures_dir}")
        return 0

    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
