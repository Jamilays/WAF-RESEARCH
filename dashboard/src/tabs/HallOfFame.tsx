import { useEffect, useState } from "react";

type HofRow = {
  payload_id: string;
  variant: string;
  mutator: string;
  vuln_class: string;
  cells: number;
  bypasses: number;
  bypass_rate: number;
  waf_targets: string;
  body: string;
};

export default function HallOfFame({ runId }: { runId: string }) {
  const [rows, setRows] = useState<HofRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/runs/${runId}/hall-of-fame?top_n=50`)
      .then((r) => r.json())
      .then((d) => { if (!cancelled) setRows(d as HofRow[]); })
      .catch((e) => { if (!cancelled) setErr((e as Error).message); });
    return () => { cancelled = true; };
  }, [runId]);

  if (err) return <p className="text-rose-400 text-sm">error: {err}</p>;
  if (rows.length === 0) {
    return <p className="text-slate-500 text-sm">no baseline-confirmed bypasses for this run.</p>;
  }

  return (
    <div>
      <div className="mb-4 text-sm text-slate-400">
        Top {rows.length} mutator variants ranked by the number of (WAF × target)
        cells that let them through with verdict <span className="text-emerald-300">allowed</span>.
        Denominator counts only baseline-confirmed cells; a variant that
        baseline_fails everywhere doesn't appear.
      </div>
      <div className="rounded border border-slate-800 overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="text-left px-3 py-2">#</th>
              <th className="text-left px-3 py-2">payload · variant</th>
              <th className="text-left px-3 py-2">class · mutator</th>
              <th className="text-right px-3 py-2">bypasses</th>
              <th className="text-right px-3 py-2">rate</th>
              <th className="text-left px-3 py-2">waf × target</th>
              <th className="text-left px-3 py-2">body</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-t border-slate-800 hover:bg-slate-900/40">
                <td className="px-3 py-1.5 text-slate-500">{i + 1}</td>
                <td className="px-3 py-1.5 text-slate-200 font-semibold">
                  {r.payload_id}
                  <span className="text-slate-500"> · {r.variant}</span>
                </td>
                <td className="px-3 py-1.5 text-slate-400">
                  {r.vuln_class} · {r.mutator}
                </td>
                <td className="px-3 py-1.5 text-right text-emerald-300">
                  {r.bypasses}<span className="text-slate-500">/{r.cells}</span>
                </td>
                <td className="px-3 py-1.5 text-right text-slate-200">
                  {(r.bypass_rate * 100).toFixed(0)}%
                </td>
                <td className="px-3 py-1.5 text-slate-400 max-w-[18rem] truncate" title={r.waf_targets}>
                  {r.waf_targets}
                </td>
                <td className="px-3 py-1.5 text-slate-500 font-mono max-w-[24rem] truncate" title={r.body}>
                  {r.body}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
