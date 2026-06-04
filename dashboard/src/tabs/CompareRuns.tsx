import { useEffect, useState } from "react";
import { api } from "../api";
import type { CompareResponse, RunSummary } from "../types";

export default function CompareRuns({ runs }: { runs: RunSummary[] }) {
  const [a, setA] = useState<string>("");
  const [b, setB] = useState<string>("");
  const [resp, setResp] = useState<CompareResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (runs.length < 2) return;
    setA(runs[1].run_id);
    setB(runs[0].run_id);
  }, [runs]);

  useEffect(() => {
    if (!a || !b) return;
    let cancelled = false;
    api.compare(a, b)
      .then((r) => { if (!cancelled) { setResp(r); setErr(null); } })
      .catch((e) => { if (!cancelled) setErr((e as Error).message); });
    return () => { cancelled = true; };
  }, [a, b]);

  const dColor = (d: number | null) => {
    if (d == null) return "text-slate-500";
    if (d > 0.05)  return "text-rose-400";
    if (d < -0.05) return "text-emerald-400";
    return "text-slate-400";
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <label className="flex items-center gap-2">
          <span className="text-slate-400">a</span>
          <select value={a} onChange={(e) => setA(e.target.value)}
                  className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
            {runs.map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2">
          <span className="text-slate-400">b</span>
          <select value={b} onChange={(e) => setB(e.target.value)}
                  className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
            {runs.map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id}</option>)}
          </select>
        </label>
      </div>
      {err && <p className="text-rose-400 text-xs">{err}</p>}
      {resp && (
        <div className="rounded border border-slate-800 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="text-left px-3 py-2">waf</th>
                <th className="text-left px-3 py-2">mutator</th>
                <th className="text-right px-3 py-2">rate a</th>
                <th className="text-right px-3 py-2">rate b</th>
                <th className="text-right px-3 py-2">Δ</th>
                <th className="text-left px-3 py-2">n a / n b</th>
              </tr>
            </thead>
            <tbody>
              {resp.rows.map((r, i) => (
                <tr key={i} className="border-t border-slate-800 hover:bg-slate-900/40">
                  <td className="px-3 py-1.5 text-slate-200">{r.waf}</td>
                  <td className="px-3 py-1.5 text-slate-400">{r.mutator}</td>
                  <td className="px-3 py-1.5 text-right text-slate-300">
                    {r.rate_a == null ? "—" : `${(r.rate_a * 100).toFixed(1)}%`}
                  </td>
                  <td className="px-3 py-1.5 text-right text-slate-300">
                    {r.rate_b == null ? "—" : `${(r.rate_b * 100).toFixed(1)}%`}
                  </td>
                  <td className={"px-3 py-1.5 text-right font-semibold " + dColor(r.delta)}>
                    {r.delta == null ? "—" :
                      `${r.delta >= 0 ? "+" : ""}${(r.delta * 100).toFixed(1)}%`}
                  </td>
                  <td className="px-3 py-1.5 text-slate-500">
                    {r.n_a ?? 0} / {r.n_b ?? 0}
                  </td>
                </tr>
              ))}
              {resp.rows.length === 0 && (
                <tr><td colSpan={6} className="px-3 py-4 text-slate-500 text-center">no comparable rows</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
