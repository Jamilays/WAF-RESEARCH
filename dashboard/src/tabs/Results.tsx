import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { BypassRateRow } from "../types";

function heatColor(rate: number, baselineFailRate = 0): string {
  // Gray out cells whose baseline barely fired — the "rate" is statistical
  // noise, not a meaningful signal about the WAF.
  if (baselineFailRate > 0.5) return "rgb(60, 60, 60)";
  // interpolate green (low bypass → WAF wins) → red (high bypass)
  const r = Math.round(220 * rate + 30);
  const g = Math.round(200 * (1 - rate) + 30);
  return `rgb(${r}, ${g}, 60)`;
}

export default function Results({ runId }: { runId: string }) {
  const [rows, setRows] = useState<BypassRateRow[]>([]);
  const [err,  setErr]  = useState<string | null>(null);
  const [lens, setLens] = useState<"true_bypass" | "waf_view">("true_bypass");

  useEffect(() => {
    let cancelled = false;
    api.bypass(runId)
      .then((r) => { if (!cancelled) setRows(r); })
      .catch((e) => { if (!cancelled) setErr((e as Error).message); });
    return () => { cancelled = true; };
  }, [runId]);

  const filtered = useMemo(() => rows.filter((r) => r.lens === lens), [rows, lens]);
  const wafs = useMemo(() => Array.from(new Set(filtered.map((r) => r.waf))).sort(), [filtered]);
  const mutators = useMemo(() => {
    // keep complexity ordering (lexical < encoding < structural < context_displacement < multi_request)
    const order = ["lexical", "encoding", "structural", "context_displacement", "multi_request"];
    const seen = new Set(filtered.map((r) => r.mutator));
    return order.filter((m) => seen.has(m)).concat(
      Array.from(seen).filter((m) => !order.includes(m)),
    );
  }, [filtered]);

  const cell = (waf: string, mut: string) =>
    filtered.find((r) => r.waf === waf && r.mutator === mut);

  if (err) return <p className="text-rose-400 text-sm">error: {err}</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <span className="text-xs text-slate-400">lens</span>
        <select
          value={lens}
          onChange={(e) => setLens(e.target.value as typeof lens)}
          className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm"
        >
          <option value="true_bypass">true_bypass (DVWA anchor)</option>
          <option value="waf_view">waf_view (all targets)</option>
        </select>
      </div>

      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">heatmap · bypass rate</h2>
        <div className="inline-block rounded border border-slate-800 overflow-hidden">
          <table className="text-xs">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="px-3 py-2 text-left">waf \ mutator</th>
                {mutators.map((m) => (
                  <th key={m} className="px-3 py-2 text-left whitespace-nowrap">{m}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {wafs.map((w) => (
                <tr key={w} className="border-t border-slate-800">
                  <td className="px-3 py-1.5 text-slate-300 font-semibold">{w}</td>
                  {mutators.map((m) => {
                    const c = cell(w, m);
                    if (!c) return <td key={m} className="px-3 py-1.5 text-slate-600">—</td>;
                    const bfr = c.baseline_fail_rate ?? 0;
                    const lowSignal = bfr > 0.5 || c.n < 5;
                    const title =
                      `k=${c.k} n=${c.n}\n` +
                      `95% Wilson [${(c.ci_lo * 100).toFixed(1)}%, ${(c.ci_hi * 100).toFixed(1)}%]\n` +
                      `baseline_fail share: ${(bfr * 100).toFixed(1)}% of ${c.n_total ?? "?"} datapoints` +
                      (lowSignal ? "\n⚠ low-signal cell — interpret with care" : "");
                    return (
                      <td
                        key={m}
                        className={
                          "px-3 py-1.5 text-slate-900 font-semibold " +
                          (lowSignal ? "opacity-60" : "")
                        }
                        style={{ backgroundColor: heatColor(c.rate, bfr) }}
                        title={title}
                      >
                        {(c.rate * 100).toFixed(1)}%
                        {lowSignal && <sup className="ml-0.5 text-slate-900/70">⚠</sup>}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">table · all rows</h2>
        <div className="rounded border border-slate-800 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="text-left px-3 py-2">waf</th>
                <th className="text-left px-3 py-2">mutator</th>
                {lens === "waf_view" && <th className="text-left px-3 py-2">target</th>}
                <th className="text-right px-3 py-2">k</th>
                <th className="text-right px-3 py-2">n</th>
                <th className="text-right px-3 py-2">rate</th>
                <th className="text-left px-3 py-2">95% CI</th>
                <th className="text-right px-3 py-2 whitespace-nowrap" title="share of datapoints where baseline didn't fire — high values mean the cell is a corpus/target mismatch, not a WAF block">
                  baseline_fail %
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr key={i} className="border-t border-slate-800 hover:bg-slate-900/40">
                  <td className="px-3 py-1.5 text-slate-200">{r.waf}</td>
                  <td className="px-3 py-1.5 text-slate-400">{r.mutator}</td>
                  {lens === "waf_view" && (
                    <td className="px-3 py-1.5 text-slate-400">{r.target}</td>
                  )}
                  <td className="px-3 py-1.5 text-right text-slate-400">{r.k}</td>
                  <td className="px-3 py-1.5 text-right text-slate-400">{r.n}</td>
                  <td className="px-3 py-1.5 text-right text-slate-100">
                    {(r.rate * 100).toFixed(1)}%
                  </td>
                  <td className="px-3 py-1.5 text-slate-500">
                    [{(r.ci_lo * 100).toFixed(1)}, {(r.ci_hi * 100).toFixed(1)}]
                  </td>
                  <td className={"px-3 py-1.5 text-right " + ((r.baseline_fail_rate ?? 0) > 0.3 ? "text-amber-300" : "text-slate-500")}>
                    {r.baseline_fail_rate != null ? `${(r.baseline_fail_rate * 100).toFixed(0)}%` : "—"}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={lens === "waf_view" ? 9 : 8} className="px-3 py-4 text-slate-500 text-center">
                  no rows for this lens
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
