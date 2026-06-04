import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { CombinedResponse, RunSummary } from "../types";

// Preferred column order mirrors the engine-side reporter so the dashboard
// and the generated report agree on the headline WAF ordering.
const WAF_ORDER = ["modsec", "coraza", "shadowd", "openappsec", "modsec-ph", "coraza-ph"];

function orderWafs(wafs: string[]): string[] {
  const known = WAF_ORDER.filter((w) => wafs.includes(w));
  const extra = wafs.filter((w) => !WAF_ORDER.includes(w)).sort();
  return [...known, ...extra];
}

function heatColor(rate: number, baselineFailRate = 0): string {
  if (baselineFailRate > 0.5) return "rgb(60, 60, 60)";
  const r = Math.round(220 * rate + 30);
  const g = Math.round(200 * (1 - rate) + 30);
  return `rgb(${r}, ${g}, 60)`;
}

export default function CrossWAF({ runs }: { runs: RunSummary[] }) {
  // Default: select every run so the dashboard surfaces the full matrix on
  // first paint. User can whittle this down to pick canonical runs per WAF.
  const [selected, setSelected] = useState<string[]>([]);
  const [resp, setResp] = useState<CombinedResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [lens, setLens] = useState<"true_bypass" | "waf_view">("true_bypass");
  const [target, setTarget] = useState<string>("dvwa");

  useEffect(() => {
    if (runs.length === 0) return;
    // Default order: oldest → newest (last-in-list wins on the backend).
    // ``runs`` comes sorted newest-first, so reverse to get the provenance
    // order the aggregator expects.
    setSelected([...runs].reverse().map((r) => r.run_id));
  }, [runs]);

  useEffect(() => {
    if (selected.length === 0) { setResp(null); return; }
    let cancelled = false;
    api.combined(selected)
      .then((r) => { if (!cancelled) { setResp(r); setErr(null); } })
      .catch((e) => { if (!cancelled) setErr((e as Error).message); });
    return () => { cancelled = true; };
  }, [selected]);

  const toggle = (id: string) =>
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );

  const move = (id: string, dir: -1 | 1) =>
    setSelected((prev) => {
      const i = prev.indexOf(id);
      if (i < 0) return prev;
      const j = i + dir;
      if (j < 0 || j >= prev.length) return prev;
      const next = [...prev];
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });

  const filtered = useMemo(
    () => (resp?.rows ?? []).filter((r) =>
      r.lens === lens && (lens === "true_bypass" ? r.target === target : true)),
    [resp, lens, target],
  );

  const wafs = useMemo(() => orderWafs(resp?.wafs ?? []), [resp]);

  const mutators = useMemo(() => {
    const order = ["lexical", "encoding", "structural", "context_displacement", "multi_request"];
    const seen = new Set(filtered.map((r) => r.mutator));
    return order.filter((m) => seen.has(m)).concat(
      Array.from(seen).filter((m) => !order.includes(m)),
    );
  }, [filtered]);

  const targets = useMemo(() => {
    const seen = new Set((resp?.rows ?? [])
      .filter((r) => r.target)
      .map((r) => r.target as string));
    return Array.from(seen).sort();
  }, [resp]);

  const cell = (waf: string, mut: string, tgt?: string) =>
    filtered.find((r) =>
      r.waf === waf && r.mutator === mut &&
      (tgt === undefined ? true : r.target === tgt));

  return (
    <div className="space-y-6">
      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">
          run selection · last-in-list wins on WAF overlap
        </h2>
        <p className="text-xs text-slate-500 mb-3">
          Tick the runs you want to merge. Order from top to bottom is the
          provenance order sent to <code>GET /runs/combined</code> — if a WAF
          appears in multiple runs, the one lower in the list supplies its
          data. Use the arrows to reorder.
        </p>
        <ul className="inline-block rounded border border-slate-800 divide-y divide-slate-800 text-xs">
          {selected.map((id, i) => (
            <li key={id} className="flex items-center gap-2 px-3 py-1.5">
              <button
                className="text-slate-500 hover:text-slate-200 disabled:opacity-30"
                disabled={i === 0}
                onClick={() => move(id, -1)}
                title="move earlier (lower priority)"
              >↑</button>
              <button
                className="text-slate-500 hover:text-slate-200 disabled:opacity-30"
                disabled={i === selected.length - 1}
                onClick={() => move(id, 1)}
                title="move later (higher priority)"
              >↓</button>
              <span className="text-slate-300 font-mono">{id}</span>
              <button
                className="ml-2 text-rose-400 hover:text-rose-200"
                onClick={() => toggle(id)}
                title="remove from merge set"
              >✕</button>
            </li>
          ))}
          {runs.filter((r) => !selected.includes(r.run_id)).map((r) => (
            <li key={r.run_id} className="flex items-center gap-2 px-3 py-1.5 opacity-60">
              <button
                className="text-emerald-400 hover:text-emerald-200"
                onClick={() => toggle(r.run_id)}
                title="add to merge set"
              >+</button>
              <span className="text-slate-400 font-mono">{r.run_id}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="flex items-center gap-3 text-xs">
        <label className="flex items-center gap-2">
          <span className="text-slate-400">lens</span>
          <select
            value={lens}
            onChange={(e) => setLens(e.target.value as typeof lens)}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1"
          >
            <option value="true_bypass">true_bypass (DVWA anchor)</option>
            <option value="waf_view">waf_view (all targets)</option>
          </select>
        </label>
        {lens === "true_bypass" && targets.length > 1 && (
          <label className="flex items-center gap-2">
            <span className="text-slate-400">target</span>
            <select
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1"
            >
              {targets.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
        )}
      </section>

      {err && <p className="text-rose-400 text-xs">{err}</p>}

      {resp && (
        <>
          <section>
            <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">
              cross-WAF heatmap · {lens === "true_bypass" ? `${target} true-bypass` : "waf-view · all targets"}
            </h2>
            <div className="inline-block rounded border border-slate-800 overflow-hidden">
              {lens === "true_bypass" ? (
                <table className="text-xs">
                  <thead className="bg-slate-900 text-slate-400">
                    <tr>
                      <th className="px-3 py-2 text-left">mutator \ waf</th>
                      {wafs.map((w) => (
                        <th key={w} className="px-3 py-2 text-left whitespace-nowrap">
                          <span title={`provenance: ${resp.waf_provenance[w] ?? "—"}`}>{w}</span>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {mutators.map((m) => (
                      <tr key={m} className="border-t border-slate-800">
                        <td className="px-3 py-1.5 text-slate-300 font-semibold">{m}</td>
                        {wafs.map((w) => {
                          const c = cell(w, m, target);
                          if (!c) return <td key={w} className="px-3 py-1.5 text-slate-600">—</td>;
                          const bfr = c.baseline_fail_rate ?? 0;
                          const lowSignal = bfr > 0.5 || c.n < 5;
                          const title =
                            `run: ${resp.waf_provenance[w] ?? "—"}\n` +
                            `k=${c.k} n=${c.n}\n` +
                            `95% Wilson [${(c.ci_lo * 100).toFixed(1)}%, ${(c.ci_hi * 100).toFixed(1)}%]` +
                            (lowSignal ? "\n⚠ low-signal cell" : "");
                          return (
                            <td
                              key={w}
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
              ) : (
                // waf-view: emit mutator × waf rows per target, stacked
                <div className="divide-y divide-slate-800">
                  {targets.map((tgt) => (
                    <div key={tgt} className="p-2">
                      <h3 className="text-[11px] uppercase tracking-widest text-slate-500 mb-1 px-1">{tgt}</h3>
                      <table className="text-xs">
                        <thead className="bg-slate-900 text-slate-400">
                          <tr>
                            <th className="px-3 py-2 text-left">mutator \ waf</th>
                            {wafs.map((w) => (
                              <th key={w} className="px-3 py-2 text-left whitespace-nowrap">
                                <span title={`provenance: ${resp.waf_provenance[w] ?? "—"}`}>{w}</span>
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {mutators.map((m) => (
                            <tr key={m} className="border-t border-slate-800">
                              <td className="px-3 py-1.5 text-slate-300 font-semibold">{m}</td>
                              {wafs.map((w) => {
                                const c = cell(w, m, tgt);
                                if (!c) return <td key={w} className="px-3 py-1.5 text-slate-600">—</td>;
                                const lowSignal = c.n < 5;
                                const title =
                                  `run: ${resp.waf_provenance[w] ?? "—"}\n` +
                                  `k=${c.k} n=${c.n}\n` +
                                  `95% Wilson [${(c.ci_lo * 100).toFixed(1)}%, ${(c.ci_hi * 100).toFixed(1)}%]`;
                                return (
                                  <td
                                    key={w}
                                    className={
                                      "px-3 py-1.5 text-slate-900 font-semibold " +
                                      (lowSignal ? "opacity-60" : "")
                                    }
                                    style={{ backgroundColor: heatColor(c.rate) }}
                                    title={title}
                                  >
                                    {(c.rate * 100).toFixed(1)}%
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>

          <section>
            <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">
              provenance · which run supplied each WAF's numbers
            </h2>
            <div className="inline-block rounded border border-slate-800 overflow-hidden">
              <table className="text-xs">
                <thead className="bg-slate-900 text-slate-400">
                  <tr>
                    <th className="text-left px-3 py-2">waf</th>
                    <th className="text-left px-3 py-2">source run_id</th>
                  </tr>
                </thead>
                <tbody>
                  {[...wafs, ...(resp.waf_provenance["baseline"] ? ["baseline"] : [])].map((w) => (
                    <tr key={w} className="border-t border-slate-800">
                      <td className="px-3 py-1.5 text-slate-200 font-semibold">{w}</td>
                      <td className="px-3 py-1.5 text-slate-400 font-mono">
                        {resp.waf_provenance[w] ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {!resp && selected.length === 0 && (
        <p className="text-slate-500 text-sm">Select at least one run above to build the cross-WAF heatmap.</p>
      )}
    </div>
  );
}
