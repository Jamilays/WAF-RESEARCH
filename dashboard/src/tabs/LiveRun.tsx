import { useEffect, useState } from "react";
import { api } from "../api";
import type { LiveSnapshot } from "../types";
import VerdictBadge from "../components/VerdictBadge";

const POLL_MS = 2000;

export default function LiveRun({ runId }: { runId: string }) {
  const [snap, setSnap] = useState<LiveSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const s = await api.live(runId, 30);
        if (!cancelled) { setSnap(s); setError(null); }
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      }
    }
    tick();
    const t = setInterval(tick, POLL_MS);
    return () => { cancelled = true; clearInterval(t); };
  }, [runId]);

  if (error)  return <p className="text-rose-400 text-sm">error: {error}</p>;
  if (!snap)  return <p className="text-slate-400 text-sm">loading…</p>;

  const progress = snap.expected
    ? Math.min(100, Math.round((snap.processed / snap.expected) * 100))
    : null;
  const hist = snap.histogram ?? {};

  return (
    <div className="space-y-6">
      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">progress</h2>
        <div className="flex items-center gap-3">
          <div className="w-full bg-slate-800 rounded h-3 overflow-hidden">
            <div
              className="h-full bg-sky-500 transition-all"
              style={{ width: progress != null ? `${progress}%` : "100%" }}
            />
          </div>
          <span className="text-xs text-slate-300 whitespace-nowrap">
            {snap.processed}{snap.expected ? ` / ${snap.expected}` : ""}{" "}
            {progress != null ? `(${progress}%)` : ""}
          </span>
        </div>
      </section>

      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">verdict histogram</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {Object.entries(hist).map(([k, v]) => (
            <div key={k} className="rounded border border-slate-800 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">{k}</div>
              <div className="text-2xl text-slate-100">{v}</div>
            </div>
          ))}
          {Object.keys(hist).length === 0 && (
            <div className="col-span-full text-xs text-slate-500">no datapoints yet</div>
          )}
        </div>
      </section>

      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">recent verdicts</h2>
        <div className="rounded border border-slate-800 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="text-left px-3 py-2">ts</th>
                <th className="text-left px-3 py-2">waf × target</th>
                <th className="text-left px-3 py-2">class · mutator</th>
                <th className="text-left px-3 py-2">variant</th>
                <th className="text-left px-3 py-2">verdict</th>
              </tr>
            </thead>
            <tbody>
              {snap.recent.map((r, i) => (
                <tr key={i} className="border-t border-slate-800 hover:bg-slate-900/40">
                  <td className="px-3 py-1.5 text-slate-500 whitespace-nowrap">
                    {r.timestamp?.slice(11, 19) ?? ""}
                  </td>
                  <td className="px-3 py-1.5 text-slate-300">{r.waf} × {r.target}</td>
                  <td className="px-3 py-1.5 text-slate-400">{r.vuln_class} · {r.mutator}</td>
                  <td className="px-3 py-1.5 text-slate-400 truncate max-w-[18rem]">
                    {r.payload_id} · {r.variant}
                  </td>
                  <td className="px-3 py-1.5"><VerdictBadge verdict={r.verdict} /></td>
                </tr>
              ))}
              {snap.recent.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-4 text-slate-500 text-center">
                  waiting for the first verdict…
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
