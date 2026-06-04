import { useEffect, useState } from "react";
import { api } from "./api";
import type { RunSummary } from "./types";
import LiveRun from "./tabs/LiveRun";
import Results from "./tabs/Results";
import PayloadExplorer from "./tabs/PayloadExplorer";
import CompareRuns from "./tabs/CompareRuns";
import HallOfFame from "./tabs/HallOfFame";
import CrossWAF from "./tabs/CrossWAF";

type Tab = "live" | "results" | "hof" | "explorer" | "compare" | "crosswaf";

const TABS: { id: Tab; label: string }[] = [
  { id: "live",     label: "Live Run" },
  { id: "results",  label: "Results" },
  { id: "crosswaf", label: "Cross-WAF" },
  { id: "hof",      label: "Hall of Fame" },
  { id: "explorer", label: "Payload Explorer" },
  { id: "compare",  label: "Compare Runs" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("live");
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [apiStatus, setApiStatus] = useState<"ok" | "down" | "unknown">("unknown");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await api.health();
        if (!cancelled) setApiStatus("ok");
        const r = await api.runs();
        if (cancelled) return;
        setRuns(r);
        if (r.length > 0) setRunId(r[0].run_id);
      } catch {
        if (!cancelled) setApiStatus("down");
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-900/60 backdrop-blur">
        <div>
          <h1 className="text-lg font-semibold text-sky-300">WAF Evasion Lab</h1>
          <p className="text-xs text-slate-400">
            Phase 6 dashboard · read-only view over <span className="text-slate-200">results/</span>
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className={
            apiStatus === "ok"   ? "text-emerald-400" :
            apiStatus === "down" ? "text-rose-400"    : "text-slate-400"
          }>
            api {apiStatus === "ok" ? "online" : apiStatus === "down" ? "unreachable" : "…"}
          </span>
          <label className="flex items-center gap-2">
            <span className="text-slate-400">run:</span>
            <select
              value={runId ?? ""}
              onChange={(e) => setRunId(e.target.value || null)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-100"
            >
              {runs.length === 0 && <option value="">— no runs —</option>}
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>{r.run_id}</option>
              ))}
            </select>
          </label>
        </div>
      </header>

      <nav className="border-b border-slate-800 px-6 bg-slate-900/40">
        <div className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={
                "px-4 py-2 text-sm rounded-t transition-colors " +
                (tab === t.id
                  ? "bg-slate-800 text-sky-300 border-x border-t border-slate-700"
                  : "text-slate-400 hover:text-slate-200")
              }
            >
              {t.label}
            </button>
          ))}
        </div>
      </nav>

      <main className="p-6">
        {apiStatus === "down" && (
          <div className="mb-4 rounded border border-rose-700 bg-rose-950/40 p-3 text-rose-200 text-sm">
            API unreachable. Check that <code className="text-rose-100">api</code> is up
            (`docker compose --profile dashboard up -d`) and
            <code className="ml-1 text-rose-100">/api/health</code> returns 200.
          </div>
        )}
        {tab === "live"     && runId && <LiveRun    runId={runId} />}
        {tab === "results"  && runId && <Results   runId={runId} />}
        {tab === "crosswaf" && <CrossWAF runs={runs} />}
        {tab === "hof"      && runId && <HallOfFame runId={runId} />}
        {tab === "explorer" && runId && <PayloadExplorer runId={runId} />}
        {tab === "compare"  && <CompareRuns runs={runs} />}
        {!runId && apiStatus === "ok" && (
          <p className="text-slate-400 text-sm">
            No runs found under <span className="text-slate-200">results/raw</span>.
            Run <code>make run</code> to seed one.
          </p>
        )}
      </main>
    </div>
  );
}
