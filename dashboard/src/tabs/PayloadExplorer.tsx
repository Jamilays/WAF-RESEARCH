import { useEffect, useState } from "react";
import { api } from "../api";
import type { RecordDetail, VariantRow } from "../types";
import VerdictBadge from "../components/VerdictBadge";

const VERDICTS = ["", "allowed", "blocked", "blocked_silent", "flagged", "baseline_fail", "error"];

// Every vuln_class the engine currently ships. Keeping them in one place
// here means a user can pick "nosql" from the dropdown instead of typing,
// and new classes (Phase 7+) land as a one-line addition.
const VULN_CLASSES = [
  "", "sqli", "xss", "cmdi", "lfi", "ssti", "xxe",
  "nosql", "ldap", "ssrf", "jndi", "graphql", "crlf",
];

const MUTATORS = [
  "", "lexical", "encoding", "structural", "context_displacement", "multi_request",
];

export default function PayloadExplorer({ runId }: { runId: string }) {
  const [filters, setFilters] = useState({
    waf: "", target: "", vuln_class: "", mutator: "", verdict: "",
  });
  const [rows, setRows] = useState<VariantRow[]>([]);
  const [total, setTotal] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<VariantRow | null>(null);
  const [detail, setDetail] = useState<RecordDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.variants(runId, { ...filters, limit: 200 })
      .then((r) => { if (!cancelled) { setRows(r.rows); setTotal(r.total); } })
      .catch((e) => { if (!cancelled) setErr((e as Error).message); });
    return () => { cancelled = true; };
  }, [runId, filters]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    let cancelled = false;
    api.record(runId, selected.waf, selected.target, selected.payload_id, selected.variant)
      .then((d) => { if (!cancelled) setDetail(d); })
      .catch((e) => { if (!cancelled) setErr((e as Error).message); });
    return () => { cancelled = true; };
  }, [runId, selected]);

  const setF = (k: keyof typeof filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setFilters((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">
          filters · {rows.length}/{total} rows
        </h2>
        <div className="flex flex-wrap gap-2 mb-3 text-xs">
          {(["waf", "target"] as const).map((k) => (
            <input
              key={k}
              placeholder={k}
              value={filters[k]}
              onChange={setF(k)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 w-28"
            />
          ))}
          <select
            value={filters.vuln_class}
            onChange={setF("vuln_class")}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1"
            title="filter by vuln class"
          >
            {VULN_CLASSES.map((v) => <option key={v} value={v}>{v || "any class"}</option>)}
          </select>
          <select
            value={filters.mutator}
            onChange={setF("mutator")}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1"
            title="filter by mutator"
          >
            {MUTATORS.map((v) => <option key={v} value={v}>{v || "any mutator"}</option>)}
          </select>
          <select
            value={filters.verdict}
            onChange={setF("verdict")}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1"
            title="filter by verdict"
          >
            {VERDICTS.map((v) => <option key={v} value={v}>{v || "any verdict"}</option>)}
          </select>
        </div>
        {err && <p className="text-rose-400 text-xs mb-2">{err}</p>}
        <div className="rounded border border-slate-800 overflow-hidden max-h-[70vh] overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="bg-slate-900 text-slate-400 sticky top-0">
              <tr>
                <th className="text-left px-2 py-1.5">waf × target</th>
                <th className="text-left px-2 py-1.5">payload</th>
                <th className="text-left px-2 py-1.5">variant</th>
                <th className="text-left px-2 py-1.5">verdict</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr
                  key={i}
                  onClick={() => setSelected(r)}
                  className={
                    "border-t border-slate-800 cursor-pointer " +
                    (selected === r ? "bg-slate-800/60" : "hover:bg-slate-900/40")
                  }
                >
                  <td className="px-2 py-1 text-slate-300">{r.waf} × {r.target}</td>
                  <td className="px-2 py-1 text-slate-400 truncate max-w-[12rem]">{r.payload_id}</td>
                  <td className="px-2 py-1 text-slate-500 truncate max-w-[12rem]">{r.variant}</td>
                  <td className="px-2 py-1"><VerdictBadge verdict={r.verdict} /></td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={4} className="px-2 py-4 text-slate-500 text-center">no matches</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="text-sm text-slate-400 uppercase tracking-widest mb-2">detail</h2>
        {!selected && <p className="text-slate-500 text-sm">pick a row to drill in.</p>}
        {selected && !detail && <p className="text-slate-500 text-sm">loading…</p>}
        {detail && (
          <div className="space-y-4 text-xs">
            <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
              <div className="flex items-center gap-2 mb-2">
                <VerdictBadge verdict={detail.verdict} />
                <span className="text-slate-300">
                  {detail.waf} × {detail.target} · {detail.vuln_class} · {detail.mutator} (rank {detail.complexity_rank})
                </span>
              </div>
              <div className="text-slate-400">payload <span className="text-slate-200">{detail.payload_id}</span> · variant <span className="text-slate-200">{detail.variant}</span></div>
            </div>
            <div>
              <div className="text-slate-400 mb-1">mutated body</div>
              <pre className="bg-slate-900/60 border border-slate-800 rounded p-3 whitespace-pre-wrap break-all">
                {detail.mutated_body}
              </pre>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <div className="text-slate-400 mb-1">baseline — {detail.baseline.status_code ?? "—"}</div>
                <pre className="bg-slate-900/60 border border-slate-800 rounded p-3 max-h-64 overflow-auto whitespace-pre-wrap break-all">
                  {detail.baseline.response_snippet ?? detail.baseline.error ?? ""}
                </pre>
              </div>
              <div>
                <div className="text-slate-400 mb-1">{detail.waf} — {detail.waf_route.status_code ?? "—"}</div>
                <pre className="bg-slate-900/60 border border-slate-800 rounded p-3 max-h-64 overflow-auto whitespace-pre-wrap break-all">
                  {detail.waf_route.response_snippet ?? detail.waf_route.error ?? ""}
                </pre>
                {detail.waf_route.waf_headers && Object.keys(detail.waf_route.waf_headers).length > 0 && (
                  <div className="mt-2">
                    <div className="text-slate-400 mb-1">waf headers</div>
                    <table className="w-full text-[11px] border border-slate-800 rounded overflow-hidden">
                      <tbody>
                        {Object.entries(detail.waf_route.waf_headers).map(([k, v]) => (
                          <tr key={k} className="border-t border-slate-800 first:border-t-0">
                            <td className="px-2 py-1 text-slate-400 align-top whitespace-nowrap">{k}</td>
                            <td className="px-2 py-1 text-slate-200 font-mono break-all">{v}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
