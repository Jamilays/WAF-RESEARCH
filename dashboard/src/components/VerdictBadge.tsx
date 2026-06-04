const COLORS: Record<string, string> = {
  allowed:        "bg-rose-500/20 text-rose-300 border-rose-600",
  blocked:        "bg-emerald-500/20 text-emerald-300 border-emerald-600",
  blocked_silent: "bg-teal-500/20 text-teal-300 border-teal-600",
  flagged:        "bg-amber-500/20 text-amber-300 border-amber-600",
  baseline_fail:  "bg-slate-700/40 text-slate-300 border-slate-600",
  error:          "bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-600",
};

export default function VerdictBadge({ verdict }: { verdict: string }) {
  const c = COLORS[verdict] ?? "bg-slate-800 text-slate-300 border-slate-700";
  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] rounded border ${c}`}>
      {verdict}
    </span>
  );
}
