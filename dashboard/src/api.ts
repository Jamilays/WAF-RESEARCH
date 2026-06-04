// Thin fetch wrapper. Base URL is /api in prod (nginx proxies) and also
// /api in dev (Vite proxy). VITE_API_BASE lets the smoke test override it.
import type {
  BypassRateRow, CombinedResponse, CompareResponse, LiveSnapshot,
  RecordDetail, RunSummary, VariantListResponse,
} from "./types";

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";

async function j<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
  }
  const r = await fetch(url.toString());
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} @ ${path}`);
  return (await r.json()) as T;
}

export const api = {
  health:    ()                 => j<{ status: string; version: string }>("/health"),
  runs:      ()                 => j<RunSummary[]>("/runs"),
  latest:    ()                 => j<RunSummary>("/runs/latest"),
  manifest:  (id: string)       => j<RunSummary>(`/runs/${id}`),
  live:      (id: string, tail = 20) => j<LiveSnapshot>(`/runs/${id}/live`, { tail }),
  bypass:    (id: string)       => j<BypassRateRow[]>(`/runs/${id}/bypass-rates`),
  variants:  (id: string, filters: Record<string, string | number | undefined>) =>
               j<VariantListResponse>(`/runs/${id}/per-variant`, filters),
  record:    (id: string, waf: string, target: string, pid: string, variant: string) =>
               j<RecordDetail>(`/runs/${id}/records/${waf}/${target}/${pid}/${variant}`),
  compare:   (a: string, b: string) =>
               j<CompareResponse>("/runs/compare", { a, b }),
  combined:  (ids: string[]) =>
               j<CombinedResponse>("/runs/combined", { ids: ids.join(",") }),
};
