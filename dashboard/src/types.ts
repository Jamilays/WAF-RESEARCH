// Wire types — kept loose on purpose. The FastAPI backend is the source of
// truth; the dashboard is content to render whatever keys appear.

export type RunSummary = {
  run_id: string;
  started_at: string | null;
  mutators: string[];
  classes: string[];
  totals: Record<string, number>;
};

export type LiveSnapshot = {
  run_id: string;
  processed: number;
  expected: number | null;
  histogram: Record<string, number>;
  recent: LiveRecord[];
  manifest: Record<string, unknown>;
};

export type LiveRecord = {
  payload_id: string;
  variant: string;
  mutator: string;
  vuln_class: string;
  waf: string;
  target: string;
  verdict: string;
  timestamp: string;
};

export type BypassRateRow = {
  waf: string;
  mutator: string;
  target?: string;
  k: number;
  n: number;
  rate: number;
  ci_lo: number;
  ci_hi: number;
  lens: "true_bypass" | "waf_view";
  // Bundle-5 additions — share of datapoints in this cell where the baseline
  // didn't fire at all (corpus/target mismatch, not a WAF block). High values
  // mean the cell's "rate" isn't comparable across WAFs.
  baseline_fail_rate?: number;
  n_total?: number;
};

export type VariantRow = {
  run_id: string;
  waf: string;
  target: string;
  payload_id: string;
  vuln_class: string;
  mutator: string;
  variant: string;
  complexity_rank: number;
  verdict: string;
  baseline_status: number | null;
  waf_status: number | null;
  notes: string | null;
};

export type VariantListResponse = {
  total: number;
  limit: number;
  offset: number;
  rows: VariantRow[];
};

export type RecordDetail = {
  run_id: string;
  waf: string;
  target: string;
  payload_id: string;
  vuln_class: string;
  variant: string;
  mutator: string;
  complexity_rank: number;
  mutated_body: string;
  verdict: string;
  baseline: RouteResult;
  waf_route: RouteResult;
  notes: string | null;
};

export type RouteResult = {
  route: string;
  status_code: number | null;
  response_ms: number | null;
  response_bytes: number | null;
  response_snippet: string | null;
  error: string | null;
  notes: string | null;
  // WAF-identifying response headers captured by the engine (name → value).
  // Records predating the schema change don't ship the key; treat as {}.
  waf_headers?: Record<string, string>;
};

export type CompareRow = {
  waf: string;
  mutator: string;
  rate_a: number | null;
  rate_b: number | null;
  delta: number | null;
  k_a: number | null;
  n_a: number | null;
  k_b: number | null;
  n_b: number | null;
};

export type CompareResponse = {
  a: string;
  b: string;
  rows: CompareRow[];
};

export type CombinedResponse = {
  run_ids: string[];
  waf_provenance: Record<string, string>;
  wafs: string[];
  rows: BypassRateRow[];
};
