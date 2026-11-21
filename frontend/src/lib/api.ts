// Typed client for the local ThreatWeaver API. Every request carries the per-session token
// that the server embeds in index.html; no other credentials exist.

const token =
  document.querySelector<HTMLMetaElement>('meta[name="tw-token"]')?.content ?? "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-ThreatWeaver-Token": token };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(res.status, `Unexpected response from ${path}`);
  }
  if (!res.ok) {
    const msg = (data as { error?: string; detail?: unknown })?.error ?? `Request failed (${res.status})`;
    throw new ApiError(res.status, typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  del: <T,>(path: string) => request<T>("DELETE", path),
};

// ------------------------------------------------------------------ response types

export interface DatasetSummary {
  available: boolean;
  reason?: string;
  samples?: number;
  benign?: number;
  malicious?: number;
  unique_samples?: number;
  unique_benign?: number;
  unique_malicious?: number;
  total_bytes?: number;
  time_span?: string[];
  verified?: boolean;
}

export interface DetectorInfo {
  kind: "lightgbm" | "legacy" | "none";
  id: string;
  tau_low: number;
  tau_high: number;
  rules_active: boolean;
}

export interface Status {
  version: string;
  model_version: string;
  model_kind: string | null;
  residual_blocks: number | null;
  embedding_dim: number | null;
  temperature: number | null;
  architecture: string;
  model_loaded: boolean;
  checkpoint_path: string | null;
  dataset: DatasetSummary;
  detector?: DetectorInfo;
  device: string;
  novelty_threshold: number | null;
  quarantine_count: number;
  total_files_scanned: number;
  suspicious_count: number;
  unfamiliar_count: number;
  protection_mode: string;
  protection_note: string;
}

export interface ExplanationGroup {
  group: string;
  label: string;
  contribution: number;
  direction: string;
}

export interface Explanation {
  units: string;
  bias: number;
  raw_score: number;
  groups: ExplanationGroup[];
}

export interface ScanResultDto {
  file_path: string;
  file_name: string;
  file_size_bytes: number;
  sha256: string;
  verdict: string;
  malware_probability: number;
  novelty_score: number;
  is_novel: boolean;
  evidence_points: string[];
  scan_duration_ms: number;
  model_version: string;
  triage_stage?: string;
  nearest_known_cluster?: string | null;
  warning_message?: string | null;
  explanation?: Explanation | null;
}

export interface ScanEvents {
  scan_seq: number;
  is_scanning: boolean;
  completed: number;
  total: number;
  current_file: string;
  is_full_system: boolean;
  target_path: string;
  results_count: number;
  next: number;
  new_results: ScanResultDto[];
}

export interface HistoryRecord {
  scan_id: string;
  target_path: string;
  timestamp: string;
  duration_seconds: number;
  model_version?: string;
  summary: Record<string, number>;
  results?: ScanResultDto[];
}

export interface DetectionRow {
  scan_id: string;
  timestamp: string;
  file_path: string;
  file_name: string;
  sha256: string;
  verdict: string;
  malware_probability: number;
}

export interface QuarantineEntry {
  quarantine_id: string;
  original_path: string;
  original_filename: string;
  file_size_bytes: number;
  sha256: string;
  quarantined_at: string;
  restored: boolean;
  restored_at: string | null;
  reason: string;
}

export interface Family {
  id: string;
  name: string;
  sample_count: number;
  mean_family_confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  file_types: Record<string, number>;
  partitions: Record<string, number>;
  tags: Record<string, Record<string, number>>;
}

export interface FamiliesResponse {
  available: boolean;
  reason?: string;
  source?: string;
  distinct_families?: number;
  min_family_confidence?: number;
  totals?: Record<string, number>;
  families: Family[];
}

export interface FsItem {
  name: string;
  kind: "file" | "folder";
  state: "threat" | "novel" | "benign" | "suspicious";
  x: number;
  y: number;
  prob?: number;
  novel?: number;
  sha256?: string;
  path?: string;
  verdict?: string;
  evidence?: string[];
}

export interface ThreatNetwork {
  available: boolean;
  reason: string | null;
  fs_items: FsItem[];
  fs_edges: [number, number][];
  nodes: { id: string; type: string; label: string; category?: string; sample_count?: number }[];
  edges: { source: string; target: string; similarity: number; type: string }[];
}

export interface Curve {
  x: number[];
  y: number[];
  thresholds: number[];
}

export interface OperatingPoint {
  threshold: number;
  tpr: number;
  fpr: number;
  precision: number;
  macro_f1: number;
  confusion: { tp: number; fp: number; tn: number; fn: number };
}

export interface Ci {
  lo: number;
  hi: number;
  n_boot: number;
}

export interface BinaryReport {
  n: number;
  n_malicious: number;
  n_benign: number;
  roc_auc?: number;
  pr_auc?: number;
  fpr_at_95_recall?: number;
  tpr_at_fpr_curve?: Record<string, number>;
  ci95?: Record<string, Ci | null>;
  roc_curve?: Curve;
  pr_curve?: Curve;
  ece: number;
  brier: number;
  reliability: { lo: number; hi: number; count: number; mean_score: number; fraction_malicious: number }[];
  score_histogram: { edges: number[]; benign: number[]; malicious: number[] };
  operating_points: Record<string, OperatingPoint>;
  drift_tau_low?: { period_start: string; n: number; tpr: number; fpr: number; macro_f1: number; roc_auc?: number }[];
}

export interface EvalSummary {
  id: string;
  kind: string;
  created_utc: string;
  model: string;
  file_types: string[] | null;
  test_roc_auc: number | null;
  test_tpr_at_fpr: Record<string, number> | null;
  n_test: number | null;
  signature: string;
}

export interface EvalDetail {
  schema: string;
  kind: string;
  created_utc: string;
  code_commit: string | null;
  model: Record<string, unknown>;
  dataset: Record<string, unknown>;
  splits: Record<string, BinaryReport & Record<string, unknown>>;
  caveats?: string[];
  _signature: string;
  [k: string]: unknown;
}

export interface Timeline {
  available: boolean;
  reason?: string;
  kind?: "benchmark" | "synthetic";
  source?: string;
  dataset?: string;
  caveats?: string[];
  batches?: { batch_id: string; window_start: string; window_end: string }[];
  strategies?: Record<string, { name: string; macro_f1_mean: number; forgetting_mean: number; bwt_mean: number; fpr_mean: number; time_sec_mean: number; r_matrix?: number[][] }>;
}

export interface Ablation {
  status?: string;
  results?: { summary_table: Record<string, string | number>[]; metadata: Record<string, unknown> };
  selection?: { selected_best_dimension: number };
}
