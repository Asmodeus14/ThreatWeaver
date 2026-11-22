// One place that maps API verdict strings to presentation. Every verdict has a colour token
// AND a distinct shape, so it never depends on colour alone.

export type VerdictKey =
  | "known_malicious"
  | "likely_malicious"
  | "suspicious"
  | "unfamiliar"
  | "trusted"
  | "benign"
  | "unsupported"
  | "error";

export interface VerdictInfo {
  key: VerdictKey;
  label: string;
  tone: "danger" | "warning" | "novel" | "trusted" | "ok" | "muted";
  needsAttention: boolean;
  rank: number; // lower = more urgent
}

const TABLE: Record<string, VerdictInfo> = {
  "Known Malicious": { key: "known_malicious", label: "Known malicious", tone: "danger", needsAttention: true, rank: 0 },
  "Likely Malicious": { key: "likely_malicious", label: "Likely malicious", tone: "danger", needsAttention: true, rank: 1 },
  Suspicious: { key: "suspicious", label: "Suspicious", tone: "warning", needsAttention: true, rank: 2 },
  "Unfamiliar / Out-of-Distribution": { key: "unfamiliar", label: "Unfamiliar", tone: "novel", needsAttention: true, rank: 3 },
  "Trusted Signer": { key: "trusted", label: "Trusted signer", tone: "trusted", needsAttention: false, rank: 5 },
  "Likely Benign": { key: "benign", label: "Likely benign", tone: "ok", needsAttention: false, rank: 6 },
  "Unsupported Format": { key: "unsupported", label: "Not analysed", tone: "muted", needsAttention: false, rank: 7 },
  "Analysis Error": { key: "error", label: "Analysis error", tone: "muted", needsAttention: true, rank: 4 },
};

export function verdictInfo(verdict: string): VerdictInfo {
  return TABLE[verdict] ?? { key: "error", label: verdict || "Unknown", tone: "muted", needsAttention: false, rank: 8 };
}

export const ALL_VERDICTS = Object.keys(TABLE);
