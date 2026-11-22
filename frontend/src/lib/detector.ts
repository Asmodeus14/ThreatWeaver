import { createContext, useContext } from "react";
import type { DetectorInfo, Status } from "./api";
export type { DetectorInfo };

export interface Thresholds {
  low: number;
  high: number;
  lowLabel: string;
  highLabel: string;
}

/** Thresholds of the active detector, as reported by /api/status (never hard-coded). */
export function thresholdsFrom(status: Status | null): Thresholds | null {
  const d = status?.detector;
  if (!d) return null;
  return {
    low: d.tau_low,
    high: d.tau_high,
    lowLabel: d.kind === "lightgbm" ? "≈1% FPR on validation" : "legacy decision threshold",
    highLabel: d.kind === "lightgbm" ? "≈0.1% FPR on validation" : "",
  };
}

export const StatusContext = createContext<Status | null>(null);
export const useStatus = () => useContext(StatusContext);
