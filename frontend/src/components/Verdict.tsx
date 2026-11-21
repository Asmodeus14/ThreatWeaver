import { verdictInfo, VerdictKey } from "../lib/verdicts";

/** Distinct glyph per verdict so meaning never relies on colour alone. */
export function VerdictGlyph({ kind, size = 14 }: { kind: VerdictKey; size?: number }) {
  const s = size;
  const common = { width: s, height: s, viewBox: "0 0 16 16", "aria-hidden": true as const };
  switch (kind) {
    case "known_malicious":
    case "likely_malicious":
      return (
        <svg {...common}>
          <path d="M5 1h6l4 4v6l-4 4H5l-4-4V5z" fill="currentColor" />
          <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="var(--surface)" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      );
    case "suspicious":
      return (
        <svg {...common}>
          <path d="M8 1.5l7 13H1z" fill="currentColor" />
          <path d="M8 6v4" stroke="var(--surface)" strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="8" cy="12.2" r="0.9" fill="var(--surface)" />
        </svg>
      );
    case "unfamiliar":
      return (
        <svg {...common}>
          <path d="M8 1l7 7-7 7-7-7z" fill="none" stroke="currentColor" strokeWidth="1.6" />
          <circle cx="8" cy="8" r="1.6" fill="currentColor" />
        </svg>
      );
    case "trusted":
      return (
        <svg {...common}>
          <path d="M8 1l6 2.5v4.2c0 3.6-2.5 6.1-6 7.3-3.5-1.2-6-3.7-6-7.3V3.5z" fill="currentColor" />
          <path d="M5.2 8.2l2 2 3.6-3.8" stroke="var(--surface)" strokeWidth="1.5" fill="none" strokeLinecap="round" />
        </svg>
      );
    case "benign":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="7" fill="currentColor" />
          <path d="M4.8 8.3l2.2 2.2 4.2-4.6" stroke="var(--surface)" strokeWidth="1.6" fill="none" strokeLinecap="round" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="2.4 2" />
        </svg>
      );
  }
}

export function Verdict({ verdict }: { verdict: string }) {
  const v = verdictInfo(verdict);
  return (
    <span className={`verdict tone-${v.tone}`} title={verdict}>
      <VerdictGlyph kind={v.key} />
      {v.label}
    </span>
  );
}
