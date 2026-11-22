export const num = (v: number | null | undefined, digits = 0): string =>
  typeof v === "number" && isFinite(v)
    ? v.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits })
    : "—";

export const pct = (v: number | null | undefined, digits = 1): string =>
  typeof v === "number" && isFinite(v) ? `${(v * 100).toFixed(digits)}%` : "—";

export const bytes = (v: number | null | undefined): string => {
  if (typeof v !== "number" || !isFinite(v)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let x = v;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
};

export const shortHash = (h: string | null | undefined, n = 12): string => (h ? `${h.slice(0, n)}…` : "—");

export const fileName = (path: string): string => path.split(/[\\/]/).pop() || path;

export const ms = (v: number | null | undefined): string =>
  typeof v !== "number" || !isFinite(v) ? "—" : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`;
