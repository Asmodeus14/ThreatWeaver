import { useEffect, useState } from "react";
import { api, Status } from "./lib/api";
import { StatusContext } from "./lib/detector";
import { go, useRoute } from "./lib/router";
import { ToastProvider } from "./components/Toast";
import { Overview } from "./pages/Overview";
import { ScanPage } from "./pages/Scan";
import { Detections } from "./pages/Detections";
import { ThreatWeb } from "./pages/ThreatWeb";
import { Families } from "./pages/Families";
import { Quarantine } from "./pages/Quarantine";
import { Reports } from "./pages/Reports";
import { Performance } from "./pages/Performance";
import { Experiments } from "./pages/Experiments";
import { Learning } from "./pages/Learning";
import { Settings } from "./pages/Settings";

const NAV: { group?: string; items: { id: string; label: string }[] }[] = [
  { items: [{ id: "overview", label: "Overview" }, { id: "scan", label: "Scan" }, { id: "detections", label: "Detections" }, { id: "web", label: "Threat web" }] },
  { group: "Response", items: [{ id: "quarantine", label: "Quarantine" }, { id: "reports", label: "Scan history" }] },
  { group: "Intelligence", items: [{ id: "families", label: "Families" }, { id: "learning", label: "Learning" }] },
  { group: "Research", items: [{ id: "performance", label: "Model performance" }, { id: "experiments", label: "Experiments" }] },
  { items: [{ id: "settings", label: "Settings" }] },
];

const PAGES: Record<string, () => JSX.Element> = {
  overview: Overview,
  scan: ScanPage,
  detections: Detections,
  web: ThreatWeb,
  families: Families,
  quarantine: Quarantine,
  reports: Reports,
  performance: Performance,
  experiments: Experiments,
  learning: Learning,
  settings: Settings,
};

function Mark() {
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
      <path d="M3 6h16M3 11h16M3 16h16" stroke="var(--rule-strong)" strokeWidth="1.5" />
      <path d="M6 3v16M11 3v16M16 3v16" stroke="var(--ink)" strokeWidth="1.5" />
      <rect x="9.5" y="9.5" width="3" height="3" fill="var(--danger)" />
    </svg>
  );
}

export function App() {
  const route = useRoute();
  const [status, setStatus] = useState<Status | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    let alive = true;
    const load = () => api.get<Status>("/api/status").then((s) => alive && setStatus(s)).catch(() => {});
    load();
    const t = window.setInterval(load, 15000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  const Page = PAGES[route.page] ?? Overview;
  const attention = status?.suspicious_count ?? 0;

  return (
    <StatusContext.Provider value={status}>
      <ToastProvider>
        <div className="shell">
          <aside className="rail">
            <div className="brand">
              <Mark />
              ThreatWeaver
            </div>
            <nav className="nav" aria-label="Main">
              {NAV.map((g, gi) => (
                <div key={gi} style={{ display: "contents" }}>
                  {g.group && <div className="nav-group">{g.group}</div>}
                  {g.items.map((it) => (
                    <a key={it.id} href={`#/${it.id}`} aria-current={route.page === it.id ? "page" : undefined}>
                      {it.label}
                      {it.id === "detections" && attention > 0 && <span className="count">{attention}</span>}
                    </a>
                  ))}
                </div>
              ))}
            </nav>
            <div className="rail-foot">
              <span>{status ? status.protection_mode : "Connecting…"}</span>
              <span>Static analysis only; files are never executed.</span>
              <a href="/legacy" style={{ color: "var(--slate)" }}>
                Open classic interface
              </a>
            </div>
          </aside>
          <div className="main">
            <header className="topbar">
              <form
                className="search"
                role="search"
                onSubmit={(e) => {
                  e.preventDefault();
                  go("detections", search ? { q: search } : {});
                }}
              >
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search scanned files by path or SHA-256"
                  aria-label="Search scanned files"
                />
              </form>
              <ThemeToggle />
            </header>
            <main className="content" id="main">
              <Page key={route.page + route.params.toString()} />
            </main>
          </div>
        </div>
      </ToastProvider>
    </StatusContext.Provider>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem("tw-theme") || "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("tw-theme", theme);
    } catch {
      /* storage unavailable: theme still applies for this session */
    }
  }, [theme]);
  return (
    <div className="segmented" role="group" aria-label="Colour theme">
      {["system", "light", "dark"].map((t) => (
        <button key={t} aria-pressed={theme === t} onClick={() => setTheme(t)}>
          {t[0].toUpperCase() + t.slice(1)}
        </button>
      ))}
    </div>
  );
}
