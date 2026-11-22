import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Info, Monitor, Moon, PanelLeftClose, PanelLeftOpen, Search, Sun } from "lucide-react";
import { api, Insights, ScanEvents, Status } from "./lib/api";
import { verdictInfo } from "./lib/verdicts";
import { StatusContext } from "./lib/detector";
import { NAV, NAV_ITEMS } from "./lib/nav";
import { useRoute } from "./lib/router";
import { nextTheme, useTheme } from "./lib/theme";
import { CommandPalette } from "./components/CommandPalette";
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

/** Woven-thread mark: three warp and three weft threads, one node lit where a file is caught. */
function Mark() {
  return (
    <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden="true">
      <rect x="0.5" y="0.5" width="25" height="25" rx="8" fill="var(--accent-soft)" stroke="var(--glass-edge-strong)" />
      <path d="M6 9h14M6 13h14M6 17h14" stroke="var(--ink-3)" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M9 6v14M13 6v14M17 6v14" stroke="var(--ink)" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="17" cy="9" r="2.6" fill="var(--accent)" />
    </svg>
  );
}

function readCollapsed(): boolean {
  try {
    return localStorage.getItem("tw-rail") === "collapsed";
  } catch {
    return false;
  }
}

/** Lightweight scan status for the top bar: no results transferred, just progress. */
function useScanStatus() {
  const [s, setS] = useState<Omit<ScanEvents, "new_results"> | null>(null);
  useEffect(() => {
    let alive = true;
    let t: number;
    const load = () =>
      api
        .get<ScanEvents>("/api/scan/events?since=1000000000")
        .then(({ new_results: _drop, ...rest }) => {
          if (!alive) return;
          setS(rest);
          t = window.setTimeout(load, rest.is_scanning ? 1500 : 6000);
        })
        .catch(() => alive && (t = window.setTimeout(load, 10000)));
    load();
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, []);
  return s;
}

export function App() {
  const route = useRoute();
  const [status, setStatus] = useState<Status | null>(null);
  const [attention, setAttention] = useState(0);
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [palette, setPalette] = useState(false);
  const [theme, setTheme] = useTheme();
  const scan = useScanStatus();

  useEffect(() => {
    let alive = true;
    const load = () => {
      api.get<Status>("/api/status").then((s) => alive && setStatus(s)).catch(() => {});
      // Same source as the Overview: unique files whose latest verdict needs attention.
      api
        .get<Insights>("/api/insights")
        .then((d) => {
          if (!alive) return;
          setAttention(Object.entries(d.verdict_counts).reduce((n, [v, c]) => n + (verdictInfo(v).needsAttention ? c : 0), 0));
        })
        .catch(() => {});
    };
    load();
    const t = window.setInterval(load, 15000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  const toggleRail = useCallback(() => {
    setCollapsed((c) => {
      try {
        localStorage.setItem("tw-rail", c ? "expanded" : "collapsed");
      } catch {
        /* preference only */
      }
      return !c;
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // The lens slides to the current page's nav item.
  const navRef = useRef<HTMLElement>(null);
  const [lens, setLens] = useState<{ y: number; visible: boolean }>({ y: 0, visible: false });
  useLayoutEffect(() => {
    const el = navRef.current?.querySelector<HTMLElement>('[aria-current="page"]');
    setLens(el ? { y: el.offsetTop, visible: true } : { y: 0, visible: false });
  }, [route.page, collapsed, status === null]);

  const Page = PAGES[route.page] ?? Overview;
  const pageLabel = NAV_ITEMS.find((n) => n.id === route.page)?.label ?? "Overview";
  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
  const scanning = scan?.is_scanning ?? false;

  return (
    <StatusContext.Provider value={status}>
      <ToastProvider>
        <div className="shell" data-collapsed={collapsed}>
          <aside className="rail glass" aria-label="Sidebar">
            <a className="brand" href="#/overview" aria-label="ThreatWeaver overview" style={{ color: "inherit", textDecoration: "none" }}>
              <Mark />
              <span className="brand-name">ThreatWeaver</span>
            </a>
            <nav className="nav" aria-label="Main" ref={navRef}>
              <span className="nav-lens" aria-hidden="true" style={{ transform: `translateY(${lens.y}px)`, opacity: lens.visible ? 1 : 0 }} />
              {NAV.map((g, gi) => (
                <div key={gi} style={{ display: "contents" }}>
                  {g.group && <div className="nav-group">{g.group}</div>}
                  {g.items.map((it) => {
                    const Icon = it.icon;
                    const badge = it.id === "detections" && attention > 0;
                    return (
                      <a
                        key={it.id}
                        className="nav-item"
                        href={`#/${it.id}`}
                        aria-current={route.page === it.id ? "page" : undefined}
                        title={collapsed ? it.label : undefined}
                        aria-label={badge ? `${it.label}, ${attention} need attention` : undefined}
                      >
                        <Icon aria-hidden="true" />
                        <span className="label">{it.label}</span>
                        {badge && <span className="count">{attention}</span>}
                        {badge && <span className="count-dot" aria-hidden="true" />}
                      </a>
                    );
                  })}
                </div>
              ))}
            </nav>
            <div className="rail-foot">
              <div className="mode-badge" title="On-demand static analysis. Files are read as data and never executed. There is no real-time protection.">
                <Info aria-hidden="true" />
                <div>
                  <strong>On-demand only</strong>
                  Static analysis; files are never executed. No real-time protection.
                </div>
              </div>
              <div className="rail-tools">
                <a href="/legacy">Classic interface</a>
                <button className="icon-btn collapse-btn" onClick={toggleRail} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
                  {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
                </button>
              </div>
            </div>
          </aside>
          <div className="main">
            <header className="topbar glass">
              <span className="sr-only">{pageLabel}</span>
              <button className="cmdk-trigger" onClick={() => setPalette(true)} aria-label="Open command palette (Ctrl+K)">
                <Search aria-hidden="true" />
                <span>Search files, pages and actions</span>
                <kbd>Ctrl K</kbd>
              </button>
              <div className="spacer" />
              <a
                className={`scan-pill${scanning ? " live" : ""}`}
                href="#/scan"
                aria-live="polite"
                title={scanning && scan?.current_file ? scan.current_file : undefined}
              >
                <span className="pulse" aria-hidden="true" />
                {scanning
                  ? `Scanning ${scan!.total ? Math.floor((scan!.completed / scan!.total) * 100) : 0}% · ${scan!.completed.toLocaleString()} files`
                  : "No scan running"}
              </a>
              <button
                className="icon-btn"
                onClick={() => setTheme(nextTheme(theme))}
                aria-label={`Theme: ${theme}. Switch to ${nextTheme(theme)}`}
                title={`Theme: ${theme} (click for ${nextTheme(theme)})`}
              >
                <ThemeIcon />
              </button>
            </header>
            <main className="content" id="main">
              <Page key={route.page + route.params.toString()} />
            </main>
          </div>
        </div>
        <CommandPalette open={palette} onClose={() => setPalette(false)} theme={theme} setTheme={setTheme} toggleRail={toggleRail} />
      </ToastProvider>
    </StatusContext.Provider>
  );
}
