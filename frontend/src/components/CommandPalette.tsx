import { useEffect, useMemo, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { CornerDownLeft, ExternalLink, Monitor, Moon, PanelLeftClose, ScanSearch, Search, Sun } from "lucide-react";
import { api, DetectionRow } from "../lib/api";
import { NAV_ITEMS } from "../lib/nav";
import { go } from "../lib/router";
import type { Theme } from "../lib/theme";
import { verdictInfo } from "../lib/verdicts";
import { VerdictGlyph } from "./Verdict";

interface Command {
  id: string;
  group: "Files" | "Go to" | "Actions";
  label: string;
  hint?: string;
  icon?: LucideIcon;
  glyph?: JSX.Element;
  keywords?: string;
  run: () => void;
}

const match = (q: string, ...fields: (string | undefined)[]) => {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  const hay = fields.filter(Boolean).join(" ").toLowerCase();
  return words.every((w) => hay.includes(w));
};

export function CommandPalette({
  open,
  onClose,
  theme,
  setTheme,
  toggleRail,
}: {
  open: boolean;
  onClose: () => void;
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggleRail: () => void;
}) {
  const [q, setQ] = useState("");
  const [files, setFiles] = useState<DetectionRow[]>([]);
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const restore = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restore.current = document.activeElement as HTMLElement | null;
    setQ("");
    setFiles([]);
    setActive(0);
    requestAnimationFrame(() => input.current?.focus());
    return () => restore.current?.focus?.();
  }, [open]);

  // File search runs against saved scan history, debounced.
  useEffect(() => {
    if (!open) return;
    const term = q.trim();
    if (term.length < 2) {
      setFiles([]);
      return;
    }
    let alive = true;
    const t = window.setTimeout(() => {
      api
        .get<{ results: DetectionRow[] }>(`/api/detections?q=${encodeURIComponent(term)}&limit=40`)
        .then((d) => {
          if (!alive) return;
          const seen = new Set<string>();
          setFiles(
            d.results.filter((r) => {
              const k = r.sha256 || r.file_path;
              if (seen.has(k)) return false;
              seen.add(k);
              return true;
            }).slice(0, 6),
          );
        })
        .catch(() => alive && setFiles([]));
    }, 160);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [q, open]);

  const commands = useMemo<Command[]>(() => {
    const done = (fn: () => void) => () => {
      onClose();
      fn();
    };
    const fileCmds: Command[] = files.map((r) => {
      const v = verdictInfo(r.verdict);
      return {
        id: `file-${r.sha256 || r.file_path}`,
        group: "Files",
        label: r.file_name,
        hint: r.file_path,
        glyph: (
          <span className={`tone-${v.tone}`}>
            <VerdictGlyph kind={v.key} size={16} />
          </span>
        ),
        run: done(() => go("detections", r.sha256 ? { sha: r.sha256 } : { q: r.file_path })),
      };
    });
    const pages: Command[] = NAV_ITEMS.map((n) => ({
      id: `go-${n.id}`,
      group: "Go to",
      label: n.label,
      icon: n.icon,
      keywords: n.keywords,
      run: done(() => go(n.id)),
    }));
    const actions: Command[] = [
      { id: "act-scan", group: "Actions", label: "Start a scan", icon: ScanSearch, keywords: "new analyse", run: done(() => go("scan")) },
      ...(["dark", "light", "system"] as Theme[])
        .filter((t) => t !== theme)
        .map<Command>((t) => ({
          id: `theme-${t}`,
          group: "Actions",
          label: `Use ${t === "system" ? "system" : t} theme`,
          icon: t === "dark" ? Moon : t === "light" ? Sun : Monitor,
          keywords: "appearance colour mode",
          run: done(() => setTheme(t)),
        })),
      { id: "act-rail", group: "Actions", label: "Collapse or expand the sidebar", icon: PanelLeftClose, keywords: "navigation", run: done(toggleRail) },
      {
        id: "act-legacy",
        group: "Actions",
        label: "Open the classic interface",
        icon: ExternalLink,
        keywords: "legacy old v1",
        run: done(() => window.location.assign("/legacy")),
      },
    ];
    const term = q.trim();
    const filter = (c: Command) => !term || match(term, c.label, c.keywords, c.group);
    return [...fileCmds, ...pages.filter(filter), ...actions.filter(filter)];
  }, [files, q, theme, onClose, setTheme, toggleRail]);

  useEffect(() => setActive(0), [q, files.length]);
  useEffect(() => {
    list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(commands.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      commands[active]?.run();
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "Tab") {
      e.preventDefault(); // focus stays in the palette
    }
  };

  let lastGroup = "";
  return (
    <div className="cmdk-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="cmdk" role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={onKey}>
        <div className="cmdk-input">
          <Search aria-hidden="true" />
          <input
            ref={input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search scanned files, pages and actions"
            aria-label="Search scanned files, pages and actions"
            role="combobox"
            aria-expanded="true"
            aria-controls="cmdk-list"
            aria-activedescendant={commands[active] ? `cmdk-${active}` : undefined}
            spellCheck={false}
          />
          <kbd>Esc</kbd>
        </div>
        <div className="cmdk-list" id="cmdk-list" role="listbox" ref={list}>
          {commands.length === 0 && (
            <div className="cmdk-empty">
              No pages, actions or scanned files match “{q}”. File search covers your saved scan history by name, path
              or SHA-256.
            </div>
          )}
          {commands.map((c, i) => {
            const head = c.group !== lastGroup ? <div className="cmdk-group">{c.group}</div> : null;
            lastGroup = c.group;
            const Icon = c.icon;
            return (
              <div key={c.id} style={{ display: "contents" }}>
                {head}
                <button
                  type="button"
                  id={`cmdk-${i}`}
                  data-index={i}
                  role="option"
                  aria-selected={i === active}
                  className="cmdk-item"
                  onMouseMove={() => setActive(i)}
                  onClick={c.run}
                  tabIndex={-1}
                >
                  {c.glyph ?? (Icon ? <Icon aria-hidden="true" /> : null)}
                  <span className="label">{c.label}</span>
                  {c.hint && <small title={c.hint}>{c.hint}</small>}
                  {i === active && <CornerDownLeft aria-hidden="true" style={{ width: 14, height: 14, opacity: 0.6 }} />}
                </button>
              </div>
            );
          })}
        </div>
        <div className="cmdk-foot">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> move
          </span>
          <span>
            <kbd>Enter</kbd> open
          </span>
          <span>
            <kbd>Ctrl</kbd> <kbd>K</kbd> toggle
          </span>
        </div>
      </div>
    </div>
  );
}
