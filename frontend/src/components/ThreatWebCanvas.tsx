import { useEffect, useRef, useState } from "react";
import type { FsItem } from "../lib/api";

export type WebFilter = "all" | "threat" | "novel" | "benign";

const STATE_TOKEN: Record<string, string> = {
  threat: "--danger",
  suspicious: "--warning",
  novel: "--novel",
  benign: "--ok",
};

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

/**
 * Directory/verdict graph of scanned files (data from /api/threat-network fs_items/fs_edges).
 * Positions come from the server's deterministic radial layout; node colour = real verdict.
 */
export function ThreatWebCanvas({
  items,
  edges,
  filter = "all",
  onSelect,
  height = 560,
}: {
  items: FsItem[];
  edges: [number, number][];
  filter?: WebFilter;
  onSelect?: (item: FsItem | null) => void;
  height?: number;
}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const view = useRef({ zoom: 1, panX: 0, panY: 0, drag: false, lastX: 0, lastY: 0, moved: false });
  const [hover, setHover] = useState<number | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [size, setSize] = useState({ w: 800, h: height });

  const visible = (n: FsItem) =>
    filter === "all" || n.kind === "folder" || n.state === filter || (filter === "threat" && n.state === "suspicious");

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [height]);

  // Uniform scale (keeps the server's radial layout round) with room for labels.
  const toScreen = (n: FsItem) => {
    const v = view.current;
    const k = Math.min(size.w, size.h) * 0.95 * v.zoom;
    return [(n.x - 0.5) * k + size.w / 2 + v.panX, (n.y - 0.5) * k + size.h / 2 + v.panY];
  };

  function draw() {
    const c = ref.current;
    if (!c) return;
    const dpr = window.devicePixelRatio || 1;
    c.width = size.w * dpr;
    c.height = size.h * dpr;
    const ctx = c.getContext("2d")!;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = cssVar("--surface");
    ctx.fillRect(0, 0, size.w, size.h);
    if (!items.length) {
      ctx.fillStyle = cssVar("--slate");
      ctx.font = `13px ${cssVar("--font")}`;
      ctx.textAlign = "center";
      ctx.fillText("Run a scan to map files here.", size.w / 2, size.h / 2);
      return;
    }
    ctx.lineWidth = 1;
    for (const [a, b] of edges) {
      const na = items[a];
      const nb = items[b];
      if (!na || !nb || (!visible(na) && !visible(nb))) continue;
      const [x1, y1] = toScreen(na);
      const [x2, y2] = toScreen(nb);
      const related = selected === null || a === selected || b === selected;
      ctx.strokeStyle = cssVar("--rule-strong");
      ctx.globalAlpha = related ? 0.9 : 0.25;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
    items.forEach((n, i) => {
      if (!visible(n)) return;
      const [x, y] = toScreen(n);
      const folder = n.kind === "folder";
      const r = folder ? 7 : 5;
      ctx.fillStyle = folder ? cssVar("--ink") : cssVar(STATE_TOKEN[n.state] || "--muted");
      ctx.beginPath();
      if (folder) ctx.rect(x - r, y - r, r * 2, r * 2);
      else ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fill();
      if (i === hover || i === selected) {
        ctx.strokeStyle = cssVar("--signal");
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(x, y, r + 4, 0, Math.PI * 2);
        ctx.stroke();
        ctx.lineWidth = 1;
      }
      if (folder || i === hover || i === selected || n.state === "threat") {
        ctx.fillStyle = cssVar("--ink");
        ctx.font = `${folder ? 12 : 11}px ${cssVar("--font")}`;
        const text = n.name.length > 34 ? n.name.slice(0, 33) + "…" : n.name;
        const flip = x > size.w * 0.7; // keep labels inside the canvas near the right edge
        ctx.textAlign = flip ? "right" : "left";
        ctx.fillText(text, flip ? x - r - 6 : x + r + 6, y + 4);
      }
    });
  }

  useEffect(draw); // redraw after every render (cheap; graph sizes are bounded by scan results)

  function hit(e: React.MouseEvent) {
    const box = ref.current!.getBoundingClientRect();
    const mx = e.clientX - box.left;
    const my = e.clientY - box.top;
    let best = -1;
    let bestD = 12;
    items.forEach((n, i) => {
      if (!visible(n)) return;
      const [x, y] = toScreen(n);
      const d = Math.hypot(x - mx, y - my);
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    });
    return best;
  }

  return (
    <canvas
      ref={ref}
      className="graph-canvas"
      style={{ height }}
      role="img"
      aria-label={`Graph of ${items.filter((n) => n.kind === "file").length} scanned files grouped by folder`}
      tabIndex={0}
      onMouseDown={(e) => {
        Object.assign(view.current, { drag: true, lastX: e.clientX, lastY: e.clientY, moved: false });
      }}
      onMouseMove={(e) => {
        const v = view.current;
        if (v.drag) {
          v.panX += e.clientX - v.lastX;
          v.panY += e.clientY - v.lastY;
          v.moved ||= Math.abs(e.clientX - v.lastX) + Math.abs(e.clientY - v.lastY) > 2;
          v.lastX = e.clientX;
          v.lastY = e.clientY;
          draw();
          return;
        }
        const h = hit(e);
        setHover(h >= 0 ? h : null);
      }}
      onMouseUp={(e) => {
        const v = view.current;
        v.drag = false;
        if (v.moved) return;
        const h = hit(e);
        setSelected(h >= 0 ? h : null);
        onSelect?.(h >= 0 ? items[h] : null);
      }}
      onMouseLeave={() => {
        view.current.drag = false;
        setHover(null);
      }}
      onWheel={(e) => {
        const v = view.current;
        v.zoom = Math.max(0.4, Math.min(4, v.zoom * (e.deltaY < 0 ? 1.1 : 0.9)));
        draw();
      }}
      onDoubleClick={() => {
        Object.assign(view.current, { zoom: 1, panX: 0, panY: 0 });
        draw();
      }}
    />
  );
}
