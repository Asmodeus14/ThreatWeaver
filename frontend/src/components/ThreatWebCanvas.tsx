import { useEffect, useRef, useState } from "react";
import type { FsItem } from "../lib/api";

export type WebFilter = "all" | "threat" | "novel" | "benign";

const STATE_TOKEN: Record<string, string> = {
  threat: "--danger",
  suspicious: "--warning",
  novel: "--novel",
  benign: "--ink-3",
};

interface SimNode {
  i: number;
  item: FsItem;
  folder: boolean;
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  pinned: boolean;
  leaves: number;
  /** Frame at which a file leaves its folder (staged bloom). */
  release: number;
  /** Per-file spring length jitter so clusters settle organically, not in rings. */
  jitter: number;
  parent: number;
  kids: number[];
}

interface Camera {
  x: number;
  y: number;
  k: number;
}

type Hist = { x: number; y: number; t: number }[];

const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

function readTokens() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n: string) => cs.getPropertyValue(n).trim() || "#888";
  return {
    ink: v("--ink"),
    ink2: v("--ink-2"),
    ink3: v("--ink-3"),
    ground: v("--ground"),
    raised: v("--ground-raised"),
    rule: v("--rule-strong"),
    font: v("--font"),
    state: Object.fromEntries(Object.entries(STATE_TOKEN).map(([k, t]) => [k, v(t)])) as Record<string, string>,
  };
}

/** Parent/child structure from folder edges, plus subtree file counts. */
function structure(items: FsItem[], edges: [number, number][]) {
  const n = items.length;
  const parent = new Array<number>(n).fill(-1);
  const children: number[][] = Array.from({ length: n }, () => []);
  for (const [a, b] of edges) {
    if (items[a]?.kind === "folder" && parent[b] === -1 && a !== b) {
      parent[b] = a;
      children[a].push(b);
    }
  }
  const leaves = new Array<number>(n).fill(0);
  const order: number[] = [];
  const stack = items.map((_, i) => i).filter((i) => parent[i] === -1);
  const seen = new Set<number>();
  while (stack.length) {
    const i = stack.pop()!;
    if (seen.has(i)) continue;
    seen.add(i);
    order.push(i);
    stack.push(...children[i]);
  }
  for (let k = order.length - 1; k >= 0; k--) {
    const i = order[k];
    leaves[i] = children[i].length ? children[i].reduce((t, c) => t + leaves[c], 0) : 1;
  }
  return { parent, children, leaves, order };
}

const velocity = (hist: Hist) => {
  if (hist.length < 2) return { x: 0, y: 0 };
  const a = hist[0];
  const b = hist[hist.length - 1];
  const dt = Math.max(16, b.t - a.t);
  return { x: ((b.x - a.x) / dt) * 16, y: ((b.y - a.y) / dt) * 16 }; // px per frame
};

/**
 * The living threat web: a force-directed map of the latest scan. Files bloom out of their
 * folders, settle under springs and repulsion, and can be grabbed, flung, zoomed and focused.
 * Colour is only the real verdict; everything else is black and white.
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
  const [hint, setHint] = useState<string | null>(null);
  const hintRef = useRef<HTMLDivElement>(null);
  const [grab, setGrab] = useState(false);
  const sim = useRef({
    nodes: [] as SimNode[],
    links: [] as [number, number][],
    neighbours: [] as Set<number>[],
    alpha: 1,
    cam: { x: 0, y: 0, k: 1 } as Camera,
    target: { x: 0, y: 0, k: 1 } as Camera,
    follow: true, // keep the bloom framed until the user takes the camera
    hover: -1,
    selected: -1,
    drag: null as null | { node: number; ox: number; oy: number; hist: Hist },
    pan: null as null | { x: number; y: number; hist: Hist; moved: boolean },
    panVel: { x: 0, y: 0 },
    size: { w: 800, h: height },
    raf: 0,
    tokens: null as ReturnType<typeof readTokens> | null,
    onScreen: true,
    filter: "all" as WebFilter,
    frame: 0,
    ambient: false,
  });
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  const visible = (n: SimNode, f: WebFilter) =>
    f === "all" || n.folder || n.item.state === f || (f === "threat" && n.item.state === "suspicious");

  // ---------------------------------------------------------------- physics
  function tick() {
    const s = sim.current;
    const { nodes, links } = s;
    const alpha = s.alpha;
    // Springs along folder edges: files sit close to their folder, folders further apart.
    for (const [a, b] of links) {
      const na = nodes[a];
      const nb = nodes[b];
      let dx = nb.x - na.x;
      let dy = nb.y - na.y;
      const d = Math.hypot(dx, dy) || 0.01;
      const rest = nb.folder && na.folder ? 70 + Math.sqrt(nb.leaves) * 6 : (18 + Math.sqrt(na.leaves) * 2.2) * nb.jitter;
      const k = ((d - rest) / d) * 0.12 * alpha;
      dx *= k;
      dy *= k;
      const wb = na.folder && !nb.folder ? 0.85 : 0.5;
      if (!nb.pinned) {
        nb.vx -= dx * wb;
        nb.vy -= dy * wb;
      }
      if (!na.pinned) {
        na.vx += dx * (1 - wb);
        na.vy += dy * (1 - wb);
      }
    }
    // Short-range repulsion through a spatial grid (linear per tick, fine for thousands of files).
    const cell = 26;
    const grid = new Map<number, number[]>();
    const key = (gx: number, gy: number) => gx * 73856093 + gy * 19349663;
    for (const n of nodes) {
      const k = key(Math.floor(n.x / cell), Math.floor(n.y / cell));
      const g = grid.get(k);
      if (g) g.push(n.i);
      else grid.set(k, [n.i]);
    }
    for (const n of nodes) {
      const cx = Math.floor(n.x / cell);
      const cy = Math.floor(n.y / cell);
      for (let gx = cx - 1; gx <= cx + 1; gx++)
        for (let gy = cy - 1; gy <= cy + 1; gy++) {
          const g = grid.get(key(gx, gy));
          if (!g) continue;
          for (const j of g) {
            if (j <= n.i) continue;
            const m = nodes[j];
            let dx = m.x - n.x;
            let dy = m.y - n.y;
            let d2 = dx * dx + dy * dy;
            if (d2 > cell * cell) continue;
            if (d2 < 0.01) {
              dx = (Math.random() - 0.5) * 0.5;
              dy = (Math.random() - 0.5) * 0.5;
              d2 = dx * dx + dy * dy;
            }
            const d = Math.sqrt(d2);
            const min = n.r + m.r + 7;
            const f = ((d < min ? (min - d) * 0.5 : 0) + (cell - d) * 0.02) * alpha;
            const ux = (dx / d) * f;
            const uy = (dy / d) * f;
            if (!n.pinned) {
              n.vx -= ux;
              n.vy -= uy;
            }
            if (!m.pinned) {
              m.vx += ux;
              m.vy += uy;
            }
          }
        }
    }
    // Long-range charge between folders keeps branches apart.
    const folders = nodes.filter((n) => n.folder);
    for (let a = 0; a < folders.length; a++)
      for (let b = a + 1; b < folders.length; b++) {
        const p = folders[a];
        const q = folders[b];
        const dx = q.x - p.x;
        const dy = q.y - p.y;
        const d2 = Math.max(100, dx * dx + dy * dy);
        const d = Math.sqrt(d2);
        const f = ((1400 + 60 * Math.sqrt(p.leaves * q.leaves)) / d2) * alpha;
        if (!p.pinned) {
          p.vx -= (dx / d) * f;
          p.vy -= (dy / d) * f;
        }
        if (!q.pinned) {
          q.vx += (dx / d) * f;
          q.vy += (dy / d) * f;
        }
      }
    const f = s.frame;
    const ambient = s.ambient;
    for (const n of nodes) {
      if (n.pinned) {
        n.vx = 0;
        n.vy = 0;
        continue;
      }
      if (!n.folder && n.parent >= 0 && f < n.release) {
        const p = nodes[n.parent];
        n.x = p.x;
        n.y = p.y;
        n.vx = 0;
        n.vy = 0;
        continue;
      }
      if (ambient && !n.folder) {
        // Gentle, non-repeating drift so the settled map keeps breathing.
        n.vx += Math.sin(f * 0.011 + n.i * 1.7) * 0.012;
        n.vy += Math.cos(f * 0.013 + n.i * 2.3) * 0.012;
      }
      n.vx -= n.x * 0.004 * alpha;
      n.vy -= n.y * 0.004 * alpha;
      n.vx *= 0.62;
      n.vy *= 0.62;
      n.x += n.vx;
      n.y += n.vy;
    }
    s.alpha = Math.max(s.ambient ? 0.018 : 0, alpha * 0.988 - 0.0004);
  }

  // ---------------------------------------------------------------- camera
  function fit(instant = false) {
    const s = sim.current;
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const n of s.nodes) {
      if (!visible(n, s.filter)) continue;
      x0 = Math.min(x0, n.x);
      y0 = Math.min(y0, n.y);
      x1 = Math.max(x1, n.x);
      y1 = Math.max(y1, n.y);
    }
    if (!isFinite(x0)) return;
    const pad = Math.min(64, s.size.h * 0.1);
    const k = Math.min(2.4, Math.max(0.15, Math.min((s.size.w - pad * 2) / Math.max(40, x1 - x0), (s.size.h - pad * 2) / Math.max(40, y1 - y0))));
    s.target = { x: (x0 + x1) / 2, y: (y0 + y1) / 2, k };
    if (instant) s.cam = { ...s.target };
  }
  const toScreen = (x: number, y: number, c: Camera, w: number, h: number) => [(x - c.x) * c.k + w / 2, (y - c.y) * c.k + h / 2];
  const toWorld = (sx: number, sy: number) => {
    const s = sim.current;
    return [(sx - s.size.w / 2) / s.cam.k + s.cam.x, (sy - s.size.h / 2) / s.cam.k + s.cam.y];
  };

  // ---------------------------------------------------------------- render loop
  function kick() {
    const s = sim.current;
    if (!s.raf) s.raf = requestAnimationFrame(frame);
  }
  function frame(t: number) {
    const s = sim.current;
    s.raf = 0;
    s.frame++;
    const calm = reducedMotion();
    if (s.alpha > 0.002 || s.drag || s.ambient) {
      tick();
      if (s.drag) s.alpha = Math.max(s.alpha, 0.12);
    }
    if (s.follow && s.frame % 4 === 0) fit();
    const flinging = !s.pan && Math.abs(s.panVel.x) + Math.abs(s.panVel.y) > 0.04;
    if (flinging) {
      // Momentum after a flick-pan, decaying like scroll deceleration.
      s.target.x -= s.panVel.x / s.cam.k;
      s.target.y -= s.panVel.y / s.cam.k;
      s.cam.x = s.target.x;
      s.cam.y = s.target.y;
      s.panVel.x *= 0.93;
      s.panVel.y *= 0.93;
    }
    // Camera eases from wherever it is now toward its target: interruptible on any frame.
    const e = calm ? 1 : 0.16;
    s.cam.x += (s.target.x - s.cam.x) * e;
    s.cam.y += (s.target.y - s.cam.y) * e;
    s.cam.k += (s.target.k - s.cam.k) * e;
    const camMoving = Math.abs(s.target.k - s.cam.k) > 0.0005 || Math.hypot(s.target.x - s.cam.x, s.target.y - s.cam.y) > 0.05;
    draw(t, calm);
    // The map keeps breathing while it is on screen; it rests when hidden or with reduced motion.
    s.ambient = !calm && s.onScreen && !document.hidden && s.nodes.length > 0;
    if (s.alpha > 0.002 || s.drag || camMoving || s.ambient || flinging) kick();
  }

  function draw(t: number, calm: boolean) {
    const s = sim.current;
    const c = ref.current;
    if (!c) return;
    const tk = (s.tokens ??= readTokens());
    const { w, h } = s.size;
    const dpr = window.devicePixelRatio || 1;
    if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
      c.width = Math.round(w * dpr);
      c.height = Math.round(h * dpr);
    }
    const ctx = c.getContext("2d")!;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const { nodes, links, cam } = s;
    if (!nodes.length) {
      ctx.fillStyle = tk.ink3;
      ctx.font = `14px ${tk.font}`;
      ctx.textAlign = "center";
      ctx.fillText("Run a scan to map files here.", w / 2, h / 2);
      return;
    }
    const focus = s.hover >= 0 ? s.hover : s.selected;
    const near = focus >= 0 ? s.neighbours[focus] : null;
    const lit = (i: number) => focus < 0 || i === focus || !!near?.has(i);
    const pos = nodes.map((n) => toScreen(n.x, n.y, cam, w, h));
    const dim = 0.16;

    ctx.lineWidth = 1;
    for (const [a, b] of links) {
      const na = nodes[a];
      const nb = nodes[b];
      if (!visible(na, s.filter) || !visible(nb, s.filter)) continue;
      const on = focus >= 0 && (a === focus || b === focus);
      ctx.strokeStyle = on ? tk.ink : tk.rule;
      ctx.globalAlpha = focus >= 0 ? (on ? 0.85 : 0.2) : nb.folder ? 1 : 0.7;
      ctx.beginPath();
      ctx.moveTo(pos[a][0], pos[a][1]);
      ctx.lineTo(pos[b][0], pos[b][1]);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    const zoom = Math.max(0.6, Math.min(1.8, cam.k));
    for (const pass of [false, true]) {
      // Files first, folders on top.
      for (const n of nodes) {
        if (n.folder !== pass || !visible(n, s.filter)) continue;
        const [x, y] = pos[n.i];
        if (x < -40 || y < -40 || x > w + 40 || y > h + 40) continue;
        const a = lit(n.i) ? 1 : dim;
        ctx.globalAlpha = a;
        const r = n.r * zoom;
        if (n.folder) {
          ctx.beginPath();
          ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fillStyle = tk.raised;
          ctx.fill();
          ctx.lineWidth = 1.6;
          ctx.strokeStyle = tk.ink;
          ctx.stroke();
          ctx.lineWidth = 1;
        } else {
          const col = tk.state[n.item.state] ?? tk.ink3;
          if (n.item.state === "threat" && !calm) {
            const ph = (t / 1400 + n.i * 0.13) % 1; // ~0.7 Hz halo, phase-shifted per node
            ctx.beginPath();
            ctx.arc(x, y, r + 2 + ph * 9, 0, Math.PI * 2);
            ctx.strokeStyle = col;
            ctx.globalAlpha = a * 0.55 * (1 - ph);
            ctx.stroke();
            ctx.globalAlpha = a;
          }
          ctx.beginPath();
          ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fillStyle = col;
          ctx.fill();
        }
        if (n.i === s.selected || n.i === s.hover) {
          ctx.beginPath();
          ctx.arc(x, y, r + 4, 0, Math.PI * 2);
          ctx.strokeStyle = tk.ink;
          ctx.lineWidth = 1.5;
          ctx.stroke();
          ctx.lineWidth = 1;
        }
      }
    }
    ctx.globalAlpha = 1;

    if (hintRef.current && s.hover >= 0) {
      const [hx, hy] = pos[s.hover];
      hintRef.current.style.transform = `translate(${Math.round(hx)}px, ${Math.round(hy - s.nodes[s.hover].r * zoom - 14)}px) translate(-50%, -100%)`;
    }
    // Labels: folders always; flagged files when zoomed in; the selected node.
    ctx.textAlign = "center";
    ctx.lineJoin = "round";
    const placed: { x0: number; y0: number; x1: number; y1: number }[] = [];
    for (const n of nodes) {
      if (!visible(n, s.filter)) continue;
      const show = (n.folder || (n.item.state === "threat" && cam.k > 1.3) || (cam.k > 2.6 && !!near?.has(n.i)) || n.i === s.selected) && n.i !== s.hover;
      if (!show) continue;
      const [x, y] = pos[n.i];
      if (x < -80 || y < -40 || x > w + 80 || y > h + 40) continue;
      const text = n.item.name.length > 28 ? n.item.name.slice(0, 27) + "…" : n.item.name;
      ctx.font = `${n.folder ? 600 : 500} ${n.folder ? 12 : 11}px ${tk.font}`;
      ctx.globalAlpha = lit(n.i) ? 1 : 0.22;
      // Folder labels sit below their whole cluster, on a pill in the card colour.
      let reach = n.r;
      if (n.folder) for (const c of n.kids) if (!nodes[c].folder) reach = Math.max(reach, Math.hypot(nodes[c].x - n.x, nodes[c].y - n.y) * cam.k / zoom);
      const tw = ctx.measureText(text).width;
      // Keep every label inside the canvas and clear of labels already placed.
      let ly = Math.min(h - 10, Math.max(20, y + Math.min(reach * zoom, 160) + (n.folder ? 22 : 16)));
      const lx = Math.min(w - tw / 2 - 12, Math.max(tw / 2 + 12, x));
      const box = (yy: number) => ({ x0: lx - tw / 2 - 8, y0: yy - 13, x1: lx + tw / 2 + 8, y1: yy + 6 });
      const hits = (b: ReturnType<typeof box>) => placed.some((q) => b.x0 < q.x1 && b.x1 > q.x0 && b.y0 < q.y1 && b.y1 > q.y0);
      for (let tries = 0; tries < 6 && hits(box(ly)); tries++) {
        const down = ly + 22;
        ly = down <= h - 10 ? down : Math.max(20, ly - 44);
      }
      placed.push(box(ly));
      ctx.fillStyle = tk.raised;
      ctx.beginPath();
      ctx.roundRect(lx - tw / 2 - 8, ly - 13, tw + 16, 19, 10);
      ctx.fill();
      if (n.folder) {
        ctx.strokeStyle = tk.rule;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      ctx.fillStyle = n.folder ? tk.ink : tk.ink2;
      ctx.fillText(text, lx, ly);
    }
    ctx.globalAlpha = 1;
  }

  // ---------------------------------------------------------------- build simulation
  useEffect(() => {
    const s = sim.current;
    const { parent, children, leaves, order } = structure(items, edges);
    const nodes: SimNode[] = items.map((item, i) => ({
      i,
      item,
      folder: item.kind === "folder",
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      r: item.kind === "folder" ? 5 + Math.min(9, Math.sqrt(leaves[i])) : 3.6,
      pinned: false,
      leaves: leaves[i],
      release: 0,
      jitter: 0.6 + ((i * 2654435761) % 1000) / 1000 * 1.0,
      parent: parent[i],
      kids: children[i],
    }));
    // Seed: folders fanned out by subtree size; files start on their folder and bloom outward.
    const roots = order.filter((i) => parent[i] === -1);
    const depthOf = (i: number) => {
      let d = 0;
      for (let p = parent[i]; p >= 0 && d < 50; p = parent[p]) d++;
      return d;
    };
    const R = 40 + Math.sqrt(items.length) * 9;
    const total = roots.reduce((t, i) => t + leaves[i], 0) || 1;
    const place = (i: number, ang: number, rad: number, span: number) => {
      nodes[i].x = Math.cos(ang) * rad;
      nodes[i].y = Math.sin(ang) * rad;
      let st = ang - span / 2;
      for (const c of children[i]) {
        const sp = (span * leaves[c]) / Math.max(1, leaves[i]);
        if (nodes[c].folder) place(c, st + sp / 2, rad + R * 0.6, sp);
        else {
          nodes[c].x = nodes[i].x + (Math.random() - 0.5) * 4;
          nodes[c].y = nodes[i].y + (Math.random() - 0.5) * 4;
          nodes[c].release = 10 + depthOf(i) * 8 + Math.min(40, children[i].indexOf(c) * 0.5);
        }
        st += sp;
      }
    };
    let a0 = -Math.PI / 2;
    for (const i of roots) {
      const span = (2 * Math.PI * leaves[i]) / total;
      place(i, a0 + span / 2, roots.length === 1 ? 0 : R * 0.5, span);
      a0 += span;
    }
    s.nodes = nodes;
    s.links = edges.filter(([a, b]) => nodes[a] && nodes[b] && a !== b);
    s.neighbours = nodes.map(() => new Set<number>());
    for (const [a, b] of s.links) {
      s.neighbours[a].add(b);
      s.neighbours[b].add(a);
    }
    s.alpha = 1;
    s.follow = true;
    s.selected = -1;
    s.hover = -1;
    if (reducedMotion()) {
      for (let k = 0; k < 320; k++) tick();
      s.alpha = 0;
      fit(true);
    } else {
      s.cam = { x: 0, y: 0, k: 2 }; // start close, pull back as it blooms
      s.target = { ...s.cam };
    }
    kick();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, edges]);

  useEffect(() => {
    const s = sim.current;
    s.filter = filter;
    if (s.follow) fit();
    kick();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  // ---------------------------------------------------------------- lifecycle
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const s = sim.current;
    const ro = new ResizeObserver(([e]) => {
      s.size = { w: e.contentRect.width, h: height };
      if (s.follow) fit(true);
      kick();
    });
    ro.observe(el);
    const io = new IntersectionObserver(([e]) => {
      s.onScreen = e.isIntersecting;
      if (e.isIntersecting) kick();
    });
    io.observe(el);
    const refresh = () => {
      s.tokens = null; // re-read colours after a theme switch
      kick();
    };
    const theme = new MutationObserver(refresh);
    theme.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    mq?.addEventListener?.("change", refresh);
    const onVis = () => !document.hidden && kick();
    document.addEventListener("visibilitychange", onVis);
    return () => {
      ro.disconnect();
      io.disconnect();
      theme.disconnect();
      mq?.removeEventListener?.("change", refresh);
      document.removeEventListener("visibilitychange", onVis);
      cancelAnimationFrame(s.raf);
      s.raf = 0;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [height]);

  // ---------------------------------------------------------------- input
  function nodeAt(sx: number, sy: number) {
    const s = sim.current;
    let best = -1;
    let bestD = 12;
    for (const n of s.nodes) {
      if (!visible(n, s.filter)) continue;
      const [x, y] = toScreen(n.x, n.y, s.cam, s.size.w, s.size.h);
      const d = Math.hypot(x - sx, y - sy) - n.r;
      if (d < bestD) {
        bestD = d;
        best = n.i;
      }
    }
    return best;
  }
  const local = (e: { clientX: number; clientY: number }) => {
    const b = ref.current!.getBoundingClientRect();
    return [e.clientX - b.left, e.clientY - b.top];
  };
  function select(i: number) {
    const s = sim.current;
    s.selected = i;
    onSelectRef.current?.(i >= 0 ? s.nodes[i].item : null);
    if (i >= 0) {
      const n = s.nodes[i];
      s.follow = false;
      s.target = { x: n.x, y: n.y, k: Math.max(s.target.k, n.folder ? 1.5 : 2) };
    }
    kick();
  }

  return (
    <div className="web-wrap">
      <canvas
        ref={ref}
        className="graph-canvas"
        style={{ height, touchAction: "none", cursor: grab ? "grabbing" : hint ? "grab" : "default" }}
        role="img"
        aria-label={`Live map of ${items.filter((n) => n.kind === "file").length} scanned files grouped by folder. Drag a node to move it, drag the background to pan, scroll to zoom, double-click or press 0 to fit.`}
        tabIndex={0}
        onPointerDown={(e) => {
          const s = sim.current;
          const [sx, sy] = local(e);
          (e.target as Element).setPointerCapture(e.pointerId);
          s.panVel = { x: 0, y: 0 };
          const hit = nodeAt(sx, sy);
          const now = performance.now();
          if (hit >= 0) {
            const n = s.nodes[hit];
            const [wx, wy] = toWorld(sx, sy);
            s.drag = { node: hit, ox: n.x - wx, oy: n.y - wy, hist: [{ x: sx, y: sy, t: now }] };
            n.pinned = true;
            s.alpha = Math.max(s.alpha, 0.3);
          } else {
            s.pan = { x: sx, y: sy, hist: [{ x: sx, y: sy, t: now }], moved: false };
          }
          s.follow = false;
          setGrab(true);
          kick();
        }}
        onPointerMove={(e) => {
          const s = sim.current;
          const [sx, sy] = local(e);
          const now = performance.now();
          if (s.drag) {
            const n = s.nodes[s.drag.node];
            const [wx, wy] = toWorld(sx, sy);
            n.x = wx + s.drag.ox; // follows the pointer 1:1 from where it was grabbed
            n.y = wy + s.drag.oy;
            s.drag.hist = [...s.drag.hist.slice(-4), { x: sx, y: sy, t: now }];
            kick();
            return;
          }
          if (s.pan) {
            const dx = sx - s.pan.x;
            const dy = sy - s.pan.y;
            s.pan.moved ||= Math.abs(dx) + Math.abs(dy) > 3;
            s.target.x -= dx / s.cam.k;
            s.target.y -= dy / s.cam.k;
            s.cam.x = s.target.x;
            s.cam.y = s.target.y;
            s.pan.x = sx;
            s.pan.y = sy;
            s.pan.hist = [...s.pan.hist.slice(-4), { x: sx, y: sy, t: now }];
            kick();
            return;
          }
          const h = nodeAt(sx, sy);
          if (h !== s.hover) {
            s.hover = h;
            setHint(h >= 0 ? s.nodes[h].item.name : null);
            kick();
          }
        }}
        onPointerUp={(e) => {
          const s = sim.current;
          const [sx, sy] = local(e);
          setGrab(false);
          if (s.drag) {
            const n = s.nodes[s.drag.node];
            const v = velocity(s.drag.hist);
            const moved = Math.hypot(sx - s.drag.hist[0].x, sy - s.drag.hist[0].y) > 4;
            n.pinned = false;
            n.vx = v.x / s.cam.k; // hand the flick's velocity to the physics
            n.vy = v.y / s.cam.k;
            s.alpha = Math.max(s.alpha, 0.25);
            const node = s.drag.node;
            s.drag = null;
            if (!moved) select(node);
            kick();
            return;
          }
          if (s.pan) {
            const moved = s.pan.moved;
            s.panVel = velocity(s.pan.hist);
            s.pan = null;
            if (!moved) select(-1);
            kick();
          }
        }}
        onPointerLeave={() => {
          const s = sim.current;
          if (!s.drag && !s.pan && s.hover >= 0) {
            s.hover = -1;
            setHint(null);
            kick();
          }
        }}
        onWheel={(e) => {
          const s = sim.current;
          const [sx, sy] = local(e);
          const [wx, wy] = toWorld(sx, sy);
          const k = Math.max(0.15, Math.min(6, s.target.k * Math.exp(-e.deltaY * 0.0015)));
          // Zoom toward the pointer: the world point under the cursor stays put.
          s.target = { k, x: wx - (sx - s.size.w / 2) / k, y: wy - (sy - s.size.h / 2) / k };
          s.follow = false;
          kick();
        }}
        onDoubleClick={() => {
          fit();
          kick();
        }}
        onKeyDown={(e) => {
          const s = sim.current;
          if (e.key === "0" || e.key === "Escape") {
            select(-1);
            fit();
          } else if (e.key === "+" || e.key === "=") s.target.k = Math.min(6, s.target.k * 1.25);
          else if (e.key === "-") s.target.k = Math.max(0.15, s.target.k / 1.25);
          else return;
          e.preventDefault();
          kick();
        }}
      />
      {hint && (
        <div className="web-hint" ref={hintRef}>
          {hint}
        </div>
      )}
    </div>
  );
}
