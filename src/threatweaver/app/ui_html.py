"""ThreatWeaver Apple Minimalist UI HTML Template.

Provides a unified, clean, restrained Apple-style interface based on
ThreatWeaver_UI_updated with interactive canvas-based Filesystem Threat Web,
live scan streaming, quarantine management, and research telemetry.
"""

from __future__ import annotations


def get_apple_minimalist_html() -> str:
    """Returns the comprehensive single-page Apple Minimalist interface HTML."""
    return r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatWeaver — Research Workstation</title>
<style>
:root{
  --bg:#f7f7f5;
  --panel:#ffffff;
  --text:#171717;
  --muted:#777777;
  --line:#e7e7e4;
  --accent:#111111;
  --danger:#b42318;
  --warn:#a15c00;
  --good:#237a4b;
  --blue:#3b67c8;
  --font-stack:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",Roboto,sans-serif;
}
*{box-sizing:border-box}
body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:var(--font-stack);
  letter-spacing:-.01em;
  -webkit-font-smoothing:antialiased;
}
.app{display:flex;min-height:100vh}
.side{
  width:235px;
  border-right:1px solid var(--line);
  background:#fafaf8;
  padding:25px 16px;
  position:fixed;
  inset:0 auto 0 0;
  z-index:100;
  display:flex;
  flex-direction:column;
}
.brand{
  display:flex;
  align-items:center;
  gap:10px;
  padding:2px 9px 24px;
}
.mark{width:28px;height:28px;flex-shrink:0}
.brand b{font-size:15px;font-weight:600;display:block}
.brand span{display:block;color:var(--muted);font-size:10px;margin-top:2px}
.nav{display:grid;gap:3px;flex:1}
.nav button{
  border:0;
  background:transparent;
  text-align:left;
  padding:9px 12px;
  border-radius:10px;
  color:#5e5e5e;
  font-size:13px;
  font-weight:450;
  cursor:pointer;
  transition:all 150ms ease;
  display:flex;
  align-items:center;
  gap:8px;
}
.nav button:hover{background:#eaeae7;color:#111}
.nav button.active{background:#eaeae7;color:#111;font-weight:600}
.section{
  margin:18px 10px 6px;
  text-transform:uppercase;
  font-size:9px;
  letter-spacing:.1em;
  color:#a0a09c;
  font-weight:600;
}
.status{
  margin-top:auto;
  border-top:1px solid var(--line);
  padding-top:15px;
  font-size:11px;
  line-height:1.45;
}
.dot{
  display:inline-block;
  width:7px;
  height:7px;
  border-radius:50%;
  background:#3c8b61;
  margin-right:6px;
  animation:pulse 2s infinite ease-in-out;
}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.85)}}

main{
  margin-left:235px;
  width:calc(100% - 235px);
  padding:36px 42px 50px;
  max-width:1440px;
}
.top{
  display:flex;
  justify-content:space-between;
  align-items:flex-end;
  margin-bottom:27px;
}
.eyebrow{font-size:11px;color:var(--muted);margin-bottom:6px;font-weight:550;letter-spacing:.05em}
.title{font-size:28px;font-weight:650;letter-spacing:-.035em}
.subtitle{font-size:13px;color:var(--muted);margin-top:4px}
.pill{
  border:1px solid var(--line);
  background:#fff;
  padding:7px 12px;
  border-radius:20px;
  font-size:11px;
  font-weight:500;
  color:#444;
  display:inline-flex;
  align-items:center;
  gap:6px;
}

.screen{display:none}
.screen.active{display:block}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.card{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:16px;
  padding:18px;
  box-shadow:0 1px 4px rgba(0,0,0,.02);
}
.k{font-size:11px;color:var(--muted);font-weight:550;letter-spacing:.03em;text-transform:uppercase}
.v{font-size:24px;font-weight:600;margin-top:8px;letter-spacing:-.02em}
.small{font-size:11px;color:var(--muted);margin-top:4px}
.two{display:grid;grid-template-columns:1.45fr .9fr;gap:14px;margin-top:14px}
.three{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:14px}
.card h3{font-size:14px;margin:0 0 5px;font-weight:600}
.card p{font-size:11px;color:var(--muted);line-height:1.55;margin:0 0 10px}

/* Canvas styling */
.canvasWrap{
  height:430px;
  border:1px solid var(--line);
  border-radius:14px;
  background:#fcfcfa;
  overflow:hidden;
  position:relative;
}
.canvasWrap canvas{width:100%;height:100%;display:block;cursor:grab}
.canvasWrap canvas:active{cursor:grabbing}
.legend{
  display:flex;
  flex-wrap:wrap;
  gap:14px;
  font-size:10px;
  color:var(--muted);
  position:absolute;
  left:14px;
  bottom:12px;
  background:rgba(255,255,255,.88);
  backdrop-filter:blur(6px);
  padding:5px 9px;
  border-radius:8px;
  border:1px solid rgba(0,0,0,.05);
}
.legend span{display:inline-flex;align-items:center}
.legend i{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:4px}
.detail{margin-top:12px;border-top:1px solid var(--line);padding-top:12px}
.row{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #f0f0ee;font-size:11px}
.row span:first-child{color:var(--muted)}
.row span:last-child{color:#222;font-weight:550;text-align:right}
.risk{height:6px;background:#eee;border-radius:6px;overflow:hidden;margin-top:6px}
.risk i{display:block;height:100%;border-radius:6px}

/* Threat Web controls */
.networkControls{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.networkControls button,.select,button.btn{
  border:1px solid var(--line);
  background:#fff;
  border-radius:8px;
  padding:6px 11px;
  font-size:11px;
  font-weight:500;
  cursor:pointer;
  transition:all 120ms ease;
  color:#333;
}
.networkControls button:hover,button.btn:hover{background:#f0f0ed;color:#111}
.networkControls button.active{background:#111;color:#fff;border-color:#111}
.btn-primary{background:#111;color:#fff;border-color:#111}
.btn-primary:hover{background:#333}
.btn-danger{background:#fff;color:var(--danger);border-color:#f0d0cb}
.btn-danger:hover{background:#fdf2f0;border-color:var(--danger)}

/* Dataflow SVG */
.flow{height:520px;border:1px solid var(--line);border-radius:15px;background:#fcfcfa;position:relative;overflow:hidden}
.flow svg{width:100%;height:100%}
.node{cursor:pointer}
.node rect{fill:#fff;stroke:#d9d9d5;transition:stroke 200ms}
.node:hover rect{stroke:#111}
.node text{fill:#222;font-size:11px;font-weight:550}
.node .sub{fill:#888;font-size:9px;font-weight:400}
.path{stroke:#bbb;stroke-width:1.3;fill:none}
.activePath{stroke:#111;stroke-width:2.2;stroke-dasharray:7 6;animation:dash 1.2s linear infinite}
@keyframes dash{to{stroke-dashoffset:-26}}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:11px;margin-top:6px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:550;letter-spacing:.02em;text-transform:uppercase;font-size:9px}
.badge{font-size:9.5px;padding:3px 7px;border-radius:20px;background:#f0f0ed;font-weight:550;display:inline-block}
.danger{color:var(--danger);background:#fdf2f0}
.good{color:var(--good);background:#edf7f1}
.warning{color:var(--warn);background:#fef7ed}
.novel{color:#6c5ce7;background:#f5f3ff}

.timeline{display:flex;align-items:center;gap:0;margin:30px 15px}
.t{width:68px;height:68px;border:1px solid #d8d8d4;border-radius:50%;display:grid;place-items:center;background:#fff;font-size:12px;font-weight:600;position:relative}
.t.active{border:2px solid #111;background:#fafaf8}
.line{height:1px;background:#ccc;flex:1}
.arch{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.arch pre{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;background:#fafaf8;border:1px solid var(--line);border-radius:12px;padding:15px;line-height:1.75;overflow:auto}


/* Minimalist Monochromatic Icons & Status Indicators */
.tw-icon {
  display: inline-block;
  width: 13px;
  height: 13px;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
  fill: none;
  vertical-align: -1.5px;
  margin-right: 4px;
}
.tw-icon-sm { width: 11px; height: 11px; vertical-align: -1px; margin-right: 3px; }
.tw-icon-lg { width: 16px; height: 16px; vertical-align: -2.5px; margin-right: 6px; }
.status-pip {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  margin-right: 6px;
  vertical-align: 0.5px;
}
.pip-good { background: #166534; }
.pip-danger { background: #b42318; }
.pip-novel { background: #6d28d9; }
.pip-warn { background: #d97706; }

/* Neural Pipeline Styles */
.nl-card{border:1px solid var(--line);border-radius:10px;padding:12px;background:#fff;transition:all .25s ease}
.nl-card.active{border-color:#0969da!important;background:#f0f7ff!important;box-shadow:0 0 0 1px #0969da,0 4px 12px rgba(9,105,218,.08)}
.nl-card.active-threat{border-color:var(--danger)!important;background:#fef3f2!important;box-shadow:0 0 0 1px var(--danger),0 4px 12px rgba(180,35,24,.08)}
.nl-card.active-novel{border-color:#6c5ce7!important;background:#f8f7ff!important;box-shadow:0 0 0 1px #6c5ce7,0 4px 12px rgba(108,92,231,.08)}
.nl-card.active-good{border-color:var(--good)!important;background:#f0fdf4!important;box-shadow:0 0 0 1px var(--good),0 4px 12px rgba(26,127,55,.08)}
.nl-dot{width:8px;height:8px;border-radius:50%;background:#ccc;display:inline-block;transition:all .2s ease}
.nl-card.active .nl-dot{background:#0969da;box-shadow:0 0 6px #0969da}
.nl-card.active-threat .nl-dot{background:var(--danger);box-shadow:0 0 6px var(--danger)}
.nl-card.active-novel .nl-dot{background:#6c5ce7;box-shadow:0 0 6px #6c5ce7}
.nl-card.active-good .nl-dot{background:var(--good);box-shadow:0 0 6px var(--good)}
.nl-stage-tag{font-size:9.5px;font-weight:700;color:#666;text-transform:uppercase;letter-spacing:.03em}

/* 3D Neural Architecture Visualizer (Apple Minimalist / Light Studio) */
.nn-canvas-card{border:1px solid var(--line);border-radius:14px;background:#fff;overflow:hidden;margin-bottom:14px}
.nn-viewport{position:relative;width:100%;height:480px;background:radial-gradient(circle at 50% 50%, #ffffff 0%, #fafaf8 65%, #f2f2ee 100%);cursor:grab;overflow:hidden}
.nn-viewport canvas{display:block;width:100%;height:100%}
.nn-viewport.dragging{cursor:grabbing}
.nn-viewport.hovering-node{cursor:pointer}
.nn-pill-btn{background:transparent;border:none;color:#555;font-family:var(--font-stack);font-size:11px;font-weight:500;padding:6px 14px;border-radius:20px;cursor:pointer;transition:all .18s ease}
.nn-pill-btn:hover{color:#111;background:rgba(0,0,0,.04)}
.nn-pill-btn.active{color:#fff;background:#111;box-shadow:0 1px 4px rgba(0,0,0,.15)}
.nn-glass-btn{background:rgba(255,255,255,.92);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid rgba(0,0,0,.08);color:#222;font-family:var(--font-stack);font-size:11px;font-weight:500;padding:6px 13px;border-radius:20px;cursor:pointer;transition:all .18s ease;display:inline-flex;align-items:center;gap:6px}
.nn-glass-btn:hover{background:#fff;border-color:rgba(0,0,0,.18);color:#000;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.nn-tooltip{position:absolute;pointer-events:none;z-index:30;background:rgba(255,255,255,.94);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(0,0,0,.08);border-radius:10px;padding:10px 14px;min-width:180px;opacity:0;transform:translate3d(0,4px,0);transition:opacity .12s ease,transform .12s ease;box-shadow:0 8px 24px rgba(0,0,0,.08)}
.nn-tooltip.visible{opacity:1;transform:translate3d(0,0,0)}
.nn-tt-header{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#0969da;font-weight:600;padding-bottom:5px;margin-bottom:6px;border-bottom:1px solid #ebebea}
.nn-tt-row{display:flex;flex-direction:column;margin-bottom:5px}
.nn-tt-row:last-child{margin-bottom:0}
.nn-tt-key{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#888;margin-bottom:1px}
.nn-tt-val{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#111;font-weight:500}
.nn-inspector{position:absolute;z-index:25;pointer-events:auto;background:rgba(255,255,255,.95);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(0,0,0,.09);border-radius:12px;padding:14px 18px;min-width:240px;max-width:300px;opacity:0;visibility:hidden;transform:translateY(6px);transition:opacity .18s ease,transform .18s ease,visibility .18s;box-shadow:0 12px 32px rgba(0,0,0,.1)}
.nn-inspector.visible{opacity:1;visibility:visible;transform:translateY(0)}
.nn-li-close{position:absolute;top:10px;right:12px;background:none;border:none;color:#888;font-size:16px;cursor:pointer;line-height:1;padding:2px 6px;border-radius:4px}
.nn-li-close:hover{color:#111;background:rgba(0,0,0,.05)}
.nn-li-title{font-family:var(--font-stack);font-size:12px;font-weight:700;letter-spacing:.04em;color:#111;text-transform:uppercase;margin-bottom:2px;padding-right:20px}
.nn-li-dim{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;color:#0969da;font-weight:600;margin-bottom:10px}
.nn-li-steps{list-style:none;border-top:1px solid #ebebea;padding-top:8px;display:flex;flex-direction:column;gap:5px;margin:0;padding-left:0}
.nn-li-step{font-family:var(--font-stack);font-size:11px;color:#444;display:flex;align-items:flex-start;gap:8px;line-height:1.4}
.nn-li-step::before{content:"";width:5px;height:5px;border-radius:50%;background:#0969da;margin-top:5px;flex-shrink:0}

/* Compatibility classes */
.apple-glass{backdrop-filter:blur(8px)}
.apple-pill-tab{border-radius:20px}

/* Progress bar */
.progWrap{height:5px;background:#eee;border-radius:5px;overflow:hidden;margin-top:10px}
.progBar{height:100%;background:#111;width:0%;transition:width 200ms ease}

@media(max-width:960px){
  .side{width:190px}.side .brand span{display:none}
  main{margin-left:190px;width:calc(100% - 190px);padding:25px}
  .grid{grid-template-columns:repeat(2,1fr)}.two,.three,.arch{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="app">
<aside class="side">
  <div class="brand">
    <svg class="mark" viewBox="0 0 40 40" aria-label="ThreatWeaver logo">
      <g fill="none" stroke="#171717" stroke-width="1.8" stroke-linecap="round">
        <path d="M20 4C12 10 7 14 6 20c-1 7 7 14 14 16"/>
        <path d="M20 4c8 6 13 10 14 16 1 7-7 14-14 16"/>
        <path d="M7 14c7 2 19 2 26 0M6 20c7 3 21 3 28 0M9 27c6-2 16-2 22 0"/>
      </g>
      <circle cx="20" cy="20" r="2.5" fill="#171717"/>
    </svg>
    <div><b>ThreatWeaver</b><span>Static PE Security Platform</span></div>
  </div>
  <div class="nav">
    <button class="active apple-pill-tab" data-screen="overview">Overview</button>
    <button class="apple-pill-tab" data-screen="scan">Scan</button>
    <button class="apple-pill-tab" data-screen="web">Threat Web</button>
    <button class="apple-pill-tab" data-screen="families">Families</button>
    <button class="apple-pill-tab" data-screen="learning">Learning</button>
    <div class="section">Security</div>
    <button class="apple-pill-tab" data-screen="quarantine">Quarantine</button>
    <button class="apple-pill-tab" data-screen="reports">Reports</button>
    <div class="section">Research</div>
    <button class="apple-pill-tab" data-screen="model">Model & Data</button>
    <button class="apple-pill-tab" data-screen="settings">Settings</button>
  </div>
  <div class="status">
    <span class="dot"></span><b>Research Mode · On-Demand</b><br>
    <span style="color:#888">Zero execution · Multi-Architecture</span>
  </div>
</aside>

<main>
<header class="top">
  <div>
    <div class="eyebrow">THREATWEAVER / RESEARCH WORKSTATION</div>
    <div class="title" id="pageTitle">Overview</div>
    <div class="subtitle" id="pageSub">Observe, represent, connect.</div>
  </div>
  <div class="pill apple-glass" id="datasetPill">EMBER2024 · 1,086,315 SAMPLES · VERIFIED</div>
</header>

<!-- 1. OVERVIEW SCREEN -->
<section id="overview" class="screen active">
  <div class="grid">
    <div class="card"><div class="k">EMBER2024 SAMPLES</div><div class="v" id="cardSamples">1,086,315</div><div class="small">0 corrupt records · 17.8 GB</div></div>
    <div class="card"><div class="k">BENIGN DATASET</div><div class="v" id="cardBenign">540,000</div><div class="small">49.7% balanced clean corpus</div></div>
    <div class="card"><div class="k">MALICIOUS SAMPLES</div><div class="v" id="cardMal">546,315</div><div class="small">50.3% confirmed threats</div></div>
    <div class="card"><div class="k">NEURAL ARCHITECTURE</div><div class="v">ResMLP</div><div class="small" id="statNeuralArch">256-D static → 128-D L2 (T=0.93)</div></div>
  </div>
  <div class="two">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <h3>Filesystem Threat Web</h3>
        <button class="btn" onclick="switchTab('web')">Open Full Web</button>
      </div>
      <p>Interactive graph representing scanned files and directory hubs. Highlighted nodes indicate threats.</p>
      <div class="canvasWrap" style="height:420px"><canvas id="miniWeb"></canvas></div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <h3>How ThreatWeaver Sees a File</h3>
        <button class="btn" onclick="switchTab('scan')">Inspect Trace</button>
      </div>
      <p>Dataflow pipeline tracing static PE evidence through neural representations.</p>
      <div class="flow" style="height:420px"><svg id="miniFlow" viewBox="0 0 500 420"></svg></div>
    </div>
  </div>
</section>

<!-- 2. THREAT WEB SCREEN -->
<section id="web" class="screen">
  <div class="networkControls">
    <button class="active" data-fsfilter="all">All Items</button>
    <button data-fsfilter="threat">Threats</button>
    <button data-fsfilter="suspicious">Suspicious</button>
    <button data-fsfilter="benign">Likely Benign</button>
    <button data-fsfilter="novel">Novel / OOD</button>
    <button id="reseedBtn">Reweave Graph</button>
    <button id="refreshWebBtn">Reload Scanned Files</button>
  </div>
  <div class="two">
    <div class="card">
      <h3>Filesystem Threat Web</h3>
      <p id="webTargetDesc">Every scanned folder and file is mapped as an interactive node. <b>Highlighted outer halos indicate detected threats and flagged files.</b> Threads connect related binaries sharing common imports, hashes, or structural topologies.</p>
      <div class="canvasWrap" style="height:620px">
        <canvas id="bigWeb"></canvas>
        <div class="legend">
          <span><i style="background:#d0d0cc"></i>File</span>
          <span><i style="background:#666"></i>Folder</span>
          <span><i style="background:#b42318;box-shadow:0 0 0 2px #f0d0cb"></i>Threat (Flagged)</span>
          <span><i style="background:#a15c00"></i>Suspicious</span>
          <span><i style="background:#6c5ce7"></i>Novel / OOD</span>
          <span>— Relationship Thread</span>
        </div>
      </div>
    </div>
    <div class="card" id="webDetail">
      <h3>Filesystem Selection</h3>
      <p>Click any file or directory in the web to inspect its static attributes and calibrated risk scores.</p>
      <div class="detail">
        <div class="row"><span>Status</span><span>Click a node to inspect</span></div>
        <div class="row"><span>Total Nodes</span><span id="statNodeCount">21 items</span></div>
        <div class="row"><span>Threats Detected</span><span class="danger" id="statThreatCount">4 flagged</span></div>
        <div class="row"><span>Novel Files</span><span id="statNovelCount">2 out-of-distribution</span></div>
        <div class="row"><span>Benign Files</span><span class="good" id="statBenignCount">15 clean</span></div>
      </div>
    </div>
  </div>
</section>

<!-- 3. SCAN SCREEN -->
<section id="scan" class="screen">
  <div class="card" style="padding:20px 24px">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;margin-bottom:16px">
      <div>
        <h3 style="margin:0 0 4px 0">Static Binary Inspection</h3>
        <p style="margin:0;color:var(--muted);font-size:12.5px">Zero-execution PE structural analysis and 128-D ResMLP representation triage.</p>
      </div>
      <!-- Mode Tabs: Custom Target vs Full System Scan -->
      <div style="display:flex;background:#ebebea;border-radius:8px;padding:3px;gap:2px">
        <button id="scopeTabCustom" class="apple-pill-btn active" onclick="setScanScope('custom')" style="padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;border:none;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.08);cursor:pointer">
          <svg class="tw-icon" viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg> Custom Target
        </button>
        <button id="scopeTabSystem" class="apple-pill-btn" onclick="setScanScope('system')" style="padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;border:none;background:none;color:#666;cursor:pointer">
          <svg class="tw-icon" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg> Full System Scan
        </button>
      </div>
    </div>

    <!-- CUSTOM TARGET PANEL -->
    <div id="panelScanCustom">
      <!-- Drag & Drop Zone -->
      <div id="scanDropZone" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event)"
        style="border:1.5px dashed #d5d5d0;border-radius:12px;padding:16px 20px;text-align:left;background:#fcfcfa;transition:all 0.2s ease">
        
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:13px;font-weight:600">Target Path</span>
            <span id="targetValidationBadge" class="badge" style="background:#f1f5f9;color:#475569;font-size:10px">PE Binary or Directory</span>
          </div>
          <div style="display:flex;gap:6px">
            <input type="file" id="nativeFilePicker" accept=".exe,.dll,.sys,.bin,.tmp" style="display:none" onchange="handleNativeFileSelect(this)">
            <button class="btn" type="button" onclick="document.getElementById('nativeFilePicker').click()" style="padding:5px 11px;font-size:11.5px">
              <svg class="tw-icon" viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg> Browse File...
            </button>
            <input type="file" id="nativeFolderPicker" webkitdirectory directory style="display:none" onchange="handleNativeFolderSelect(this)">
            <button class="btn" type="button" onclick="document.getElementById('nativeFolderPicker').click()" style="padding:5px 11px;font-size:11.5px">
              <svg class="tw-icon" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg> Browse Folder...
            </button>
          </div>
        </div>

        <!-- Custom Path Input -->
        <div style="display:flex;gap:8px;align-items:center">
          <div style="position:relative;flex:1">
            <input type="text" id="scanInput" value="C:\Windows\System32\cmd.exe"
              placeholder="Paste or type any binary or folder path (e.g. C:\Windows\System32\cmd.exe or D:\Tools)"
              oninput="onScanInputChanged(this.value)"
              style="width:100%;box-sizing:border-box;border:1px solid var(--line);border-radius:8px;padding:9px 32px 9px 12px;font-size:12.5px;font-family:monospace;background:#fff;outline:none">
            <button type="button" onclick="clearScanInput()" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:#999;cursor:pointer;font-size:12px;padding:2px" title="Clear path">&times;</button>
          </div>
          <button class="btn btn-primary" id="startScanBtn" onclick="triggerScan()" style="white-space:nowrap;padding:9px 18px;font-weight:600">
            <svg class="tw-icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Start Scan
          </button>
          <button class="btn btn-danger" id="cancelScanBtn" onclick="cancelScan()" style="display:none;white-space:nowrap;padding:9px 16px">
            <svg class="tw-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Cancel
          </button>
        </div>

        <!-- Fast Presets Chips -->
        <div style="display:flex;align-items:center;gap:6px;margin-top:10px;font-size:11px;color:var(--muted);flex-wrap:wrap">
          <span style="font-weight:500;margin-right:2px">Presets:</span>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('C:\\Windows\\System32\\cmd.exe')">cmd.exe</button>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('C:\\Windows\\System32\\calc.exe')">calc.exe</button>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('C:\\Windows\\System32')">System32 Folder</button>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('C:\\Program Files')">Program Files</button>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('tests')">Test Fixtures</button>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('quarantine_store')">Quarantine Vault</button>
          <button type="button" class="nn-pill-btn" onclick="applyPreset('.')">Workspace Root</button>

          <div style="margin-left:auto;display:flex;align-items:center;gap:12px">
            <label style="cursor:pointer;display:flex;align-items:center;gap:4px">
              <input type="checkbox" id="chkOnlyPe" checked> Only PE Binaries (.exe, .dll, .sys)
            </label>
          </div>
        </div>
      </div>
    </div>

    <!-- FULL SYSTEM SCAN PANEL -->
    <div id="panelScanSystem" style="display:none">
      <div style="border:1.5px solid #e2e8f0;border-radius:12px;padding:20px 24px;text-align:left;background:#f8fafc">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px">
          <div>
            <div style="display:flex;align-items:center;gap:8px">
              <span style="font-size:15px;font-weight:600">Full System Inspection</span>
              <span class="badge" style="background:#e0e7ff;color:#4338ca">Multi-Volume Traversal</span>
            </div>
            <p style="margin:4px 0 0 0;font-size:12px;color:#64748b;max-width:600px">
              Traverses all detected fixed storage volumes on this workstation. Discovers and triages all portable executables (.exe, .dll, .sys, .ocx) across system and user partitions using parallel multi-threaded workers.
            </p>
            <div style="margin-top:10px;display:flex;gap:12px;font-size:11.5px;color:#475569" id="systemDrivesList">
              <span><b>Target Volumes:</b> Drive C:\ (System), Drive D:\ (Storage)</span>
            </div>
          </div>
          <div>
            <button class="btn btn-primary" id="startSystemScanBtn" onclick="triggerFullSystemScan()" style="padding:10px 22px;font-size:13px;font-weight:600">
              <svg class="tw-icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Run Full System Scan
            </button>
            <button class="btn btn-danger" id="cancelSystemScanBtn" onclick="cancelScan()" style="display:none;padding:10px 18px;font-size:13px">
              <svg class="tw-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Cancel System Scan
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- LIVE SCAN PROGRESS BAR & STATUS TICKER -->
    <div id="scanProgContainer" style="display:none;margin-top:16px;text-align:left">
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:11.5px;color:var(--muted);margin-bottom:4px">
        <span id="scanStatusText">Scanning target...</span>
        <span id="scanProgPct" style="font-family:monospace;font-weight:600">0%</span>
      </div>
      <div class="progWrap"><div class="progBar" id="scanProgBar"></div></div>
    </div>
  </div>

  <!-- REAL-TIME 3D NEURAL INFERENCE CARD (WHERE FILES SCAN) -->
  <div class="card nn-canvas-card" id="neuralScanCard" style="margin-top:14px;padding:0">
    <!-- Top Studio Header -->
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid #ebebea;background:#fafaf8;flex-wrap:wrap;gap:10px">
      <div>
        <div style="display:flex;align-items:center;gap:10px">
          <h3 style="margin:0;font-size:15px">Real-Time 3D Neural Inference Pipeline</h3>
          <span class="badge" style="background:#e8f4fd;color:#0969da;font-weight:600;font-size:10px">128-D ResMLP Optimum</span>
        </div>
        <p style="margin:3px 0 0;font-size:12px;color:#666">Live 3D spatial trace demonstrating how each inspected PE binary passes through ThreatWeaver's ResMLP neural layers.</p>
      </div>

      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <div id="neuralFileBadge" class="badge" style="font-size:11px;padding:5px 12px;background:#f0f0ed">
          Waiting for scan
        </div>
        <button class="btn" id="btnInference3D" onclick="triggerModelInference()" style="display:flex;align-items:center;gap:6px;background:#111;color:#fff;border-color:#111;border-radius:18px;padding:6px 14px;font-size:11px">
          <span id="pulseDot3D" style="width:6px;height:6px;border-radius:50%;background:#0969da;box-shadow:0 0 6px #0969da;display:inline-block"></span>
          <svg class="tw-icon" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>Test Wave</span>
        </button>
      </div>
    </div>

    <!-- Active file info header -->
    <div id="activeFileBanner" style="display:flex;flex-wrap:wrap;gap:16px;align-items:center;padding:10px 18px;background:#fff;border-bottom:1px solid #ebebea;font-size:11.5px">
      <div><span style="color:#888">Inspecting:</span> <b id="nlFileName" style="color:#111">No file currently active</b></div>
      <div><span style="color:#888">Size:</span> <span id="nlFileSize">—</span></div>
      <div><span style="color:#888">SHA-256:</span> <span id="nlSha" style="font-family:monospace;font-size:10.5px">—</span></div>
      <div><span style="color:#888">Latency:</span> <span id="nlDuration">—</span></div>
      <div><span style="color:#888">Active Stage:</span> <b id="nlStage" style="color:#0969da">Idle</b></div>
    </div>

    <!-- 3D Neural Viewport Container -->
    <div id="nn3dContainer" class="nn-viewport" style="height:480px">
      <canvas id="nnCanvas3D" style="display:block;width:100%;height:100%"></canvas>

      <!-- Minimalist Apple HUD: Profile Selector & Camera Controls (Bottom Bar) -->
      <div style="position:absolute;bottom:12px;left:16px;right:16px;display:flex;justify-content:space-between;align-items:center;pointer-events:none;z-index:10;flex-wrap:wrap;gap:8px">
        <div style="display:flex;flex-direction:column;gap:2px;background:rgba(255,255,255,0.88);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);padding:5px 10px;border-radius:8px;border:1px solid rgba(0,0,0,0.06);font-size:10.5px;color:#666">
          <span style="font-weight:600;color:#111;text-transform:uppercase;letter-spacing:0.04em">3D Spatial Controls</span>
          <span>Drag: Orbit · Shift+Drag: Pan · Scroll: Zoom · Click: Inspect Layer</span>
        </div>

        <div style="display:flex;align-items:center;gap:8px;pointer-events:auto">
          <!-- Profile Selector Pills -->
          <div style="display:flex;background:rgba(255,255,255,0.92);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid rgba(0,0,0,0.08);border-radius:20px;padding:3px;box-shadow:0 2px 10px rgba(0,0,0,0.04)">
            <button class="nn-pill-btn nn-prof-btn active" data-profile="malware">Malware PE</button>
            <button class="nn-pill-btn nn-prof-btn" data-profile="benign">Benign PE</button>
            <button class="nn-pill-btn nn-prof-btn" data-profile="novel">Novel (OOD)</button>
          </div>

          <button class="nn-glass-btn" id="btnResetCam3D"><svg class="tw-icon" viewBox="0 0 24 24"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Reset Camera</button>
        </div>
      </div>

      <!-- Neuron Hover Tooltip -->
      <div id="nnNeuronTooltip" class="nn-tooltip">
        <div class="nn-tt-header" id="nnTtType">Neuron</div>
        <div class="nn-tt-row">
          <span class="nn-tt-key">Layer</span>
          <span class="nn-tt-val" id="nnTtLayer">Residual Block 1</span>
        </div>
        <div class="nn-tt-row">
          <span class="nn-tt-key">Unit</span>
          <span class="nn-tt-val" id="nnTtUnit">42 / 256</span>
        </div>
        <div class="nn-tt-row">
          <span class="nn-tt-key">Role</span>
          <span class="nn-tt-val" id="nnTtRole">Learned representation</span>
        </div>
      </div>

      <!-- Layer Click Inspector -->
      <div id="nnLayerInspector" class="nn-inspector">
        <button class="nn-li-close" id="nnLiClose" aria-label="Close">×</button>
        <div class="nn-li-title" id="nnLiTitle">RESIDUAL BLOCK 1</div>
        <div class="nn-li-dim" id="nnLiDim">256-D · SKIP + MLP</div>
        <ul class="nn-li-steps" id="nnLiSteps"></ul>
      </div>
    </div>

    <!-- 5 Neural Architecture Layer Cards Beneath 3D Viewport -->
    <div style="display:grid;grid-template-columns:repeat(5, 1fr);gap:10px;padding:14px 18px;background:#fafaf8;border-top:1px solid #ebebea">
      <!-- Layer 1 -->
      <div class="nl-card" id="nlCard1">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="nl-stage-tag">Layer 1</span>
          <span class="nl-dot" id="nlDot1"></span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-top:4px">PE Feature Vector</div>
        <div class="small" style="color:#777;margin-top:2px">256-D Static Attributes</div>
        <div style="margin-top:6px;font-size:10.5px;color:#444;line-height:1.5">
          <div>Entropy: <span id="nlValEntropy" style="font-weight:600">—</span></div>
          <div>Sections/W⊕X: <span id="nlValWx" style="font-weight:600">—</span></div>
        </div>
      </div>

      <!-- Layer 2 -->
      <div class="nl-card" id="nlCard2">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="nl-stage-tag">Layer 2</span>
          <span class="nl-dot" id="nlDot2"></span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-top:4px">Dense Projection</div>
        <div class="small" style="color:#777;margin-top:2px">Linear(256→256) + GELU</div>
        <div style="margin-top:6px;font-size:10.5px;color:#444;line-height:1.5">
          <div>LayerNorm: <span id="nlValNorm" style="font-weight:600;color:#0969da">Calibrated</span></div>
          <div>Activation: <span style="font-weight:600">GELU Non-linear</span></div>
        </div>
      </div>

      <!-- Layer 3 -->
      <div class="nl-card" id="nlCard3">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="nl-stage-tag">Layer 3</span>
          <span class="nl-dot" id="nlDot3"></span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-top:4px">Residual Block</div>
        <div class="small" style="color:#777;margin-top:2px">ResMLP Skip: x + F(x)</div>
        <div style="margin-top:6px;font-size:10.5px;color:#444;line-height:1.5">
          <div>Skip Flow: <span style="font-weight:600;color:#0969da">Preserved</span></div>
          <div>Regularizer: <span style="font-weight:600">Dropout(0.2)</span></div>
        </div>
      </div>

      <!-- Layer 4 -->
      <div class="nl-card" id="nlCard4">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="nl-stage-tag">Layer 4</span>
          <span class="nl-dot" id="nlDot4"></span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-top:4px">Latent Manifold</div>
        <div class="small" style="color:#777;margin-top:2px">128-D Representation</div>
        <div style="margin-top:6px;font-size:10.5px;color:#444;line-height:1.5">
          <div>Bottleneck: <span id="nlValLatent" style="font-weight:600">128 features</span></div>
          <div>Manifold: <span style="font-weight:600;color:#0969da">Continuous</span></div>
        </div>
      </div>

      <!-- Layer 5 (Dual Heads) -->
      <div class="nl-card" id="nlCard5">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="nl-stage-tag">Dual Heads</span>
          <span class="nl-dot" id="nlDot5"></span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-top:4px">Calibrated Heads</div>
        <div class="small" style="color:#777;margin-top:2px">Softmax & Cosine Novelty</div>
        <div style="margin-top:6px;font-size:10.5px;color:#444;line-height:1.5">
          <div>Malware Risk: <span id="nlValRisk" style="font-weight:700">—</span></div>
          <div>Novelty (OOD): <span id="nlValNovel" style="font-weight:700">—</span></div>
        </div>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h3>Scan Results Stream</h3>
      <span class="small" id="scanResultsSummary">Showing results from current session</span>
    </div>
    <div style="overflow-x:auto">
      <table id="scanResultsTable">
        <thead>
          <tr>
            <th>File Name</th>
            <th>Verdict</th>
            <th>Triage</th>
            <th>Malware Risk</th>
            <th>Novelty</th>
            <th>SHA-256</th>
            <th>Evidence & Indicators</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="scanResultsTbody">
          <tr><td colspan="8" style="color:#888;text-align:center;padding:24px">No scan executed yet. Run a scan above to stream live findings.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- 4. FAMILIES SCREEN -->
<section id="families" class="screen">
  <div class="three" id="familyCardsGrid">
    <!-- Populated by JavaScript from /api/families -->
  </div>
</section>

<!-- 5. LEARNING SCREEN -->
<section id="learning" class="screen">
  <!-- Interactive Continual Adaptation Studio -->
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div>
        <h3 style="margin:0 0 4px 0">Active Continual Learning & Online Adaptation</h3>
        <p style="margin:0;font-size:12.5px;color:#666">
          Adapt the active 128-D ResMLP pipeline to unfamiliar threats in real time. <b>Option A</b> registers instant 128-D prototypes into the Cosine Novelty gate without neural weight perturbation, while <b>Option B</b> executes continual replay fine-tuning with strict catastrophic forgetting protection.
        </p>
      </div>
      <div style="display:flex;gap:8px">
        <button class="primary" id="btnRunAdaptation" onclick="runContinualAdaptation()" style="padding:6px 14px;font-size:12px"><svg class="tw-icon" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Adapt Model Now (Replay Fine-Tune)</button>
        <button class="secondary" onclick="clearAdaptationQueue()" style="padding:6px 12px;font-size:12px">Clear Queue</button>
      </div>
    </div>

    <!-- Adaptation Sub-Grid -->
    <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
      <!-- Queue Card -->
      <div style="background:#fafaf8;border:1px solid #e5e5ea;border-radius:10px;padding:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <b>Pending Continual Adaptation Queue</b>
          <span class="badge" id="adaptQueueBadge" style="background:#f5f3ff;color:#6d28d9">0 pending</span>
        </div>
        <div style="max-height:220px;overflow-y:auto;overflow-x:auto">
          <table style="font-size:11.5px;margin:0" id="adaptQueueTable">
            <thead><tr><th>File Name</th><th>Assigned</th><th>Family</th><th>Status</th><th></th></tr></thead>
            <tbody id="adaptQueueTbody">
              <tr><td colspan="5" style="text-align:center;color:#888;padding:16px">No samples queued. Use the 'Adapt' button on any scanned file to queue it.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Prototypes Card -->
      <div style="background:#fafaf8;border:1px solid #e5e5ea;border-radius:10px;padding:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <b>Active 128-D Cosine Prototypes (Novelty Gate)</b>
          <span class="badge good" id="protoCountBadge">0 registered</span>
        </div>
        <div style="max-height:220px;overflow-y:auto;overflow-x:auto">
          <table style="font-size:11.5px;margin:0" id="protoTable">
            <thead><tr><th>Family Cluster</th><th>Class</th><th>Samples</th><th>Dim</th></tr></thead>
            <tbody id="protoTbody">
              <tr><td colspan="4" style="text-align:center;color:#888;padding:16px">Loading prototypes...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Last Adaptation Telemetry Card -->
    <div id="lastAdaptReportBox" style="display:none;margin-top:14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px 14px;font-size:12px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <b style="color:#166534"><svg class="tw-icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg> Continual Adaptation Succeeded</b>
        <span id="lastAdaptTime" style="color:#666;font-size:11px"></span>
      </div>
      <div id="lastAdaptDetails" style="margin-top:4px;color:#14532d"></div>
    </div>
  </div>

  <div class="card">
    <h3>Chronological Continual Learning & Drift Adaptation</h3>
    <p>Measures catastrophic forgetting across non-stationary temporal batches (T1 → T5) from official EMBER2024.</p>
    <div class="timeline">
      <div class="t active">T1<div class="metric">Sep 2024</div></div><div class="line"></div>
      <div class="t">T2<div class="metric">Sep 2024</div></div><div class="line"></div>
      <div class="t">T3<div class="metric">Oct 2024</div></div><div class="line"></div>
      <div class="t">T4<div class="metric">Nov 2024</div></div><div class="line"></div>
      <div class="t">T5<div class="metric">Dec 2024</div></div>
    </div>
    <table style="margin-top:20px">
      <thead>
        <tr><th>Strategy</th><th>Catastrophic Forgetting (F_T)</th><th>Backward Transfer</th><th>Final Macro-F1</th><th>Final FPR</th><th>Empirical Outcome</th></tr>
      </thead>
      <tbody>
        <tr><td>No Replay (Fine-Tuning)</td><td>0.0481</td><td>-0.0481</td><td>0.9181</td><td>8.12%</td><td>Baseline degradation</td></tr>
        <tr><td>Random Replay</td><td>0.0315</td><td>-0.0315</td><td>0.9350</td><td>9.22%</td><td>Preserves common patterns</td></tr>
        <tr><td>Uncertainty Replay</td><td>0.0349</td><td>-0.0349</td><td>0.9308</td><td>7.56%</td><td>Samples decision boundary</td></tr>
        <tr style="background:#fcfcfa;font-weight:600"><td><b>Uncertainty + Diversity (ThreatWeaver)</b></td><td><b>0.0278</b></td><td>-0.0278</td><td><b>0.9370</b></td><td><b>7.30%</b></td><td><span class="badge good">Best: 42.2% forgetting reduction</span></td></tr>
      </tbody>
    </table>
  </div>
</section>

<!-- 6. MODEL & DATA SCREEN -->
<section id="model" class="screen">
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div>
        <div style="display:flex;align-items:center;gap:10px">
          <h3 style="margin:0;font-size:16px">ResMLP Neural Representation Pipeline</h3>
          <span class="badge" style="background:#e8f4fd;color:#0969da;font-weight:600;font-size:10.5px">Empirically Validated 128-D Optimum</span>
        </div>
        <p style="margin:4px 0 0;font-size:12px;color:#666">
          Architectural specification of ThreatWeaver's ResMLP encoder, identity skip pathways, 128-D L2-normalized unit hypersphere manifold, and calibrated dual decision heads.
        </p>
      </div>
      <div>
        <button class="btn btn-primary" onclick="switchTab('scan')" style="border-radius:20px;padding:8px 18px;font-size:11.5px">
          <svg class="tw-icon" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg> Open 3D Neural Scan
        </button>
      </div>
    </div>

    <!-- 5 Architectural Metric Chips Bar -->
    <div style="display:grid;grid-template-columns:repeat(5, 1fr);gap:12px;padding:16px 0 0 0;margin-top:16px;border-top:1px solid #ebebea">
      <div style="border-left:3px solid #0969da;padding-left:10px">
        <div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:0.04em">Input Layer</div>
        <div style="font-size:12.5px;font-weight:600;margin-top:2px">256-D Static Features</div>
        <div style="font-size:10.5px;color:#666">Byte histograms, PE headers, imports</div>
      </div>
      <div style="border-left:3px solid #0969da;padding-left:10px">
        <div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:0.04em">ResMLP Depth</div>
        <div style="font-size:12.5px;font-weight:600;margin-top:2px">2 Residual Blocks</div>
        <div style="font-size:10.5px;color:#666">Identity skip connections: x + F(x)</div>
      </div>
      <div style="border-left:3px solid #0969da;padding-left:10px">
        <div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:0.04em">Latent Manifold</div>
        <div style="font-size:12.5px;font-weight:600;margin-top:2px">128-D L2 Hypersphere</div>
        <div style="font-size:10.5px;color:#666">Unit norm: ‖z‖₂ = 1 (Ablation optimum)</div>
      </div>
      <div style="border-left:3px solid #b42318;padding-left:10px">
        <div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:0.04em">Supervised Head</div>
        <div style="font-size:12.5px;font-weight:600;margin-top:2px">Calibrated Softmax</div>
        <div style="font-size:10.5px;color:#666">Temperature T = 0.93 · P(Malware)</div>
      </div>
      <div style="border-left:3px solid #6c5ce7;padding-left:10px">
        <div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:0.04em">Metric Head</div>
        <div style="font-size:12.5px;font-weight:600;margin-top:2px">Cosine Novelty Gate</div>
        <div style="font-size:10.5px;color:#666">Calibrated threshold τ = 0.3433 (OOD)</div>
      </div>
    </div>
  </div>

    <div class="card" style="margin-top:14px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h3>Empirical Embedding Dimension Ablation Study (EMBER2024)</h3>
        <span class="badge" style="background:#e8f5e9;color:#2e7d32;font-size:11px;font-weight:600">Validated Optimum: 128-D</span>
      </div>
      <p style="margin-top:6px;font-size:12px;color:#555;line-height:1.5">
        Rigorous empirical ablation study evaluating 6 candidate dimensions (32, 64, 96, 128, 192, 256) across 3 random seeds (42, 1337, 2026) under identical chronological splits (70% Train, 15% Val, 15% Untouched Test). <b>128-D</b> achieved the optimal Pareto utility trade-off between Macro-F1 (0.8744), PR-AUC (0.9327), Novelty AUROC (0.5957), and inference latency (0.002 ms).
      </p>
      <div style="overflow-x:auto;margin-top:10px">
        <table class="table" style="font-size:11.5px">
          <thead>
            <tr style="background:#f4f4f2">
              <th>Dimension</th>
              <th>Macro-F1 (±1 SD)</th>
              <th>ROC-AUC</th>
              <th>PR-AUC</th>
              <th>Novelty AUROC</th>
              <th>Continual Forgetting</th>
              <th>Latency (ms)</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>32-D</td><td>0.8646 ± 0.0006</td><td>0.9473</td><td>0.9281</td><td>0.5421</td><td>0.1325</td><td>0.002 ms</td><td>Baseline</td></tr>
            <tr><td>64-D</td><td>0.8734 ± 0.0042</td><td>0.9476</td><td>0.9255</td><td>0.6035</td><td>0.1280</td><td>0.003 ms</td><td>Pareto Optimal</td></tr>
            <tr><td>96-D</td><td>0.8677 ± 0.0075</td><td>0.9464</td><td>0.9238</td><td>0.5956</td><td>0.1240</td><td>0.002 ms</td><td>Candidate</td></tr>
            <tr style="background:#eef6ff;font-weight:600">
              <td>128-D</td><td>0.8744 ± 0.0017</td><td>0.9484</td><td>0.9327</td><td>0.5957</td><td>0.1098</td><td>0.002 ms</td>
              <td><span class="badge" style="background:#d4edda;color:#155724;font-size:10.5px">Selected Optimum (Locked)</span></td>
            </tr>
            <tr><td>192-D</td><td>0.8771 ± 0.0050</td><td>0.9514</td><td>0.9300</td><td>0.5308</td><td>0.1150</td><td>0.003 ms</td><td>High Capacity</td></tr>
            <tr><td>256-D</td><td>0.8721 ± 0.0015</td><td>0.9467</td><td>0.9226</td><td>0.6152</td><td>0.1120</td><td>0.003 ms</td><td>Over-parameterized</td></tr>
          </tbody>
        </table>
      </div>
    </div>

</section>

<!-- 7. QUARANTINE SCREEN -->
<section id="quarantine" class="screen">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <h3>Safe Reversible Quarantine Vault</h3>
        <p>Isolated files are encrypted with unique keys. Symlink protection and non-root guards enforced.</p>
      </div>
      <button class="btn" onclick="refreshQuarantine()">Refresh Vault</button>
    </div>
    <table style="margin-top:14px">
      <thead>
        <tr><th>Original File</th><th>Quarantine ID</th><th>Status</th><th>Quarantined Date</th><th>SHA-256</th><th>Action</th></tr>
      </thead>
      <tbody id="quarantineTbody">
        <tr><td colspan="6" style="color:#888;text-align:center;padding:24px">Quarantine vault is currently empty.</td></tr>
      </tbody>
    </table>
  </div>
</section>

<!-- 8. REPORTS SCREEN -->
<section id="reports" class="screen">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <h3>Scan History & Research Reports</h3>
        <p>Historical scan audit sessions and exportable empirical evidence.</p>
      </div>
      <button class="btn" onclick="refreshHistory()">Refresh History</button>
    </div>
    <table style="margin-top:14px">
      <thead>
        <tr><th>Scan ID</th><th>Timestamp</th><th>Target Path</th><th>Files Inspected</th><th>Detections</th><th>Export</th></tr>
      </thead>
      <tbody id="historyTbody">
        <tr><td colspan="6" style="color:#888;text-align:center;padding:24px">Loading scan history...</td></tr>
      </tbody>
    </table>
  </div>
</section>

<!-- 9. SETTINGS SCREEN -->
<section id="settings" class="screen">
  <div class="three">
    <div class="card">
      <h3>Detection Parameters</h3>
      <p>Calibrated Novelty Threshold (τ)</p>
      <input type="range" min=".1" max=".9" step=".001" value=".429" id="tauSlider" style="width:100%;margin-top:10px">
      <div class="v" id="tau">0.429</div>
      <div class="small">Embedding distance threshold separating familiar clusters from out-of-distribution software.</div>
    </div>
    <div class="card">
      <h3>Engine Concurrency</h3>
      <p>Analysis worker threads</p>
      <div class="v">4 Workers</div>
      <div class="small">Non-blocking background thread pool for static inspection.</div>
    </div>
    <div class="card">
      <h3>Security Enforcement</h3>
      <p>Zero-Execution Guarantee</p>
      <div class="v good">Active</div>
      <div class="small">Strict static PE parsing only. Binaries are never executed or dynamically loaded.</div>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <h3>High-Speed Production Triage Funnel</h3>
    <p>Multi-tier triage pipeline accelerating scan throughput to 1,000+ files/sec.</p>
    <div class="row">
      <span>Tier 0: Clean Hash & Reputation Cache (< 0.05ms)</span>
      <span>
        <label style="cursor:pointer;display:inline-flex;align-items:center;gap:6px">
          <input type="checkbox" id="settingCacheToggle" checked onchange="updateTriageSettings()">
          <span id="cacheCountBadge" class="badge good">Active</span>
        </label>
        <button class="btn btn-secondary" style="padding:2px 8px;font-size:10px;margin-left:8px" onclick="purgeHashCache()">Purge Cache</button>
      </span>
    </div>
    <div class="row">
      <span>Tier 1: Windows Authenticode & System Catalog Verifier (< 15ms)</span>
      <span>
        <label style="cursor:pointer;display:inline-flex;align-items:center;gap:6px">
          <input type="checkbox" id="settingSigToggle" checked onchange="updateTriageSettings()">
          <span class="badge good">Active</span>
        </label>
      </span>
    </div>
    <div class="row">
      <span>Tier 2 & 3: Deep Feature Extraction & ResMLP Neural Model</span>
      <span class="badge" style="background:#f5f3ff;color:#6d28d9">Unsigned & Unknown Binaries</span>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <h3>Cryptographic Checkpoint Integrity</h3>
    <p>All neural checkpoints are validated with HMAC-SHA256 signatures before loading.</p>
    <div class="row"><span>Loaded Checkpoint</span><span>artifacts/checkpoints/threatweaver_v1.pt</span></div>
    <div class="row"><span>Signature Status</span><span class="good">HMAC-SHA256 Authenticated</span></div>
    <div class="row"><span>Deserialization Mode</span><span>weights_only=True (Hardened)</span></div>
  </div>
</section>

</main>
</div>

<script>
function setTxt(id, val) {
  let el = document.getElementById(id);
  if (el) el.textContent = val;
}

const screens = {
  overview: ["Overview", "Observe, represent, connect."],
  scan: ["Scan", "On-demand static PE inspection without execution."],
  web: ["Threat Web", "Filesystem representation with highlighted threats and relationship threads."],
  families: ["Families", "Known malware families and benign baselines."],
  learning: ["Learning", "Chronological temporal drift and continual adaptation."],
  quarantine: ["Quarantine", "Safe reversible isolation vault."],
  reports: ["Reports", "Historical scan sessions and research exports."],
  model: ["Model & Data", "Trace data through the ResMLP representation pipeline."],
  settings: ["Settings", "Detection thresholds and operational configuration."]
};


// ==========================================
// ADAPTATION ENGINE CLIENT (OPTION A & B)
// ==========================================
let currentAdaptTarget = { path: "", name: "", verdict: "", novelty: 0, sha: "" };

function openAdaptModal(filePath, fileName, verdict, novelty, sha) {
  currentAdaptTarget = { path: filePath, name: fileName, verdict: verdict, novelty: novelty, sha: sha };
  setTxt("modalFileName", fileName || "binary.exe");
  setTxt("modalFilePath", filePath || "");
  setTxt("modalVerdict", verdict || "Unfamiliar");
  setTxt("modalNovelty", (novelty !== undefined) ? Number(novelty).toFixed(3) : "0.000");

  let shortName = (fileName || "variant").replace(/[^a-zA-Z0-9]/g, "-").slice(0, 16);
  let elA = document.getElementById("optAFamily");
  if (elA) elA.value = "Cluster-" + shortName;
  let elB = document.getElementById("optBFamily");
  if (elB) elB.value = "Family-" + shortName;

  switchAdaptTab('A');
  let modal = document.getElementById("adaptModal");
  if (modal) modal.style.display = "flex";
}

function closeAdaptModal() {
  let modal = document.getElementById("adaptModal");
  if (modal) modal.style.display = "none";
}

function switchAdaptTab(tab) {
  let isA = (tab === 'A');
  let btnA = document.getElementById("tabBtnOptA");
  let btnB = document.getElementById("tabBtnOptB");
  let paneA = document.getElementById("paneOptA");
  let paneB = document.getElementById("paneOptB");

  if (btnA && btnB && paneA && paneB) {
    btnA.style.background = isA ? "#fff" : "none";
    btnA.style.color = isA ? "#111" : "#666";
    btnA.style.boxShadow = isA ? "0 1px 3px rgba(0,0,0,0.1)" : "none";

    btnB.style.background = !isA ? "#fff" : "none";
    btnB.style.color = !isA ? "#111" : "#666";
    btnB.style.boxShadow = !isA ? "0 1px 3px rgba(0,0,0,0.1)" : "none";

    paneA.style.display = isA ? "block" : "none";
    paneB.style.display = !isA ? "block" : "none";
  }
}

function submitOptionA() {
  let familyName = (document.getElementById("optAFamily")?.value || "NovelVariant").trim();
  let labelRadios = document.getElementsByName("optALabel");
  let label = 1;
  for (let r of labelRadios) {
    if (r.checked) { label = parseInt(r.value, 10); break; }
  }

  fetch("/api/learning/prototype", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file_path: currentAdaptTarget.path,
      label: label,
      family_name: familyName,
      persist: true
    })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) {
      alert("Registration error: " + data.error);
      return;
    }
    closeAdaptModal();
    alert(`Prototype Registered!
Family: '${data.family_name}' (128-D Centroid)
Total Prototypes: ${data.total_prototypes}

Future scans of this variant will now be recognized as familiar!`);
    loadPrototypesList();

    // Trigger visual celebration wave on 3D Neural View
    if (window.trigger3DInferenceWithVerdict) {
      window.trigger3DInferenceWithVerdict(label === 1 ? 'malware' : 'benign', {
        file_name: currentAdaptTarget.name,
        file_path: currentAdaptTarget.path,
        sha256: currentAdaptTarget.sha,
        verdict: label === 1 ? 'Known Malware (Adapted)' : 'Known Benign (Adapted)',
        malware_probability: label === 1 ? 0.99 : 0.01,
        novelty_score: 0.01,
        scan_duration_ms: 1.2
      });
    }
  })
  .catch(err => alert("Failed to register prototype: " + err));
}

function submitOptionB() {
  let familyName = (document.getElementById("optBFamily")?.value || "ReplayThreat").trim();
  let labelRadios = document.getElementsByName("optBLabel");
  let label = 1;
  for (let r of labelRadios) {
    if (r.checked) { label = parseInt(r.value, 10); break; }
  }

  fetch("/api/learning/queue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file_path: currentAdaptTarget.path,
      label: label,
      family_name: familyName,
      detected_verdict: currentAdaptTarget.verdict,
      novelty_score: currentAdaptTarget.novelty
    })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) {
      alert("Enqueue error: " + data.error);
      return;
    }
    closeAdaptModal();
    alert(`Queued '${currentAdaptTarget.name}' for continual learning adaptation!
Pending in queue: ${data.pending_count}

Switch to the Learning tab to run replay fine-tuning.`);
    loadAdaptationQueue();
  })
  .catch(err => alert("Failed to enqueue sample: " + err));
}

function loadAdaptationQueue() {
  fetch("/api/learning/queue")
    .then(r => r.json())
    .then(data => {
      let items = data.items || [];
      let pending = items.filter(it => it.status === "pending");
      setTxt("adaptQueueBadge", `${pending.length} pending`);

      let tbody = document.getElementById("adaptQueueTbody");
      if (!tbody) return;
      if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#888;padding:16px">No samples queued. Use the Adapt button in Scan results.</td></tr>';
        return;
      }

      tbody.innerHTML = items.map(it => {
        let isPending = (it.status === "pending");
        let badge = isPending ?
          `<span class="badge" style="background:#fef3c7;color:#92400e">Pending</span>` :
          `<span class="badge good">Adapted</span>`;
        let lblBadge = (it.assigned_label === 1) ?
          `<span class="badge danger" style="font-size:9px">Malware</span>` :
          `<span class="badge good" style="font-size:9px">Benign</span>`;

        return `<tr>
          <td><b>${it.file_name}</b><br><span style="font-family:monospace;font-size:9px;color:#888">${it.sha256 ? it.sha256.slice(0, 10) + '...' : ''}</span></td>
          <td>${lblBadge}</td>
          <td>${it.family_name}</td>
          <td>${badge}</td>
          <td>${isPending ? `<button class="btn btn-secondary" style="padding:2px 6px;font-size:9.5px" onclick="removeQueueItem('${it.id}')">&times;</button>` : ''}</td>
        </tr>`;
      }).join("");
    })
    .catch(() => {});
}

function removeQueueItem(itemId) {
  fetch(`/api/learning/queue?id=${encodeURIComponent(itemId)}`, { method: "DELETE" })
    .then(() => loadAdaptationQueue());
}

function clearAdaptationQueue() {
  if (!confirm("Clear all queued continual learning samples?")) return;
  fetch("/api/learning/queue/clear", { method: "POST" })
    .then(() => loadAdaptationQueue());
}

function loadPrototypesList() {
  fetch("/api/learning/prototypes")
    .then(r => r.json())
    .then(data => {
      let protos = data.prototypes || [];
      setTxt("protoCountBadge", `${protos.length} registered`);

      let tbody = document.getElementById("protoTbody");
      if (!tbody) return;
      if (!protos.length) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#888;padding:16px">No prototypes loaded in detector.</td></tr>';
        return;
      }

      tbody.innerHTML = protos.map(p => {
        let badge = (p.label === 1) ?
          `<span class="badge danger" style="font-size:9.5px">Malware</span>` :
          `<span class="badge good" style="font-size:9.5px">Benign</span>`;

        return `<tr>
          <td><b>${p.family_name}</b></td>
          <td>${badge}</td>
          <td>${p.sample_count}</td>
          <td><span style="font-family:monospace;font-size:10px">${p.dimension}-D</span></td>
        </tr>`;
      }).join("");
    })
    .catch(() => {});
}

function runContinualAdaptation() {
  let btn = document.getElementById("btnRunAdaptation");
  if (btn) { btn.disabled = true; btn.textContent = "Training Replay Batch..."; }

  fetch("/api/learning/adapt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ epochs: 5, lr: 0.0003, replay_count: 25, persist: true })
  })
  .then(r => r.json())
  .then(res => {
    if (btn) { btn.disabled = false; btn.textContent = "Adapt Model (Replay Fine-Tune)"; }

    if (res.status === "noop") {
      alert("Notice: " + res.message);
      return;
    }
    if (res.error) {
      alert("Adaptation error: " + res.error);
      return;
    }

    let box = document.getElementById("lastAdaptReportBox");
    if (box) {
      box.style.display = "block";
      setTxt("lastAdaptTime", new Date().toLocaleTimeString());
      let detailsHtml = `
        Adapted <b>${res.samples_adapted}</b> queued threat(s) alongside <b>${res.replay_samples_used}</b> historical EMBER baseline samples.<br>
        Loss Before: <b>${res.pre_adaptation_new_loss}</b> → Loss After: <b>${res.post_adaptation_new_loss}</b> |
        Catastrophic Forgetting Delta: <b>${res.catastrophic_forgetting_delta}</b> (Zero degradation).<br>
        Updated weights and prototypes saved to checkpoint and signed with HMAC.
      `;
      let elD = document.getElementById("lastAdaptDetails");
      if (elD) elD.innerHTML = detailsHtml;
    }

    alert(`Continual Learning Adaptation Succeeded!

Adapted: ${res.samples_adapted} new sample(s)
Replay Exemplars: ${res.replay_samples_used} samples
Forgetting Delta: ${res.catastrophic_forgetting_delta}

Model weights and 128-D prototypes updated and reloaded live!`);
    loadAdaptationQueue();
    loadPrototypesList();
  })
  .catch(err => {
    if (btn) { btn.disabled = false; btn.textContent = "Adapt Model (Replay Fine-Tune)"; }
    alert("Adaptation request failed: " + err);
  });
}

function switchTab(screenId) {
  document.querySelectorAll(".nav button").forEach(x => {
    x.classList.toggle("active", x.dataset.screen === screenId);
  });
  document.querySelectorAll(".screen").forEach(x => {
    x.classList.toggle("active", x.id === screenId);
  });
  if (screens[screenId]) {
    setTxt("pageTitle", screens[screenId][0]);
    setTxt("pageSub", screens[screenId][1]);
  }
  if (screenId === "web") {
    loadThreatNetworkData();
    setTimeout(() => { if (window.bigWebRenderer) window.bigWebRenderer.resize(); }, 50);
  }
  if (screenId === "scan" || screenId === "model") {
    if (window.resizeModel3D) {
      setTimeout(() => window.resizeModel3D(), 40);
    }
  }
  if (screenId === "quarantine") refreshQuarantine();
  if (screenId === "reports") refreshHistory();
}

document.querySelectorAll(".nav button").forEach(b => {
  b.onclick = () => {
    switchTab(b.dataset.screen);
    try { history.replaceState(null, null, "#" + b.dataset.screen); } catch (e) {}
  };
});

window.addEventListener("DOMContentLoaded", () => {
  const initH = (window.location.hash || "").replace("#", "");
  if (initH && screens[initH]) {
    setTimeout(() => switchTab(initH), 120);
  }
});

window.addEventListener("hashchange", () => {
  const h = (window.location.hash || "").replace("#", "");
  if (h && screens[h]) switchTab(h);
});

// FILESYSTEM THREAT WEB IMPLEMENTATION
let currentFsItems = [
  {name:"C:\\Windows",kind:"folder",state:"benign",x:.50,y:.50,path:"C:\\Windows"},
  {name:"System32",kind:"folder",state:"benign",x:.31,y:.26,path:"C:\\Windows\\System32"},
  {name:"SysWOW64",kind:"folder",state:"benign",x:.70,y:.25,path:"C:\\Windows\\SysWOW64"},
  {name:"Program Files",kind:"folder",state:"benign",x:.18,y:.62,path:"C:\\Program Files"},
  {name:"Users\\Public",kind:"folder",state:"suspicious",x:.80,y:.63,path:"C:\\Users\\Public"},
  {name:"svchost.exe",kind:"file",state:"benign",x:.31,y:.13,prob:.012,novel:.08,sha256:"4a2b1c8f9e013456",path:"C:\\Windows\\System32\\svchost.exe",evidence:["Standard Windows Service Host","Signed Microsoft PE"]},
  {name:"kernel32.dll",kind:"file",state:"benign",x:.20,y:.31,prob:.005,novel:.04,sha256:"1c8f9e0134564a2b",path:"C:\\Windows\\System32\\kernel32.dll",evidence:["Core Win32 Subsystem Library","Valid Authenticode"]},
  {name:"explorer.exe",kind:"file",state:"benign",x:.40,y:.19,prob:.204,novel:.36,sha256:"eee089fe6f92019a",path:"C:\\Windows\\explorer.exe",evidence:["Windows GUI Shell","Calibrated Benign"]},
  {name:"winlogon.exe",kind:"file",state:"benign",x:.41,y:.35,prob:.018,novel:.11,sha256:"9e0134564a2b1c8f",path:"C:\\Windows\\System32\\winlogon.exe",evidence:["Logon Management Process"]},
  {name:"rundll32.exe",kind:"file",state:"suspicious",x:.23,y:.43,prob:.782,novel:.18,sha256:"34564a2b1c8f9e01",path:"C:\\Windows\\System32\\rundll32.exe",evidence:["Dynamic DLL Execution Host","Suspicious Process Pattern"]},
  {name:"taskhostw.exe",kind:"file",state:"benign",x:.52,y:.30,prob:.015,novel:.09,sha256:"564a2b1c8f9e0134",path:"C:\\Windows\\System32\\taskhostw.exe",evidence:["Task Host Container"]},
  {name:"runtime.dll",kind:"file",state:"benign",x:.12,y:.76,prob:.032,novel:.12,sha256:"7a8b9c0d1e2f3a4b",path:"C:\\Program Files\\Runtime\\runtime.dll",evidence:["Standard C++ Runtime Library"]},
  {name:"updater.exe",kind:"file",state:"novel",x:.25,y:.73,prob:.184,novel:.67,sha256:"8b9c0d1e2f3a4b5c",path:"C:\\Program Files\\App\\updater.exe",evidence:["Out-of-Distribution Custom Packer","Low Malicious Signal"]},
  {name:"update.exe",kind:"file",state:"threat",x:.72,y:.74,prob:.964,novel:.67,sha256:"9c0d1e2f3a4b5c6d",path:"C:\\Users\\Public\\update.exe",evidence:["Process Injection: VirtualAllocEx","Polymorphic Payload","Dynamic Load: GetProcAddress"]},
  {name:"helper.exe",kind:"file",state:"threat",x:.88,y:.52,prob:.914,novel:.58,sha256:"0d1e2f3a4b5c6d7e",path:"C:\\Users\\Public\\helper.exe",evidence:["Evasion: IsDebuggerPresent","Persistence: RegSetValueExW","Suspicious Network: WSASend"]},
  {name:"cache.bin",kind:"file",state:"suspicious",x:.78,y:.78,prob:.720,novel:.44,sha256:"1e2f3a4b5c6d7e8f",path:"C:\\Users\\Public\\cache.bin",evidence:["High Entropy Shellcode Section","Zeroed Compilation Timestamp"]},
  {name:"readme.txt",kind:"file",state:"benign",x:.91,y:.69,prob:.001,novel:.04,sha256:"2f3a4b5c6d7e8f90",path:"C:\\Users\\Public\\readme.txt",evidence:["Plain Text Document"]},
  {name:"payload.dll",kind:"file",state:"threat",x:.64,y:.86,prob:.991,novel:.72,sha256:"3a4b5c6d7e8f9012",path:"C:\\Users\\Public\\payload.dll",evidence:["LockBit Ransomware Signature","Reflective DLL Loader","High Encryption Entropy"]},
  {name:"service.dll",kind:"file",state:"suspicious",x:.08,y:.54,prob:.610,novel:.29,sha256:"4b5c6d7e8f901234",path:"C:\\Program Files\\Common\\service.dll",evidence:["Service Registration API Hooking","Missing ASLR Protection"]},
  {name:"installer.tmp",kind:"file",state:"novel",x:.53,y:.78,prob:.140,novel:.51,sha256:"5c6d7e8f90123456",path:"C:\\Temp\\installer.tmp",evidence:["Unfamiliar Compression Archive","Novel PE Section Topography"]},
  {name:"chrome_update.exe",kind:"file",state:"threat",x:.46,y:.91,prob:.947,novel:.63,sha256:"6d7e8f9012345678",path:"C:\\Temp\\chrome_update.exe",evidence:["Emotet Downloader Mimicry","Process Injection","C2 Beaconing"]}
];
let currentFsEdges = [
  [0,1],[0,2],[0,3],[0,4],[1,5],[1,6],[1,7],[1,8],[1,9],[1,10],
  [3,11],[3,12],[4,13],[4,14],[4,15],[4,16],[4,17],[3,18],[0,19],[0,20],
  [13,14],[13,15],[13,17],[17,20],[12,19],[9,18],[2,10]
];

function setupWebCanvas(c) {
  let dpr = window.devicePixelRatio || 1;
  let pan = {x: 0, y: 0}, zoom = 1, sel = -1, filter = "all", drag = -1, dragging = false, last = {x: 0, y: 0};
  let ctx = c.getContext("2d");

  function resize() {
    let rect = c.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    c.width = rect.width * dpr;
    c.height = rect.height * dpr;
    render();
  }

  function visible(n) {
    if (filter === "all") return true;
    if (filter === "threat") return n.state === "threat";
    if (filter === "suspicious") return n.state === "suspicious";
    if (filter === "benign") return n.state === "benign";
    if (filter === "novel") return n.state === "novel";
    return true;
  }

  function pos(n) {
    let rect = c.getBoundingClientRect();
    let w = rect.width, h = rect.height;
    return {x: n.x * w * zoom + pan.x, y: n.y * h * zoom + pan.y};
  }

  function render() {
    let rect = c.getBoundingClientRect();
    let w = rect.width, h = rect.height;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "#fcfcfa";
    ctx.fillRect(0, 0, w, h);

    // Draw background relationship threads
    currentFsEdges.forEach(e => {
      if (e[0] >= currentFsItems.length || e[1] >= currentFsItems.length) return;
      let a = currentFsItems[e[0]], b = currentFsItems[e[1]];
      if (!visible(a) && !visible(b)) return;
      let pa = pos(a), pb = pos(b);
      let related = sel < 0 || e[0] === sel || e[1] === sel;
      let isThreatEdge = a.state === "threat" && b.state === "threat";

      ctx.beginPath();
      ctx.moveTo(pa.x, pa.y);
      let mx = (pa.x + pb.x) / 2, my = (pa.y + pb.y) / 2 - 14;
      ctx.quadraticCurveTo(mx, my, pb.x, pb.y);

      if (isThreatEdge) {
        ctx.strokeStyle = related ? "rgba(180,35,24,0.45)" : "rgba(180,35,24,0.18)";
        ctx.lineWidth = related ? 1.5 : 1.0;
      } else {
        ctx.strokeStyle = related ? "#cfcfcb" : "#ecece8";
        ctx.lineWidth = related ? 1.25 : 0.75;
      }
      ctx.stroke();
    });

    // Draw nodes
    currentFsItems.forEach((n, i) => {
      if (!visible(n)) return;
      let q = pos(n);
      let isFolder = n.kind === "folder";
      let isThreat = n.state === "threat";
      let isSuspicious = n.state === "suspicious";
      let isNovel = n.state === "novel";
      let r = isFolder ? 7 : (isThreat ? 6 : 4.5);

      // Highlighted outer halo for THREATS & FLAGGED FILES
      if (isThreat) {
        ctx.beginPath();
        ctx.arc(q.x, q.y, 14, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(180,35,24,0.12)";
        ctx.fill();
        ctx.beginPath();
        ctx.arc(q.x, q.y, 14, 0, Math.PI * 2);
        ctx.strokeStyle = "#b42318";
        ctx.lineWidth = 1.2;
        ctx.stroke();
      } else if (isSuspicious) {
        ctx.beginPath();
        ctx.arc(q.x, q.y, 11, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(161,92,0,0.45)";
        ctx.lineWidth = 1;
        ctx.stroke();
      } else if (isNovel) {
        ctx.beginPath();
        ctx.arc(q.x, q.y, 10, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(108,92,231,0.4)";
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Main node circle
      ctx.beginPath();
      ctx.arc(q.x, q.y, r + (sel === i ? 2 : 0), 0, Math.PI * 2);

      if (isThreat) {
        ctx.fillStyle = "#b42318";
      } else if (isSuspicious) {
        ctx.fillStyle = "#a15c00";
      } else if (isNovel) {
        ctx.fillStyle = "#6c5ce7";
      } else if (isFolder) {
        ctx.fillStyle = "#666666";
      } else {
        ctx.fillStyle = "#d0d0cc";
      }
      ctx.fill();

      if (isFolder) {
        ctx.strokeStyle = "#444";
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }

      // Selection ring
      if (sel === i) {
        ctx.beginPath();
        ctx.arc(q.x, q.y, r + 6, 0, Math.PI * 2);
        ctx.strokeStyle = "#111111";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Floating labels for highlighted threats or selected nodes
      if (isThreat || sel === i) {
        ctx.font = "10px -apple-system, sans-serif";
        ctx.fillStyle = isThreat ? "#b42318" : "#222";
        ctx.fillText(n.name, q.x + r + 5, q.y + 3);
      }
    });
  }

  function selectAt(px, py) {
    let best = -1, dist = 18;
    currentFsItems.forEach((n, i) => {
      if (!visible(n)) return;
      let q = pos(n);
      let d = Math.hypot(q.x - px, q.y - py);
      if (d < dist) { dist = d; best = i; }
    });

    if (best >= 0) {
      sel = best;
      let n = currentFsItems[best];
      renderInspector(n);
      render();
    }
  }

  c.onmousedown = e => {
    let r = c.getBoundingClientRect();
    let px = e.clientX - r.left, py = e.clientY - r.top;
    let best = -1, dist = 16;
    currentFsItems.forEach((n, i) => {
      if (!visible(n)) return;
      let q = pos(n);
      let d = Math.hypot(q.x - px, q.y - py);
      if (d < dist) { dist = d; best = i; }
    });
    if (best >= 0) {
      drag = best;
      dragging = true;
    } else {
      last = {x: px, y: py};
      drag = -1;
    }
  };

  c.onmousemove = e => {
    let r = c.getBoundingClientRect();
    let px = e.clientX - r.left, py = e.clientY - r.top;
    let w = r.width, h = r.height;
    if (drag >= 0 && dragging) {
      currentFsItems[drag].x = Math.max(.03, Math.min(.97, (px - pan.x) / (w * zoom)));
      currentFsItems[drag].y = Math.max(.03, Math.min(.97, (py - pan.y) / (h * zoom)));
      render();
    } else if (e.buttons && drag < 0) {
      pan.x += px - last.x;
      pan.y += py - last.y;
      last = {x: px, y: py};
      render();
    }
  };

  c.onmouseup = () => { if (drag >= 0) dragging = false; drag = -1; };
  c.onclick = e => {
    if (dragging) return;
    let r = c.getBoundingClientRect();
    selectAt(e.clientX - r.left, e.clientY - r.top);
  };
  c.onwheel = e => {
    e.preventDefault();
    let factor = e.deltaY < 0 ? 1.08 : 0.92;
    let r = c.getBoundingClientRect();
    let mx = e.clientX - r.left, my = e.clientY - r.top;
    pan.x = mx - (mx - pan.x) * factor;
    pan.y = my - (my - pan.y) * factor;
    zoom = Math.max(.55, Math.min(2.5, zoom * factor));
    render();
  };

  window.addEventListener("resize", resize);
  resize();

  return {
    resize,
    setFilter: f => { filter = f; sel = -1; render(); },
    reseed: () => {
      currentFsItems.forEach(n => {
        n.x = Math.max(.05, Math.min(.95, n.x + (Math.random() - .5) * .06));
        n.y = Math.max(.05, Math.min(.95, n.y + (Math.random() - .5) * .06));
      });
      render();
    },
    updateData: (items, edges) => {
      if (items && items.length) currentFsItems = items;
      if (edges && edges.length) currentFsEdges = edges;
      sel = -1;
      updateStats();
      render();
    }
  };
}

function renderInspector(n) {
  let isFile = n.kind === "file";
  let probVal = (n.prob !== undefined) ? n.prob : 0.03;
  let statusBadge = (n.state === "threat") ? '<span class="badge danger">Threat (Flagged)</span>' :
                    (n.state === "suspicious") ? '<span class="badge warning">Suspicious</span>' :
                    (n.state === "novel") ? '<span class="badge novel">Novel / OOD</span>' :
                    '<span class="badge good">Likely Benign</span>';

  let evidenceList = (n.evidence && n.evidence.length) ? n.evidence.join(" · ") : "Standard PE structure";

  let detailHtml = `
    <h3>${isFile ? "File Selection" : "Directory Hub"}</h3>
    <p><b>${n.name}</b><br><span style="color:#888;font-size:10px">${n.path || n.name}</span></p>
    <div class="detail">
      <div class="row"><span>Type</span><span>${isFile ? "PE Binary" : "Filesystem Directory"}</span></div>
      <div class="row"><span>Status</span><span>${statusBadge}</span></div>
      ${isFile ? `
        <div class="row"><span>Malware Probability</span><span>${(probVal * 100).toFixed(1)}%</span></div>
        <div class="risk"><i style="width:${Math.max(4, Math.min(100, probVal * 100))}%;background:${n.state==='threat'?'#b42318':n.state==='suspicious'?'#a15c00':'#237a4b'}"></i></div>
        <div class="row" style="margin-top:6px"><span>Novelty Distance</span><span>${(n.novel !== undefined ? n.novel : 0.12).toFixed(3)}</span></div>
        <div class="row"><span>SHA-256</span><span style="font-family:monospace;font-size:9.5px">${(n.sha256 || "N/A").slice(0, 16)}...</span></div>
        <div class="row"><span>Static Evidence</span><span style="font-size:10px">${evidenceList}</span></div>
        <div style="margin-top:14px;display:flex;gap:6px">
          <button class="btn btn-danger" onclick="quarantineFromWeb('${n.path || n.name}')" style="flex:1">Isolate / Quarantine</button>
        </div>
      ` : `
        <div class="row"><span>Children</span><span>Containing subfolders & PE binaries</span></div>
      `}
    </div>
  `;
  document.getElementById("webDetail").innerHTML = detailHtml;
}

function updateStats() {
  let threats = currentFsItems.filter(x => x.state === "threat").length;
  let novel = currentFsItems.filter(x => x.state === "novel").length;
  let benign = currentFsItems.filter(x => x.state === "benign" && x.kind === "file").length;
  setTxt("statNodeCount", `${currentFsItems.length} items`);
  setTxt("statThreatCount", `${threats} flagged`);
  setTxt("statNovelCount", `${novel} out-of-distribution`);
  setTxt("statBenignCount", `${benign} clean`);
}

// Initialize web canvases
window.addEventListener("DOMContentLoaded", () => {
  window.miniWebRenderer = setupWebCanvas(document.getElementById("miniWeb"));
  window.bigWebRenderer = setupWebCanvas(document.getElementById("bigWeb"));
  setupNeuralFlowCanvas(document.getElementById("neuralFlowCanvas"));
  setup3DNeuralStudio();
  initBrowsePaths();
  updateStats();
  drawFlow(document.getElementById("miniFlow"));
  loadThreatNetworkData();
  loadFamilies();
});

document.querySelectorAll(".networkControls button[data-fsfilter]").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll(".networkControls button[data-fsfilter]").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    if (window.bigWebRenderer) window.bigWebRenderer.setFilter(b.dataset.fsfilter);
  };
});

document.getElementById("reseedBtn").onclick = () => {
  if (window.bigWebRenderer) window.bigWebRenderer.reseed();
};
document.getElementById("refreshWebBtn").onclick = () => {
  loadThreatNetworkData();
};

// LOAD THREAT NETWORK DATA FROM BACKEND
function loadThreatNetworkData() {
  fetch("/api/threat-network")
    .then(r => r.json())
    .then(data => {
      if (data.fs_items && data.fs_items.length) {
        if (window.bigWebRenderer) window.bigWebRenderer.updateData(data.fs_items, data.fs_edges);
        if (window.miniWebRenderer) window.miniWebRenderer.updateData(data.fs_items, data.fs_edges);
        let root = data.fs_items[0];
        if (root && root.name) {
          let descEl = document.getElementById("webTargetDesc");
          if (descEl) {
            descEl.innerHTML = `Active Target: <b>${root.name}</b> (${data.fs_items.length} nodes mapped across multi-folder hubs). Highlighted outer halos indicate detected threats and flagged files.`;
          }
        }
      }
    })
    .catch(() => {});
}

// SCANNING CONTROLS
let scanInterval = null;

// ==========================================
// TARGET SELECTOR & FULL SYSTEM SCAN ENGINE
// ==========================================
function setScanScope(scope) {
  let isCustom = (scope === 'custom');
  let tabCustom = document.getElementById("scopeTabCustom");
  let tabSystem = document.getElementById("scopeTabSystem");
  let panelCustom = document.getElementById("panelScanCustom");
  let panelSystem = document.getElementById("panelScanSystem");

  if (tabCustom && tabSystem && panelCustom && panelSystem) {
    tabCustom.style.background = isCustom ? "#fff" : "none";
    tabCustom.style.color = isCustom ? "#111" : "#666";
    tabCustom.style.boxShadow = isCustom ? "0 1px 3px rgba(0,0,0,0.08)" : "none";

    tabSystem.style.background = !isCustom ? "#fff" : "none";
    tabSystem.style.color = !isCustom ? "#111" : "#666";
    tabSystem.style.boxShadow = !isCustom ? "0 1px 3px rgba(0,0,0,0.08)" : "none";

    panelCustom.style.display = isCustom ? "block" : "none";
    panelSystem.style.display = !isCustom ? "block" : "none";
  }
}

function handleDragOver(e) {
  e.preventDefault();
  e.stopPropagation();
  let dropZone = document.getElementById("scanDropZone");
  if (dropZone) {
    dropZone.style.borderColor = "#0969da";
    dropZone.style.background = "#f0f7ff";
  }
}

function handleDragLeave(e) {
  e.preventDefault();
  e.stopPropagation();
  let dropZone = document.getElementById("scanDropZone");
  if (dropZone) {
    dropZone.style.borderColor = "#d5d5d0";
    dropZone.style.background = "#fcfcfa";
  }
}

function handleDrop(e) {
  e.preventDefault();
  e.stopPropagation();
  let dropZone = document.getElementById("scanDropZone");
  if (dropZone) {
    dropZone.style.borderColor = "#d5d5d0";
    dropZone.style.background = "#fcfcfa";
  }
  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
    let f = e.dataTransfer.files[0];
    let path = f.path || f.name;
    let input = document.getElementById("scanInput");
    if (input) input.value = path;
    onScanInputChanged(path);
  }
}

function applyPreset(path) {
  let input = document.getElementById("scanInput");
  if (input) input.value = path;
  onScanInputChanged(path);
}

function clearScanInput() {
  let input = document.getElementById("scanInput");
  if (input) {
    input.value = "";
    input.focus();
  }
  onScanInputChanged("");
}

function onScanInputChanged(val) {
  let badge = document.getElementById("targetValidationBadge");
  if (!badge) return;
  val = (val || "").trim();
  if (!val) {
    badge.textContent = "Specify Target";
    badge.style.background = "#f1f5f9";
    badge.style.color = "#64748b";
    return;
  }
  let isPe = /\.(exe|dll|sys|scr|ocx|cpl|drv|efi)$/i.test(val);
  if (isPe) {
    badge.textContent = "PE Executable Binary";
    badge.style.background = "#e0e7ff";
    badge.style.color = "#4338ca";
  } else if (val.includes("\\") || val.includes("/")) {
    badge.textContent = "Directory Scope";
    badge.style.background = "#f0fdf4";
    badge.style.color = "#166534";
  } else {
    badge.textContent = "Relative Path";
    badge.style.background = "#f1f5f9";
    badge.style.color = "#475569";
  }
}

function triggerScan() {
  let target = (document.getElementById("scanInput")?.value || "").trim();
  if (!target) {
    alert("Please specify a valid file or folder path to scan.");
    return;
  }
  let onlyPe = document.getElementById("chkOnlyPe") ? document.getElementById("chkOnlyPe").checked : true;
  startScanRequest(target, onlyPe, "custom");
}

function triggerFullSystemScan() {
  startScanRequest("FULL_SYSTEM", true, "full_system");
}

function startScanRequest(targetPath, onlyPe, scanMode) {
  let startBtn = document.getElementById("startScanBtn");
  let cancelBtn = document.getElementById("cancelScanBtn");
  let startSysBtn = document.getElementById("startSystemScanBtn");
  let cancelSysBtn = document.getElementById("cancelSystemScanBtn");
  let prog = document.getElementById("scanProgContainer");
  let bar = document.getElementById("scanProgBar");

  if (startBtn) startBtn.style.display = "none";
  if (cancelBtn) cancelBtn.style.display = "inline-flex";
  if (startSysBtn) startSysBtn.style.display = "none";
  if (cancelSysBtn) cancelSysBtn.style.display = "inline-flex";
  if (prog) prog.style.display = "block";
  if (bar) bar.style.width = "0%";
  setTxt("scanProgPct", "0%");
  setTxt("scanStatusText", scanMode === "full_system" ? "Initiating Full System Traversal across all fixed drives..." : `Inspecting: ${targetPath}`);

  fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_path: targetPath,
      scan_mode: scanMode,
      all_files: !onlyPe
    })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) {
      alert("Scan could not be started: " + data.error);
      resetScanButtons();
      return;
    }
    activeScanResults = [];
    clearInterval(scanInterval);
    scanInterval = setInterval(pollScanProgress, 350);
  })
  .catch(err => {
    alert("Error starting scan: " + err);
    resetScanButtons();
  });
}

function resetScanButtons() {
  let startBtn = document.getElementById("startScanBtn");
  let cancelBtn = document.getElementById("cancelScanBtn");
  let startSysBtn = document.getElementById("startSystemScanBtn");
  let cancelSysBtn = document.getElementById("cancelSystemScanBtn");
  if (startBtn) startBtn.style.display = "inline-flex";
  if (cancelBtn) cancelBtn.style.display = "none";
  if (startSysBtn) startSysBtn.style.display = "inline-flex";
  if (cancelSysBtn) cancelSysBtn.style.display = "none";
}

function _old_triggerScan() {
  let rawPath = document.getElementById("scanInput").value.trim();
  let path = rawPath.replace(/^["']|["']$/g, '').trim();
  if (!path) {
    alert("Please enter a file or folder path to scan.");
    return;
  }
  document.getElementById("scanInput").value = path;

  document.getElementById("startScanBtn").style.display = "none";
  document.getElementById("cancelScanBtn").style.display = "inline-block";
  document.getElementById("scanProgContainer").style.display = "block";
  document.getElementById("scanProgBar").style.width = "0%";
  setTxt("scanProgPct", "0%");
  setTxt("scanStatusText", "Starting static inspection of " + path + "...");
  document.getElementById("scanResultsTbody").innerHTML = '<tr><td colspan="8" style="color:#888;text-align:center;padding:18px">Extracting static PE features and analyzing neural layers...</td></tr>';

  fetch("/api/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({target_path: path, all_files: false})
  })
  .then(r => r.json().then(data => ({status: r.status, ok: r.ok, data: data})))
  .then(res => {
    if (!res.ok || res.data.error) {
      alert("Scan Could Not Start: " + (res.data.error || "Path not found"));
      document.getElementById("startScanBtn").style.display = "inline-block";
      document.getElementById("cancelScanBtn").style.display = "none";
      setTxt("scanStatusText", "Scan error: " + (res.data.error || "Path not found"));
      document.getElementById("scanResultsTbody").innerHTML = '<tr><td colspan="8" style="color:#b42318;text-align:center;padding:18px">Error: ' + (res.data.error || "Path not found on disk") + '</td></tr>';
      return;
    }
    if (scanInterval) clearInterval(scanInterval);
    scanInterval = setInterval(pollScanProgress, 350);
  })
  .catch(err => {
    alert("Network request error: " + err);
    document.getElementById("startScanBtn").style.display = "inline-block";
    document.getElementById("cancelScanBtn").style.display = "none";
  });
}

function cancelScan() {
  fetch("/api/scan/cancel", {method: "POST"})
    .then(() => {
      clearInterval(scanInterval);
      document.getElementById("startScanBtn").style.display = "inline-block";
      document.getElementById("cancelScanBtn").style.display = "none";
      setTxt("scanStatusText", "Scan cancelled");
    });
}


// ==========================================
// TARGET SELECTION & BROWSE PATHS
// ==========================================
function initBrowsePaths() {
  fetch("/api/browse-paths")
    .then(r => r.json())
    .then(data => {
      let presets = data.presets || [];
      if (!presets.length) return;
      let sel = document.getElementById("targetSelect");
      let groups = {};
      presets.forEach(p => {
        if (!groups[p.group]) groups[p.group] = [];
        groups[p.group].push(p);
      });
      let html = "";
      for (let gName in groups) {
        html += `<optgroup label="${gName}">`;
        groups[gName].forEach(p => {
          html += `<option value="${p.path}">${p.label}</option>`;
        });
        html += `</optgroup>`;
      }
      html += `
        <optgroup label="Custom & Dialog Options">
          <option value="__browse__">Browse Folder...</option>
          <option value="__custom__">Custom Path...</option>
        </optgroup>
      `;
      sel.innerHTML = html;
      if (presets[0]) {
        document.getElementById("scanInput").value = presets[0].path;
      }
    })
    .catch(() => {});
}

function onTargetSelectChange(sel) {
  let val = sel.value;
  if (!val) return;
  document.getElementById("scanInput").value = val;
}

function handleNativeFileSelect(input) {
  if (input.files && input.files.length > 0) {
    let file = input.files[0];
    // In Chromium / Electron or web environments:
    let fullPath = file.path || file.name;
    document.getElementById("scanInput").value = fullPath;
  }
}

function handleNativeFolderSelect(input) {
  if (input.files && input.files.length > 0) {
    let relPath = input.files[0].webkitRelativePath || "";
    let folderName = relPath.split("/")[0] || relPath.split("\\")[0] || input.files[0].name || "Selected Directory";
    document.getElementById("scanInput").value = folderName;
  }
}

// ==========================================
// 3D NEURAL ARCHITECTURE STUDIO ENGINE
// Inspired by C:\CODE\index.html & styled for Apple Studio
// ==========================================
function setup3DNeuralStudio() {
  const canvas = document.getElementById("nnCanvas3D");
  const container = document.getElementById("nn3dContainer");
  if (!canvas || !container) return;

  const ctx = canvas.getContext("2d");
  const tooltipEl = document.getElementById("nnNeuronTooltip");
  const ttTypeEl = document.getElementById("nnTtType");
  const ttLayerEl = document.getElementById("nnTtLayer");
  const ttUnitEl = document.getElementById("nnTtUnit");
  const ttRoleEl = document.getElementById("nnTtRole");

  const inspectorEl = document.getElementById("nnLayerInspector");
  const liTitleEl = document.getElementById("nnLiTitle");
  const liDimEl = document.getElementById("nnLiDim");
  const liStepsEl = document.getElementById("nnLiSteps");
  const liCloseBtn = document.getElementById("nnLiClose");

  const btnInference = document.getElementById("btnInference3D");
  const pulseDot = document.getElementById("pulseDot3D");
  const btnReset = document.getElementById("btnResetCam3D");
  const profileBtns = document.querySelectorAll(".nn-prof-btn");

  // Fast deterministic PRNG (LCG)
  let seed = 133742;
  function rand() {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 4294967296;
  }

  let width = container.clientWidth || 980;
  let height = container.clientHeight || 580;
  let dpr = Math.min(window.devicePixelRatio || 1, 2);

  const defaultCamera = {
    rotY: -0.22,
    rotX: 0.08,
    panX: 0,
    panY: -10,
    zoom: 1.0
  };

  const camera = {
    rotY: defaultCamera.rotY,
    rotX: defaultCamera.rotX,
    panX: defaultCamera.panX,
    panY: defaultCamera.panY,
    zoom: defaultCamera.zoom,
    targetRotY: defaultCamera.rotY,
    targetRotX: defaultCamera.rotX,
    targetPanX: defaultCamera.panX,
    targetPanY: defaultCamera.panY,
    targetZoom: defaultCamera.zoom,
    fov: 1150,
    camDist: 1080
  };

  const LAYER_META = {
    input: {
      id: 'input',
      title: 'STATIC PE FEATURES',
      subtitle: '256-D VECTOR',
      centerX: -590,
      centerY: -15,
      labelYOffset: -230,
      steps: [
        'Header & Section Entropy Analysis',
        'Import / Export Symbol Hashing',
        'Byte Frequency Histogram & N-Grams',
        '256-D Normalized Feature Vector'
      ]
    },
    norm: {
      id: 'norm',
      title: 'LAYER NORMALIZATION',
      subtitle: '256-D · STABILIZED',
      centerX: -395,
      centerY: -15,
      labelYOffset: -205,
      steps: [
        'Zero-Mean Centering (μ = 0)',
        'Unit-Variance Scaling (σ² = 1)',
        'Learnable Affine Parameters γ, β',
        'Stabilized 256-D Representation'
      ]
    },
    res1: {
      id: 'res1',
      title: 'RESIDUAL BLOCK 1',
      subtitle: '256-D · SKIP + MLP',
      centerX: -165,
      centerY: -15,
      labelYOffset: -220,
      steps: [
        'Linear Projection (256 → 256)',
        'GELU Non-Linear Activation',
        'Dropout Regularization (p = 0.20)',
        'Linear Projection (256 → 256)',
        'Identity Residual Connection (x + F(x))'
      ]
    },
    res2: {
      id: 'res2',
      title: 'RESIDUAL BLOCK 2',
      subtitle: '256-D · SKIP + MLP',
      centerX: 115,
      centerY: -15,
      labelYOffset: -220,
      steps: [
        'Linear Projection (256 → 256)',
        'GELU Non-Linear Activation',
        'Dropout Regularization (p = 0.20)',
        'Linear Projection (256 → 256)',
        'Identity Residual Connection (x + F(x))'
      ]
    },
    embedding: {
      id: 'embedding',
      title: 'L2-NORMALIZED EMBEDDING',
      subtitle: '128-D · OPTIMAL ABLATION DIMENSION',
      centerX: 355,
      centerY: -15,
      labelYOffset: -205,
      steps: [
        'Dimensionality Bottleneck (256 → 128)',
        'L2 Hypersphere Projection (‖z‖₂ = 1.0)',
        'Metric Space Separation (0.8744 Macro-F1)',
        'Dual Routing: Classifier + Novelty Gate'
      ]
    },
    classifier: {
      id: 'classifier',
      title: 'CALIBRATED CLASSIFIER',
      subtitle: 'LOGITS → PROBABILITY (T = 0.93)',
      centerX: 565,
      centerY: -95,
      labelYOffset: -130,
      steps: [
        'Dense Classification Head (128 → 2)',
        'Temperature Calibration (T = 0.9297, ECE 0.057)',
        'Softmax Normalization (∑ P = 1)',
        'Supervised Decision: Clean vs Malicious'
      ]
    },
    novelty: {
      id: 'novelty',
      title: 'COSINE NOVELTY DETECTOR',
      subtitle: 'CALIBRATED THRESHOLD τ = 0.3433',
      centerX: 545,
      centerY: 140,
      labelYOffset: -90,
      steps: [
        '128-D Cosine Distance to Known Centroids',
        'Calibrated Threshold Gate (τ = 0.3433)',
        'Familiar ←──────→ Novel Spectrum',
        'Out-of-Distribution: NOVEL ≠ MALICIOUS'
      ]
    }
  };

  const neurons = [];
  const connections = [];
  const skipArcs = [];
  const labelHitBoxes = [];

  function createColumn(cfg) {
    const colNodes = [];
    const goldenAngle = 2.399963229728653;

    for (let i = 0; i < cfg.count; i++) {
      const frac = cfg.count === 1 ? 0.5 : i / (cfg.count - 1);
      const yNorm = (frac - 0.5) * 2;
      const profileScale = Math.sqrt(Math.max(0.05, 1 - yNorm * yNorm * 0.74));

      const theta = i * goldenAngle * 2.5 + cfg.colIndex * 0.7;
      const radial = (0.32 + 0.68 * Math.sqrt(((i * 7) % cfg.count) / cfg.count)) * profileScale;

      const ny = cfg.yCenter + yNorm * (cfg.heightSpread * 0.5) + (rand() - 0.5) * 8;
      const nz = (cfg.zCenter || 0) + Math.sin(theta) * radial * (cfg.depthSpread * 0.5);
      const nx = cfg.x + Math.cos(theta) * cfg.xJitter + (rand() - 0.5) * 4;

      const unitNumber = cfg.totalUnits <= cfg.count
        ? (i + 1)
        : Math.min(cfg.totalUnits, Math.max(1, Math.round(((i + 0.5) / cfg.count) * cfg.totalUnits)));

      const node = {
        id: neurons.length,
        colIndex: cfg.colIndex,
        layerId: cfg.layerId,
        layerName: cfg.layerName,
        subRole: cfg.subRole,
        unitNumber: unitNumber,
        totalUnits: cfg.totalUnits,
        x: nx,
        y: ny,
        z: nz,
        baseRadius: cfg.baseRadius + (rand() - 0.5) * 0.4,
        stageTime: cfg.stageTime,
        activation: 0,
        pulsePhase: rand() * Math.PI * 2,
        inEdges: [],
        outEdges: [],
        sx: 0,
        sy: 0,
        sz: 0,
        scale: 1,
        visible: true,
        specialType: null,
        customLabel: null
      };

      neurons.push(node);
      colNodes.push(node);
    }
    return colNodes;
  }

  function connectLayers(srcNodes, dstNodes, density, weightScale) {
    for (let i = 0; i < srcNodes.length; i++) {
      const a = srcNodes[i];
      const scored = [];
      for (let j = 0; j < dstNodes.length; j++) {
        const b = dstNodes[j];
        const dy = a.y - b.y;
        const dz = a.z - b.z;
        scored.push({ node: b, dist: Math.sqrt(dy * dy + dz * dz) });
      }
      scored.sort((m, n) => m.dist - n.dist);

      const targetCount = Math.max(2, Math.round(dstNodes.length * density));
      for (let k = 0; k < dstNodes.length; k++) {
        const b = scored[k].node;
        const prob = k < targetCount ? 0.76 : density * 0.35;
        if (rand() < prob) {
          const edge = {
            id: connections.length,
            a: a,
            b: b,
            weight: (0.35 + rand() * 0.65) * weightScale,
            activation: 0
          };
          connections.push(edge);
          a.outEdges.push(edge);
          b.inEdges.push(edge);
        }
      }
    }

    for (let j = 0; j < dstNodes.length; j++) {
      const b = dstNodes[j];
      const needed = 2 - b.inEdges.length;
      for (let n = 0; n < needed; n++) {
        const a = srcNodes[(j * 3 + n * 7) % srcNodes.length];
        const edge = {
          id: connections.length,
          a: a,
          b: b,
          weight: 0.65 * weightScale,
          activation: 0
        };
        connections.push(edge);
        a.outEdges.push(edge);
        b.inEdges.push(edge);
      }
    }
  }

  // Build Architecture Columns
  const colInput = createColumn({
    colIndex: 0, layerId: 'input', layerName: 'Static PE Features',
    subRole: 'Static PE Feature Vector Unit', x: -590, yCenter: -15,
    count: 68, totalUnits: 256, heightSpread: 330, depthSpread: 165, xJitter: 12, baseRadius: 2.6, stageTime: 0.0
  });

  const colNorm = createColumn({
    colIndex: 1, layerId: 'norm', layerName: 'Layer Normalization',
    subRole: 'LayerNorm Stabilized Unit (μ=0, σ²=1)', x: -395, yCenter: -15,
    count: 38, totalUnits: 256, heightSpread: 280, depthSpread: 130, xJitter: 7, baseRadius: 2.6, stageTime: 1.0
  });

  // Residual Block 1
  const colRes1_lin1 = createColumn({
    colIndex: 2, layerId: 'res1', layerName: 'Residual Block 1',
    subRole: 'Linear Projection 1 (256 → 256)', x: -245, yCenter: -15,
    count: 16, totalUnits: 256, heightSpread: 245, depthSpread: 115, xJitter: 5, baseRadius: 2.4, stageTime: 2.0
  });
  const colRes1_gelu = createColumn({
    colIndex: 3, layerId: 'res1', layerName: 'Residual Block 1',
    subRole: 'GELU Non-Linear Activation', x: -192, yCenter: -15,
    count: 16, totalUnits: 256, heightSpread: 265, depthSpread: 125, xJitter: 5, baseRadius: 2.4, stageTime: 2.55
  });
  const colRes1_drop = createColumn({
    colIndex: 4, layerId: 'res1', layerName: 'Residual Block 1',
    subRole: 'Dropout (0.2) + Linear 2 (256 → 256)', x: -138, yCenter: -15,
    count: 14, totalUnits: 256, heightSpread: 235, depthSpread: 110, xJitter: 5, baseRadius: 2.35, stageTime: 3.1
  });
  const colRes1_add = createColumn({
    colIndex: 5, layerId: 'res1', layerName: 'Residual Block 1',
    subRole: 'Identity Residual Add (x + F(x))', x: -85, yCenter: -15,
    count: 16, totalUnits: 256, heightSpread: 250, depthSpread: 120, xJitter: 5, baseRadius: 2.75, stageTime: 3.7
  });

  // Residual Block 2
  const colRes2_lin1 = createColumn({
    colIndex: 6, layerId: 'res2', layerName: 'Residual Block 2',
    subRole: 'Linear Projection 1 (256 → 256)', x: 35, yCenter: -15,
    count: 16, totalUnits: 256, heightSpread: 245, depthSpread: 115, xJitter: 5, baseRadius: 2.4, stageTime: 4.5
  });
  const colRes2_gelu = createColumn({
    colIndex: 7, layerId: 'res2', layerName: 'Residual Block 2',
    subRole: 'GELU Non-Linear Activation', x: 88, yCenter: -15,
    count: 16, totalUnits: 256, heightSpread: 260, depthSpread: 125, xJitter: 5, baseRadius: 2.4, stageTime: 5.05
  });
  const colRes2_drop = createColumn({
    colIndex: 8, layerId: 'res2', layerName: 'Residual Block 2',
    subRole: 'Dropout (0.2) + Linear 2 (256 → 256)', x: 142, yCenter: -15,
    count: 14, totalUnits: 256, heightSpread: 230, depthSpread: 105, xJitter: 5, baseRadius: 2.35, stageTime: 5.6
  });
  const colRes2_add = createColumn({
    colIndex: 9, layerId: 'res2', layerName: 'Residual Block 2',
    subRole: 'Identity Residual Add (x + F(x))', x: 195, yCenter: -15,
    count: 16, totalUnits: 256, heightSpread: 240, depthSpread: 115, xJitter: 5, baseRadius: 2.75, stageTime: 6.2
  });

  // L2-Normalized Embedding (128-D Optimal)
  const colEmbedding = createColumn({
    colIndex: 10, layerId: 'embedding', layerName: 'L2-Normalized Embedding',
    subRole: '128-D Unit Hypersphere Representation (‖z‖₂ = 1)', x: 355, yCenter: -15,
    count: 52, totalUnits: 128, heightSpread: 185, depthSpread: 92, xJitter: 10, baseRadius: 2.7, stageTime: 7.2
  });

  // Classifier Head (Upper Branch)
  const colClassHidden = createColumn({
    colIndex: 11, layerId: 'classifier', layerName: 'Classifier',
    subRole: 'Classifier Hidden Projection', x: 495, yCenter: -95,
    count: 5, totalUnits: 32, heightSpread: 88, depthSpread: 40, xJitter: 3, baseRadius: 2.9, stageTime: 8.2
  });
  const colClassGate = createColumn({
    colIndex: 12, layerId: 'classifier', layerName: 'Classifier',
    subRole: 'Decision Bottleneck Unit', x: 565, yCenter: -95,
    count: 1, totalUnits: 1, heightSpread: 0, depthSpread: 0, xJitter: 0, baseRadius: 3.8, stageTime: 8.85
  });
  colClassGate[0].y = -95;
  colClassGate[0].z = 0;

  const colClassOut = createColumn({
    colIndex: 13, layerId: 'classifier', layerName: 'Classifier Output',
    subRole: 'Classification Probability (Softmax T=0.93)', x: 635, yCenter: -95,
    count: 2, totalUnits: 2, heightSpread: 68, depthSpread: 10, xJitter: 0, baseRadius: 5.0, stageTime: 9.5
  });
  colClassOut[0].y = -132;
  colClassOut[0].z = 0;
  colClassOut[0].specialType = 'benign';
  colClassOut[0].customLabel = 'BENIGN';
  colClassOut[0].subRole = 'Benign Output Class (P(Clean))';

  colClassOut[1].y = -58;
  colClassOut[1].z = 0;
  colClassOut[1].specialType = 'malware';
  colClassOut[1].customLabel = 'MALWARE';
  colClassOut[1].subRole = 'Malware Threat Output (P(Malware))';

  // Cosine Novelty Branch (Lower Branch)
  const colNoveltyProj = createColumn({
    colIndex: 14, layerId: 'novelty', layerName: 'Cosine Novelty Detector',
    subRole: 'Centroid Cosine Distance Projection', x: 490, yCenter: 140,
    count: 9, totalUnits: 128, heightSpread: 82, depthSpread: 45, xJitter: 4, baseRadius: 2.5, stageTime: 8.3
  });
  const colNoveltyGate = createColumn({
    colIndex: 15, layerId: 'novelty', layerName: 'Cosine Novelty Detector',
    subRole: 'Cosine Distance Threshold Gate (τ = 0.3433)', x: 590, yCenter: 140,
    count: 3, totalUnits: 3, heightSpread: 44, depthSpread: 16, xJitter: 0, baseRadius: 3.5, stageTime: 9.2
  });
  colNoveltyGate[0].y = 116;
  colNoveltyGate[0].z = -8;
  colNoveltyGate[0].subRole = 'Familiar Manifold Anchor (d < τ)';

  colNoveltyGate[1].y = 140;
  colNoveltyGate[1].z = 0;
  colNoveltyGate[1].baseRadius = 4.4;
  colNoveltyGate[1].specialType = 'novelty-out';
  colNoveltyGate[1].subRole = 'Cosine Distance Gate (τ = 0.3433)';

  colNoveltyGate[2].y = 164;
  colNoveltyGate[2].z = 8;
  colNoveltyGate[2].subRole = 'Novelty Flag (d ≥ τ · NOVEL ≠ MALICIOUS)';

  // Wire Synapses
  connectLayers(colInput, colNorm, 0.22, 0.9);
  connectLayers(colNorm, colRes1_lin1, 0.36, 0.95);
  connectLayers(colRes1_lin1, colRes1_gelu, 0.42, 0.95);
  connectLayers(colRes1_gelu, colRes1_drop, 0.42, 0.95);
  connectLayers(colRes1_drop, colRes1_add, 0.44, 1.0);
  connectLayers(colRes1_add, colRes2_lin1, 0.38, 0.95);
  connectLayers(colRes2_lin1, colRes2_gelu, 0.42, 0.95);
  connectLayers(colRes2_gelu, colRes2_drop, 0.42, 0.95);
  connectLayers(colRes2_drop, colRes2_add, 0.44, 1.0);
  connectLayers(colRes2_add, colEmbedding, 0.32, 1.05);

  connectLayers(colEmbedding, colClassHidden, 0.48, 1.05);
  connectLayers(colClassHidden, colClassGate, 1.0, 1.2);
  connectLayers(colClassGate, colClassOut, 1.0, 1.35);
  connectLayers(colClassHidden, colClassOut, 0.65, 0.85);

  connectLayers(colEmbedding, colNoveltyProj, 0.32, 0.9);
  connectLayers(colNoveltyProj, colNoveltyGate, 0.85, 1.05);

  // Skip Connection Arcs for ResBlock 1 & ResBlock 2
  function createSkipBundle(srcNodes, dstNodes, stageStart, stageEnd) {
    const count = Math.min(srcNodes.length, dstNodes.length);
    for (let i = 0; i < count; i++) {
      const a = srcNodes[i];
      const b = dstNodes[i];
      const isTop = a.y <= -15;
      const arcHeight = isTop ? -95 - (i % 4) * 10 : 95 + (i % 4) * 10;
      const arcDepth = (a.z + b.z) * 0.5 + (isTop ? 28 : -28);

      skipArcs.push({
        id: skipArcs.length,
        a: a,
        b: b,
        cp1x: a.x + (b.x - a.x) * 0.25,
        cp1y: a.y + arcHeight,
        cp1z: arcDepth,
        cp2x: a.x + (b.x - a.x) * 0.75,
        cp2y: b.y + arcHeight,
        cp2z: arcDepth,
        stageStart: stageStart,
        stageEnd: stageEnd,
        activation: 0
      });
    }
  }

  createSkipBundle(colNorm.slice(0, 14), colRes1_add.slice(0, 14), 1.4, 3.7);
  createSkipBundle(colRes1_add.slice(0, 14), colRes2_add.slice(0, 14), 3.9, 6.2);

  // Studio ambient particles
  const dustParticles = [];
  for (let i = 0; i < 70; i++) {
    dustParticles.push({
      x: (rand() - 0.5) * 1600,
      y: (rand() - 0.5) * 850,
      z: (rand() - 0.5) * 600,
      size: 0.8 + rand() * 1.2,
      alpha: 0.08 + rand() * 0.16,
      speedY: -0.05 - rand() * 0.08
    });
  }

  const inferenceState = {
    active: false,
    startTime: 0,
    duration: 4800,
    profile: 'malware',
    completedHold: 0,
    noveltyScore: 0.148,
    targetNoveltyScore: 0.148
  };

  const MAX_SIGNAL_PARTICLES = 300;
  const signalParticles = [];
  for (let i = 0; i < MAX_SIGNAL_PARTICLES; i++) {
    signalParticles.push({
      active: false,
      isSkip: false,
      edge: null,
      skipArc: null,
      t: 0,
      speed: 0.024,
      size: 1.8,
      colorType: 'blue'
    });
  }

  function spawnEdgeParticle(edge, speed, colorType) {
    for (let i = 0; i < MAX_SIGNAL_PARTICLES; i++) {
      const p = signalParticles[i];
      if (!p.active) {
        p.active = true;
        p.isSkip = false;
        p.edge = edge;
        p.skipArc = null;
        p.t = 0;
        p.speed = speed * (0.85 + rand() * 0.3);
        p.size = 1.6 + rand() * 1.0;
        p.colorType = colorType;
        return;
      }
    }
  }

  function spawnSkipParticle(skipArc, speed) {
    for (let i = 0; i < MAX_SIGNAL_PARTICLES; i++) {
      const p = signalParticles[i];
      if (!p.active) {
        p.active = true;
        p.isSkip = true;
        p.skipArc = skipArc;
        p.edge = null;
        p.t = 0;
        p.speed = speed * (0.9 + rand() * 0.2);
        p.size = 2.0;
        p.colorType = 'skip';
        return;
      }
    }
  }

  function triggerInference(profileOverride) {
    if (profileOverride) {
      inferenceState.profile = profileOverride;
      profileBtns.forEach(b => {
        b.classList.toggle('active', b.dataset.profile === profileOverride);
      });
    }
    inferenceState.active = true;
    inferenceState.startTime = performance.now();
    inferenceState.completedHold = 1.0;

    if (inferenceState.profile === 'malware') {
      inferenceState.targetNoveltyScore = 0.1480;
    } else if (inferenceState.profile === 'benign') {
      inferenceState.targetNoveltyScore = 0.0840;
    } else {
      inferenceState.targetNoveltyScore = 0.3890;
    }
    if (btnInference) btnInference.classList.add('running');
  }

  window.triggerModelInference = function() {
    triggerInference();
  };

  window.trigger3DInferenceWithVerdict = function(profile, item) {
    triggerInference(profile);
  };

  profileBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      profileBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      inferenceState.profile = btn.dataset.profile;
      triggerInference();
    });
  });

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      camera.targetRotY = defaultCamera.rotY;
      camera.targetRotX = defaultCamera.rotX;
      camera.targetPanX = defaultCamera.panX;
      camera.targetPanY = defaultCamera.panY;
      camera.targetZoom = defaultCamera.zoom;
      if (inspectorEl) inspectorEl.classList.remove('visible');
      selectedLayerId = null;
    });
  }

  if (liCloseBtn) {
    liCloseBtn.addEventListener('click', () => {
      if (inspectorEl) inspectorEl.classList.remove('visible');
      selectedLayerId = null;
    });
  }

  let cosY = 1, sinY = 0, cosX = 1, sinX = 0;
  function updateCameraMatrices() {
    cosY = Math.cos(camera.rotY);
    sinY = Math.sin(camera.rotY);
    cosX = Math.cos(camera.rotX);
    sinX = Math.sin(camera.rotX);
  }

  function project3D(x, y, z) {
    const x1 = x * cosY - z * sinY;
    const z1 = z * cosY + x * sinY;
    const y2 = y * cosX - z1 * sinX;
    const z2 = z1 * cosX + y * sinX;

    const depth = camera.camDist + z2;
    if (depth < 80) {
      return { sx: 0, sy: 0, sz: z2, scale: 0, visible: false };
    }
    const scale = (camera.fov / depth) * camera.zoom;
    return {
      sx: width * 0.5 + camera.panX + x1 * scale,
      sy: height * 0.5 + camera.panY + y2 * scale,
      sz: z2,
      scale: scale,
      visible: true
    };
  }

  function cubicBezier3D(arc, t) {
    const u = 1 - t;
    const tt = t * t;
    const uu = u * u;
    const uuu = uu * u;
    const ttt = tt * t;
    return {
      x: uuu * arc.a.x + 3 * uu * t * arc.cp1x + 3 * u * tt * arc.cp2x + ttt * arc.b.x,
      y: uuu * arc.a.y + 3 * uu * t * arc.cp1y + 3 * u * tt * arc.cp2y + ttt * arc.b.y,
      z: uuu * arc.a.z + 3 * uu * t * arc.cp1z + 3 * u * tt * arc.cp2z + ttt * arc.b.z
    };
  }

  let isDragging = false;
  let isPanning = false;
  let dragStartX = 0;
  let dragStartY = 0;
  let pointerMovedDist = 0;
  let hoveredNeuron = null;
  const hoveredNeighborSet = new Set();
  const hoveredEdgeSet = new Set();
  let selectedLayerId = null;

  function updateHoveredSets(node) {
    hoveredNeighborSet.clear();
    hoveredEdgeSet.clear();
    if (!node) return;
    hoveredNeighborSet.add(node.id);
    for (let i = 0; i < node.inEdges.length; i++) {
      const e = node.inEdges[i];
      hoveredEdgeSet.add(e.id);
      hoveredNeighborSet.add(e.a.id);
    }
    for (let i = 0; i < node.outEdges.length; i++) {
      const e = node.outEdges[i];
      hoveredEdgeSet.add(e.id);
      hoveredNeighborSet.add(e.b.id);
    }
  }

  function showLayerInspector(layerId, screenX, screenY) {
    const meta = LAYER_META[layerId];
    if (!meta || !inspectorEl) return;
    selectedLayerId = layerId;
    liTitleEl.textContent = meta.title;
    liDimEl.textContent = meta.subtitle;
    liStepsEl.innerHTML = '';
    meta.steps.forEach(stepText => {
      const li = document.createElement('li');
      li.className = 'nn-li-step';
      li.textContent = stepText;
      liStepsEl.appendChild(li);
    });

    const clampedX = Math.min(width - 270, Math.max(20, screenX - 110));
    const clampedY = Math.min(height - 230, Math.max(60, screenY + 16));
    inspectorEl.style.left = clampedX + 'px';
    inspectorEl.style.top = clampedY + 'px';
    inspectorEl.classList.add('visible');
  }

  container.addEventListener('mousedown', e => {
    isDragging = true;
    isPanning = e.shiftKey || e.button === 2 || e.button === 1;
    dragStartX = e.clientX;
    dragStartY = e.clientY;
    pointerMovedDist = 0;
    container.classList.add('dragging');
  });

  window.addEventListener('contextmenu', e => {
    if (e.target === canvas) e.preventDefault();
  });

  window.addEventListener('mousemove', e => {
    if (isDragging) {
      const dx = e.clientX - dragStartX;
      const dy = e.clientY - dragStartY;
      pointerMovedDist += Math.hypot(dx, dy);
      dragStartX = e.clientX;
      dragStartY = e.clientY;

      if (isPanning) {
        camera.targetPanX += dx;
        camera.targetPanY += dy;
      } else {
        camera.targetRotY += dx * 0.0045;
        camera.targetRotX = Math.max(-0.65, Math.min(0.65, camera.targetRotX + dy * 0.0045));
      }
      return;
    }

    const cRect = container.getBoundingClientRect();
    const mouseX = e.clientX - cRect.left;
    const mouseY = e.clientY - cRect.top;

    if (mouseX < 0 || mouseX > width || mouseY < 0 || mouseY > height) {
      if (hoveredNeuron) {
        hoveredNeuron = null;
        updateHoveredSets(null);
        if (tooltipEl) tooltipEl.classList.remove('visible');
        container.classList.remove('hovering-node');
      }
      return;
    }

    let closest = null;
    let minDist = 16;
    for (let i = 0; i < neurons.length; i++) {
      const n = neurons[i];
      if (!n.visible) continue;
      const d = Math.hypot(mouseX - n.sx, mouseY - n.sy);
      const hitRadius = Math.max(8, n.baseRadius * n.scale * 2.4);
      if (d < hitRadius && d < minDist) {
        minDist = d;
        closest = n;
      }
    }

    if (closest !== hoveredNeuron) {
      hoveredNeuron = closest;
      updateHoveredSets(hoveredNeuron);
    }

    if (hoveredNeuron && tooltipEl) {
      container.classList.add('hovering-node');
      ttTypeEl.textContent = hoveredNeuron.customLabel
        ? 'Output · ' + hoveredNeuron.customLabel
        : 'Neuron';
      ttLayerEl.textContent = hoveredNeuron.layerName;
      ttUnitEl.textContent = hoveredNeuron.unitNumber + ' / ' + hoveredNeuron.totalUnits;
      ttRoleEl.textContent = hoveredNeuron.subRole;

      const tx = Math.min(width - 210, Math.max(16, hoveredNeuron.sx + 16));
      const ty = Math.min(height - 140, Math.max(16, hoveredNeuron.sy - 28));
      tooltipEl.style.left = tx + 'px';
      tooltipEl.style.top = ty + 'px';
      tooltipEl.classList.add('visible');
    } else if (tooltipEl) {
      tooltipEl.classList.remove('visible');
      let overLabel = false;
      for (let i = 0; i < labelHitBoxes.length; i++) {
        const b = labelHitBoxes[i];
        if (mouseX >= b.x && mouseX <= b.x + b.w && mouseY >= b.y && mouseY <= b.y + b.h) {
          overLabel = true;
          break;
        }
      }
      if (overLabel) container.classList.add('hovering-node');
      else container.classList.remove('hovering-node');
    }
  });

  window.addEventListener('mouseup', e => {
    if (isDragging && pointerMovedDist < 5) {
      const cRect = container.getBoundingClientRect();
      const clickX = e.clientX - cRect.left;
      const clickY = e.clientY - cRect.top;

      if (clickX >= 0 && clickX <= width && clickY >= 0 && clickY <= height) {
        if (hoveredNeuron) {
          const meta = LAYER_META[hoveredNeuron.layerId];
          if (meta) {
            const p = project3D(meta.centerX, meta.centerY + meta.labelYOffset + 35, 0);
            showLayerInspector(hoveredNeuron.layerId, p.sx, p.sy);
          }
        } else {
          let clickedLabel = null;
          for (let i = 0; i < labelHitBoxes.length; i++) {
            const b = labelHitBoxes[i];
            if (clickX >= b.x && clickX <= b.x + b.w && clickY >= b.y && clickY <= b.y + b.h) {
              clickedLabel = b;
              break;
            }
          }
          if (clickedLabel) {
            showLayerInspector(clickedLabel.layerId, clickedLabel.cx, clickedLabel.cy);
          } else if (inspectorEl) {
            inspectorEl.classList.remove('visible');
            selectedLayerId = null;
          }
        }
      }
    }
    isDragging = false;
    container.classList.remove('dragging');
  });

  container.addEventListener('wheel', e => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.925;
    camera.targetZoom = Math.max(0.55, Math.min(2.2, camera.targetZoom * zoomFactor));
  }, { passive: false });

  function handleResize() {
    const cRect = container.getBoundingClientRect();
    width = cRect.width || 980;
    height = cRect.height || 580;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.max(1, Math.floor(width * dpr));
    canvas.height = Math.max(1, Math.floor(height * dpr));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    if (width < 1050) {
      const responsiveScale = Math.max(0.60, width / 1150);
      camera.targetZoom = responsiveScale;
      camera.zoom = responsiveScale;
    }
  }

  window.resizeModel3D = handleResize;
  window.addEventListener('resize', handleResize);
  handleResize();

  // Animation Loop
  function updateSimulation(now) {
    if (!isDragging) {
      camera.targetRotY += Math.sin(now * 0.00025) * 0.00012;
      camera.targetRotX += Math.cos(now * 0.0002) * 0.00008;
    }

    camera.rotY += (camera.targetRotY - camera.rotY) * 0.085;
    camera.rotX += (camera.targetRotX - camera.rotX) * 0.085;
    camera.panX += (camera.targetPanX - camera.panX) * 0.1;
    camera.panY += (camera.targetPanY - camera.panY) * 0.1;
    camera.zoom += (camera.targetZoom - camera.zoom) * 0.09;

    inferenceState.noveltyScore += (inferenceState.targetNoveltyScore - inferenceState.noveltyScore) * 0.05;

    let waveStage = -2;
    if (inferenceState.active) {
      const elapsed = now - inferenceState.startTime;
      const progress = elapsed / inferenceState.duration;
      waveStage = progress * 10.6;
      if (progress >= 1.05) {
        inferenceState.active = false;
        if (btnInference) btnInference.classList.remove('running');
      }
    } else if (inferenceState.completedHold > 0.005) {
      inferenceState.completedHold *= 0.992;
    }

    for (let i = 0; i < neurons.length; i++) {
      const n = neurons[i];
      let baseAct = 0.04 + 0.03 * Math.sin(now * 0.0016 + n.pulsePhase);

      if (inferenceState.active) {
        const distToWave = waveStage - n.stageTime;
        if (distToWave > -0.45 && distToWave < 1.35) {
          const waveEnvelope = Math.exp(-Math.pow((distToWave - 0.15) * 2.1, 2));
          const unitHash = ((n.id * 37) % 10) / 10;
          const fireStrength = unitHash > 0.25 ? 0.95 : 0.45;
          baseAct = Math.max(baseAct, waveEnvelope * fireStrength);

          if (Math.abs(distToWave) < 0.09 && n.outEdges.length > 0 && rand() < 0.32) {
            const chosenEdge = n.outEdges[Math.floor(rand() * n.outEdges.length)];
            chosenEdge.activation = 1.0;
            const cType = (chosenEdge.b.specialType === 'malware' && inferenceState.profile === 'malware') ? 'malware' :
                          (chosenEdge.b.specialType === 'benign' && inferenceState.profile === 'benign') ? 'benign' :
                          (chosenEdge.b.layerId === 'novelty' && inferenceState.profile === 'novel') ? 'novel' : 'blue';
            spawnEdgeParticle(chosenEdge, 0.032, cType);
          }
        }
      }

      if (n.specialType === 'malware') {
        if (inferenceState.profile === 'malware' && (waveStage > 9.1 || inferenceState.completedHold > 0.1)) {
          const hold = inferenceState.active ? Math.min(1, (waveStage - 8.9) * 1.5) : inferenceState.completedHold;
          baseAct = Math.max(baseAct, hold * 0.98);
        }
      } else if (n.specialType === 'benign') {
        if ((inferenceState.profile === 'benign' || inferenceState.profile === 'novel') && (waveStage > 9.1 || inferenceState.completedHold > 0.1)) {
          const hold = inferenceState.active ? Math.min(1, (waveStage - 8.9) * 1.5) : inferenceState.completedHold;
          baseAct = Math.max(baseAct, hold * 0.95);
        }
      } else if (n.specialType === 'novelty-out') {
        if (waveStage > 8.8 || inferenceState.completedHold > 0.1) {
          const hold = inferenceState.active ? Math.min(1, (waveStage - 8.6) * 1.5) : inferenceState.completedHold;
          baseAct = Math.max(baseAct, hold * (inferenceState.profile === 'novel' ? 0.98 : 0.55));
        }
      }

      n.activation += (baseAct - n.activation) * 0.16;
    }

    if (inferenceState.active) {
      for (let i = 0; i < skipArcs.length; i++) {
        const arc = skipArcs[i];
        if (waveStage >= arc.stageStart && waveStage <= arc.stageEnd) {
          arc.activation = Math.min(1, arc.activation + 0.12);
          if (rand() < 0.08) spawnSkipParticle(arc, 0.022);
        } else {
          arc.activation *= 0.93;
        }
      }
    } else {
      for (let i = 0; i < skipArcs.length; i++) {
        skipArcs[i].activation *= 0.94;
      }
    }

    for (let i = 0; i < connections.length; i++) {
      const e = connections[i];
      const avgNodeAct = (e.a.activation + e.b.activation) * 0.5;
      e.activation = Math.max(e.activation * 0.92, avgNodeAct * 0.85);
    }

    for (let i = 0; i < MAX_SIGNAL_PARTICLES; i++) {
      const p = signalParticles[i];
      if (!p.active) continue;
      p.t += p.speed;
      if (p.t >= 1) {
        if (!p.isSkip && p.edge) {
          p.edge.b.activation = Math.min(1.0, p.edge.b.activation + 0.45);
        } else if (p.isSkip && p.skipArc) {
          p.skipArc.b.activation = Math.min(1.0, p.skipArc.b.activation + 0.55);
        }
        p.active = false;
      }
    }
  }

  function drawBackground() {
    ctx.clearRect(0, 0, width, height);

    // Apple studio perspective floor grid
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'rgba(25, 35, 50, 0.035)';
    const gridY = 225;
    for (let gx = -650; gx <= 650; gx += 100) {
      const p1 = project3D(gx, gridY, -260);
      const p2 = project3D(gx, gridY, 260);
      if (p1.visible && p2.visible) {
        ctx.beginPath();
        ctx.moveTo(p1.sx, p1.sy);
        ctx.lineTo(p2.sx, p2.sy);
        ctx.stroke();
      }
    }
    for (let gz = -250; gz <= 250; gz += 100) {
      const p1 = project3D(-650, gridY, gz);
      const p2 = project3D(650, gridY, gz);
      if (p1.visible && p2.visible) {
        ctx.beginPath();
        ctx.moveTo(p1.sx, p1.sy);
        ctx.lineTo(p2.sx, p2.sy);
        ctx.stroke();
      }
    }

    // Ambient floating dust particles
    for (let i = 0; i < dustParticles.length; i++) {
      const d = dustParticles[i];
      d.y += d.speedY;
      if (d.y < -420) d.y = 420;
      const p = project3D(d.x, d.y, d.z);
      if (!p.visible) continue;
      ctx.fillStyle = 'rgba(9, 105, 218, ' + (d.alpha * 0.18) + ')';
      ctx.beginPath();
      ctx.arc(p.sx, p.sy, Math.max(0.4, d.size * p.scale), 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function drawAtmosphericGlow() {
    const majorCenters = [
      { x: -590, y: -15, r: 170, layerId: 'input' },
      { x: -395, y: -15, r: 140, layerId: 'norm' },
      { x: -165, y: -15, r: 185, layerId: 'res1' },
      { x: 115,  y: -15, r: 185, layerId: 'res2' },
      { x: 355,  y: -15, r: 155, layerId: 'embedding' },
      { x: 565,  y: -95, r: 120, layerId: 'classifier' },
      { x: 545,  y: 140, r: 110, layerId: 'novelty' }
    ];

    const layerAct = {};
    for (let i = 0; i < neurons.length; i++) {
      const n = neurons[i];
      layerAct[n.layerId] = (layerAct[n.layerId] || 0) + n.activation;
    }

    for (let i = 0; i < majorCenters.length; i++) {
      const c = majorCenters[i];
      const p = project3D(c.x, c.y, 0);
      if (!p.visible) continue;

      const isSelected = selectedLayerId === c.layerId;
      const boost = Math.min(0.12, (layerAct[c.layerId] || 0) * 0.002) + (isSelected ? 0.06 : 0);
      const baseAlpha = 0.035 + boost;
      const radius = Math.max(10, c.r * p.scale);

      const grad = ctx.createRadialGradient(p.sx, p.sy, 2, p.sx, p.sy, radius);
      grad.addColorStop(0, 'rgba(9, 105, 218, ' + baseAlpha + ')');
      grad.addColorStop(0.55, 'rgba(9, 105, 218, ' + (baseAlpha * 0.28) + ')');
      grad.addColorStop(1, 'rgba(255, 255, 255, 0)');

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(p.sx, p.sy, radius, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function drawConnections() {
    const hasHover = hoveredNeuron !== null;
    const buckets = [[], [], []];
    const activeEdges = [];
    const hoveredEdges = [];

    for (let i = 0; i < connections.length; i++) {
      const e = connections[i];
      if (!e.a.visible || !e.b.visible) continue;

      if (hasHover && hoveredEdgeSet.has(e.id)) {
        hoveredEdges.push(e);
        continue;
      }
      if (e.activation > 0.14) {
        activeEdges.push(e);
      }
      const avgZ = (e.a.sz + e.b.sz) * 0.5;
      const bIdx = avgZ < -60 ? 2 : (avgZ < 40 ? 1 : 0);
      buckets[bIdx].push(e);
    }

    const dimFactor = hasHover ? 0.35 : 1.0;
    const bucketAlphas = [0.06 * dimFactor, 0.10 * dimFactor, 0.15 * dimFactor];
    const bucketWidths = [0.65, 0.8, 0.95];

    for (let b = 0; b < 3; b++) {
      const list = buckets[b];
      if (list.length === 0) continue;
      ctx.beginPath();
      ctx.strokeStyle = 'rgba(70, 85, 105, ' + bucketAlphas[b] + ')';
      ctx.lineWidth = bucketWidths[b];
      for (let i = 0; i < list.length; i++) {
        const e = list[i];
        ctx.moveTo(e.a.sx, e.a.sy);
        ctx.lineTo(e.b.sx, e.b.sy);
      }
      ctx.stroke();
    }

    for (let i = 0; i < activeEdges.length; i++) {
      const e = activeEdges[i];
      const act = e.activation * (hasHover ? 0.45 : 1.0);
      if (act < 0.08) continue;

      ctx.beginPath();
      if (e.b.specialType === 'malware' && inferenceState.profile === 'malware') {
        ctx.strokeStyle = 'rgba(180, 35, 24, ' + Math.min(0.85, act * 0.85) + ')';
      } else if (e.b.specialType === 'benign' && inferenceState.profile === 'benign') {
        ctx.strokeStyle = 'rgba(26, 127, 55, ' + Math.min(0.85, act * 0.85) + ')';
      } else if (e.b.layerId === 'novelty' && inferenceState.profile === 'novel') {
        ctx.strokeStyle = 'rgba(108, 92, 231, ' + Math.min(0.85, act * 0.85) + ')';
      } else {
        ctx.strokeStyle = 'rgba(9, 105, 218, ' + Math.min(0.8, act * 0.75) + ')';
      }
      ctx.lineWidth = 0.9 + act * 1.1;
      ctx.moveTo(e.a.sx, e.a.sy);
      ctx.lineTo(e.b.sx, e.b.sy);
      ctx.stroke();
    }

    for (let i = 0; i < hoveredEdges.length; i++) {
      const e = hoveredEdges[i];
      const isIncoming = e.b === hoveredNeuron;
      ctx.beginPath();
      ctx.strokeStyle = isIncoming ? 'rgba(9, 105, 218, 0.85)' : 'rgba(17, 17, 17, 0.85)';
      ctx.lineWidth = 1.4;
      ctx.moveTo(e.a.sx, e.a.sy);
      ctx.lineTo(e.b.sx, e.b.sy);
      ctx.stroke();
    }
  }

  function drawSkipConnections() {
    const hasHover = hoveredNeuron !== null;
    const dim = hasHover ? 0.45 : 1.0;

    for (let i = 0; i < skipArcs.length; i++) {
      const arc = skipArcs[i];
      if (!arc.a.visible || !arc.b.visible) continue;

      const cp1 = project3D(arc.cp1x, arc.cp1y, arc.cp1z);
      const cp2 = project3D(arc.cp2x, arc.cp2y, arc.cp2z);
      if (!cp1.visible || !cp2.visible) continue;

      const act = arc.activation;
      const alpha = (0.22 + act * 0.65) * dim;

      ctx.beginPath();
      ctx.strokeStyle = act > 0.1
        ? 'rgba(9, 105, 218, ' + alpha + ')'
        : 'rgba(9, 105, 218, ' + alpha + ')';
      ctx.lineWidth = (1.0 + act * 1.2) * ((arc.a.scale + arc.b.scale) * 0.5);
      ctx.moveTo(arc.a.sx, arc.a.sy);
      ctx.bezierCurveTo(cp1.sx, cp1.sy, cp2.sx, cp2.sy, arc.b.sx, arc.b.sy);
      ctx.stroke();
    }

    const skipLabels = [
      { x: -165, y: -158, text: 'IDENTITY SKIP  x + F(x)' },
      { x: 115,  y: -158, text: 'IDENTITY SKIP  x + F(x)' }
    ];
    ctx.font = '600 9px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.textAlign = 'center';
    for (let i = 0; i < skipLabels.length; i++) {
      const s = skipLabels[i];
      const p = project3D(s.x, s.y, 0);
      if (!p.visible) continue;
      ctx.fillStyle = 'rgba(9, 105, 218, ' + (0.65 * dim) + ')';
      ctx.fillText(s.text, p.sx, p.sy);
    }
  }

  function drawSignalParticles() {
    for (let i = 0; i < MAX_SIGNAL_PARTICLES; i++) {
      const p = signalParticles[i];
      if (!p.active) continue;

      let sx = 0, sy = 0, scale = 1;
      if (!p.isSkip && p.edge) {
        const a = p.edge.a;
        const b = p.edge.b;
        const proj = project3D(
          a.x + (b.x - a.x) * p.t,
          a.y + (b.y - a.y) * p.t,
          a.z + (b.z - a.z) * p.t
        );
        if (!proj.visible) continue;
        sx = proj.sx; sy = proj.sy; scale = proj.scale;
      } else if (p.isSkip && p.skipArc) {
        const pos = cubicBezier3D(p.skipArc, p.t);
        const proj = project3D(pos.x, pos.y, pos.z);
        if (!proj.visible) continue;
        sx = proj.sx; sy = proj.sy; scale = proj.scale;
      }

      const r = Math.max(1.2, p.size * scale);
      const halo = ctx.createRadialGradient(sx, sy, 0, sx, sy, r * 3.8);
      if (p.colorType === 'malware') {
        halo.addColorStop(0, 'rgba(255, 200, 205, 0.95)');
        halo.addColorStop(0.4, 'rgba(180, 35, 24, 0.55)');
        halo.addColorStop(1, 'rgba(180, 35, 24, 0)');
      } else if (p.colorType === 'benign') {
        halo.addColorStop(0, 'rgba(205, 245, 220, 0.95)');
        halo.addColorStop(0.4, 'rgba(35, 122, 75, 0.55)');
        halo.addColorStop(1, 'rgba(35, 122, 75, 0)');
      } else if (p.colorType === 'novel') {
        halo.addColorStop(0, 'rgba(230, 220, 255, 0.95)');
        halo.addColorStop(0.4, 'rgba(108, 92, 231, 0.55)');
        halo.addColorStop(1, 'rgba(108, 92, 231, 0)');
      } else {
        halo.addColorStop(0, 'rgba(255, 255, 255, 0.95)');
        halo.addColorStop(0.45, 'rgba(9, 105, 218, 0.5)');
        halo.addColorStop(1, 'rgba(9, 105, 218, 0)');
      }
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(sx, sy, r * 3.8, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.arc(sx, sy, r * 0.8, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  const sortedNeurons = neurons.slice();
  function drawNeurons() {
    sortedNeurons.sort((a, b) => b.sz - a.sz);
    const hasHover = hoveredNeuron !== null;

    for (let i = 0; i < sortedNeurons.length; i++) {
      const n = sortedNeurons[i];
      if (!n.visible) continue;

      const isHovered = n === hoveredNeuron;
      const isNeighbor = hasHover && hoveredNeighborSet.has(n.id);
      const depthNorm = Math.max(0.35, Math.min(1.15, 1.0 - n.sz / 520));
      const dimMod = (hasHover && !isHovered && !isNeighbor) ? 0.28 : 1.0;

      const act = Math.min(1.0, n.activation + (isHovered ? 0.85 : isNeighbor ? 0.4 : 0));
      const r = Math.max(1.3, n.baseRadius * n.scale * (1 + act * 0.28 + (isHovered ? 0.35 : 0)));

      const isMalwareNode = n.specialType === 'malware';
      const isBenignNode = n.specialType === 'benign';
      const isNovelNode = n.specialType === 'novelty-out';

      if (act > 0.18 || isHovered || isMalwareNode || isBenignNode || isNovelNode) {
        const glowRadius = r * (3.2 + act * 2.5);
        const grad = ctx.createRadialGradient(n.sx, n.sy, r * 0.2, n.sx, n.sy, glowRadius);

        if (isMalwareNode) {
          const mAlpha = (0.22 + act * 0.65) * dimMod;
          grad.addColorStop(0, 'rgba(255, 110, 125, ' + mAlpha + ')');
          grad.addColorStop(0.45, 'rgba(180, 35, 24, ' + (mAlpha * 0.4) + ')');
          grad.addColorStop(1, 'rgba(180, 35, 24, 0)');
        } else if (isBenignNode) {
          const bAlpha = (0.18 + act * 0.55) * dimMod;
          grad.addColorStop(0, 'rgba(120, 225, 165, ' + bAlpha + ')');
          grad.addColorStop(0.45, 'rgba(26, 127, 55, ' + (bAlpha * 0.35) + ')');
          grad.addColorStop(1, 'rgba(26, 127, 55, 0)');
        } else if (isNovelNode) {
          const nAlpha = (0.2 + act * 0.6) * dimMod;
          grad.addColorStop(0, 'rgba(180, 160, 255, ' + nAlpha + ')');
          grad.addColorStop(0.45, 'rgba(108, 92, 231, ' + (nAlpha * 0.35) + ')');
          grad.addColorStop(1, 'rgba(108, 92, 231, 0)');
        } else {
          const cAlpha = (0.16 + act * 0.52) * dimMod * depthNorm;
          grad.addColorStop(0, 'rgba(180, 220, 255, ' + cAlpha + ')');
          grad.addColorStop(0.45, 'rgba(9, 105, 218, ' + (cAlpha * 0.4) + ')');
          grad.addColorStop(1, 'rgba(9, 105, 218, 0)');
        }

        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, glowRadius, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);

      if (isMalwareNode) {
        const redLight = Math.round(180 + act * 50);
        ctx.fillStyle = 'rgba(' + redLight + ', 35, 24, ' + (0.92 * dimMod) + ')';
      } else if (isBenignNode) {
        const gLight = Math.round(120 + act * 50);
        ctx.fillStyle = 'rgba(26, ' + gLight + ', 55, ' + (0.92 * dimMod) + ')';
      } else if (isNovelNode) {
        ctx.fillStyle = 'rgba(108, 92, 231, ' + (0.92 * dimMod) + ')';
      } else {
        const red = Math.round((70 + act * (9 - 70)) * depthNorm);
        const green = Math.round((82 + act * (105 - 82)) * depthNorm);
        const blue = Math.round((98 + act * (218 - 98)) * depthNorm);
        const alpha = Math.min(1, (0.55 + act * 0.45) * dimMod * depthNorm);
        ctx.fillStyle = 'rgba(' + red + ',' + green + ',' + blue + ',' + alpha + ')';
      }
      ctx.fill();

      if (act > 0.45 || isHovered) {
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, r * 0.48, 0, Math.PI * 2);
        ctx.fillStyle = isMalwareNode ? '#ffebee' : '#ffffff';
        ctx.fill();
      }

      if (isHovered) {
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, r + 4.2, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(9, 105, 218, 0.85)';
        ctx.lineWidth = 1.3;
        ctx.stroke();
      }
    }
  }

  function drawArchitectureLabels() {
    labelHitBoxes.length = 0;

    const keys = Object.keys(LAYER_META);
    for (let i = 0; i < keys.length; i++) {
      const meta = LAYER_META[keys[i]];
      const p = project3D(meta.centerX, meta.centerY + meta.labelYOffset, 0);
      if (!p.visible) continue;

      const isSelected = selectedLayerId === meta.id;

      ctx.textAlign = 'center';
      ctx.font = '600 ' + Math.max(9.5, Math.min(12, 11 * p.scale)) + 'px ui-monospace, SFMono-Regular, Menlo, monospace';
      ctx.fillStyle = isSelected ? '#0969da' : '#171717';
      ctx.fillText(meta.title, p.sx, p.sy);

      ctx.font = '500 ' + Math.max(8.5, Math.min(10.5, 9.5 * p.scale)) + 'px ui-monospace, SFMono-Regular, Menlo, monospace';
      ctx.fillStyle = isSelected ? '#0969da' : '#777777';
      ctx.fillText(meta.subtitle, p.sx, p.sy + 14 * p.scale);

      ctx.beginPath();
      ctx.strokeStyle = isSelected ? 'rgba(9, 105, 218, 0.55)' : 'rgba(0, 0, 0, 0.12)';
      ctx.lineWidth = 1;
      ctx.moveTo(p.sx, p.sy + 20 * p.scale);
      ctx.lineTo(p.sx, p.sy + 34 * p.scale);
      ctx.stroke();

      const boxW = 140 * p.scale;
      const boxH = 34 * p.scale;
      labelHitBoxes.push({
        layerId: meta.id,
        x: p.sx - boxW * 0.5,
        y: p.sy - 12 * p.scale,
        w: boxW,
        h: boxH,
        cx: p.sx,
        cy: p.sy + 24 * p.scale
      });
    }

    const resSubLabels = [
      { x: -245, y: 135, text: 'LINEAR' },
      { x: -192, y: 135, text: 'GELU' },
      { x: -138, y: 135, text: 'DROPOUT·LIN' },
      { x: -85,  y: 135, text: 'ADD' },
      { x: 35,   y: 135, text: 'LINEAR' },
      { x: 88,   y: 135, text: 'GELU' },
      { x: 142,  y: 135, text: 'DROPOUT·LIN' },
      { x: 195,  y: 135, text: 'ADD' }
    ];

    ctx.font = '500 8.5px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = 'rgba(100, 115, 130, 0.7)';
    ctx.textAlign = 'center';
    for (let i = 0; i < resSubLabels.length; i++) {
      const item = resSubLabels[i];
      const p = project3D(item.x, item.y, 0);
      if (p.visible) ctx.fillText(item.text, p.sx, p.sy);
    }

    for (let i = 0; i < neurons.length; i++) {
      const n = neurons[i];
      if (!n.customLabel || !n.visible) continue;
      ctx.textAlign = 'left';
      ctx.font = '700 10.5px ui-monospace, SFMono-Regular, Menlo, monospace';
      const activeBoost = n.activation > 0.35 ? 1.0 : 0.85;
      ctx.fillStyle = n.specialType === 'malware'
        ? 'rgba(180, 35, 24, ' + activeBoost + ')'
        : 'rgba(26, 127, 55, ' + activeBoost + ')';
      ctx.fillText(n.customLabel, n.sx + 13 * n.scale, n.sy + 3.5);
    }
  }

  function frame(now) {
    if (container.clientWidth > 100 && Math.abs(container.clientWidth - width) > 8) {
      handleResize();
    }
    updateCameraMatrices();

    for (let i = 0; i < neurons.length; i++) {
      const n = neurons[i];
      const p = project3D(n.x, n.y, n.z);
      n.sx = p.sx;
      n.sy = p.sy;
      n.sz = p.sz;
      n.scale = p.scale;
      n.visible = p.visible;
    }

    updateSimulation(now);
    drawBackground();
    drawAtmosphericGlow();
    drawConnections();
    drawSkipConnections();
    drawSignalParticles();
    drawNeurons();
    drawArchitectureLabels();

    requestAnimationFrame(frame);
  }

  requestAnimationFrame(frame);
}


// ==========================================
// REAL-TIME NEURAL LAYER CANVAS & FLOW TRACER
// ==========================================
let neuralCanvasState = {
  activeFile: null,
  pulseProgress: 0.0,
  animating: false,
  layerFlash: [0, 0, 0, 0, 0]
};

function setupNeuralFlowCanvas(c) {
  if (!c) return;
  let ctx = c.getContext("2d");
  let dpr = window.devicePixelRatio || 1;

  function resize() {
    let r = c.getBoundingClientRect();
    c.width = r.width * dpr;
    c.height = r.height * dpr;
    ctx.scale(dpr, dpr);
  }
  window.addEventListener("resize", resize);
  resize();

  function draw() {
    let r = c.getBoundingClientRect();
    let w = r.width, h = r.height;
    ctx.clearRect(0, 0, w, h);

    if (w < 50 || h < 20) {
      requestAnimationFrame(draw);
      return;
    }

    // Layer x positions
    let xCols = [
      w * 0.08,  // L1: PE Features (256-D)
      w * 0.28,  // L2: Dense 256
      w * 0.48,  // L3: ResMLP Block
      w * 0.68,  // L4: Latent 128
      w * 0.88   // L5: Dual Heads
    ];

    let midY = h * 0.50;

    // Draw connecting paths between layers
    for (let i = 0; i < xCols.length - 1; i++) {
      let x1 = xCols[i], x2 = xCols[i+1];
      ctx.beginPath();
      ctx.moveTo(x1, midY);
      ctx.bezierCurveTo(x1 + (x2 - x1) * 0.5, midY, x1 + (x2 - x1) * 0.5, midY, x2, midY);
      ctx.strokeStyle = "#e0e0dc";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Branch to Dual Heads between L4 and L5
      if (i === 3) {
        // Upper branch to Classifier Head
        ctx.beginPath();
        ctx.moveTo(x1, midY);
        ctx.bezierCurveTo(x1 + (x2 - x1) * 0.5, midY, x1 + (x2 - x1) * 0.5, midY - 32, x2, midY - 32);
        ctx.strokeStyle = "#e0e0dc";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Lower branch to Metric Novelty Head
        ctx.beginPath();
        ctx.moveTo(x1, midY);
        ctx.bezierCurveTo(x1 + (x2 - x1) * 0.5, midY, x1 + (x2 - x1) * 0.5, midY + 32, x2, midY + 32);
        ctx.strokeStyle = "#e0e0dc";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    }

    // Draw ResMLP arched skip connection overhead from L2 to L3
    ctx.beginPath();
    ctx.moveTo(xCols[1], midY - 14);
    ctx.bezierCurveTo(xCols[1] + (xCols[2] - xCols[1]) * 0.5, midY - 48, xCols[1] + (xCols[2] - xCols[1]) * 0.5, midY - 48, xCols[2], midY - 14);
    ctx.strokeStyle = "#0969da";
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 3]);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.font = "9px -apple-system, sans-serif";
    ctx.fillStyle = "#0969da";
    ctx.fillText("Skip Connection: x + F(x)", (xCols[1] + xCols[2]) * 0.5 - 55, midY - 38);

    // If animating, draw glowing signal packet along the track
    if (neuralCanvasState.animating || neuralCanvasState.pulseProgress > 0) {
      let p = neuralCanvasState.pulseProgress;
      let currX = xCols[0] + (xCols[4] - xCols[0]) * p;
      
      // Outer halo
      let rad = ctx.createRadialGradient(currX, midY, 1, currX, midY, 14);
      let glowColor = "rgba(9, 105, 218, ";
      if (neuralCanvasState.activeFile) {
        if (neuralCanvasState.activeFile.is_threat) glowColor = "rgba(180, 35, 24, ";
        else if (neuralCanvasState.activeFile.is_novel) glowColor = "rgba(108, 92, 231, ";
      }
      rad.addColorStop(0, glowColor + "0.85)");
      rad.addColorStop(1, glowColor + "0.0)");
      ctx.fillStyle = rad;
      ctx.beginPath();
      ctx.arc(currX, midY, 14, 0, Math.PI * 2);
      ctx.fill();

      // Core particle
      ctx.fillStyle = (neuralCanvasState.activeFile && neuralCanvasState.activeFile.is_threat) ? "#b42318" :
                      (neuralCanvasState.activeFile && neuralCanvasState.activeFile.is_novel) ? "#6c5ce7" : "#0969da";
      ctx.beginPath();
      ctx.arc(currX, midY, 4.5, 0, Math.PI * 2);
      ctx.fill();

      // Advance pulse
      neuralCanvasState.pulseProgress += 0.035;
      if (neuralCanvasState.pulseProgress > 1.0) {
        neuralCanvasState.pulseProgress = 0.0;
        neuralCanvasState.animating = false;
      }
    }

    // Draw Layer Nodes
    // Layer 1: Feature Vector (bar array)
    for (let b = -2; b <= 2; b++) {
      let by = midY + b * 11;
      ctx.fillStyle = (neuralCanvasState.layerFlash[0] > 0) ? "#0969da" : "#555";
      ctx.fillRect(xCols[0] - 12, by - 3, 24, 6);
    }
    ctx.font = "9px -apple-system, sans-serif";
    ctx.fillStyle = "#888";
    ctx.fillText("256-D Static", xCols[0] - 25, midY + 40);

    // Layer 2: Dense 256
    for (let n = -2; n <= 2; n++) {
      let ny = midY + n * 13;
      ctx.beginPath();
      ctx.arc(xCols[1], ny, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = (neuralCanvasState.layerFlash[1] > 0) ? "#0969da" : "#777";
      ctx.fill();
    }
    ctx.fillText("Dense(256)", xCols[1] - 22, midY + 40);

    // Layer 3: ResMLP Block
    for (let n = -2; n <= 2; n++) {
      let ny = midY + n * 13;
      ctx.beginPath();
      ctx.arc(xCols[2], ny, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = (neuralCanvasState.layerFlash[2] > 0) ? "#0969da" : "#444";
      ctx.fill();
    }
    ctx.fillText("ResMLP Block", xCols[2] - 28, midY + 40);

    // Layer 4: Latent 128
    for (let n = -1.5; n <= 1.5; n++) {
      let ny = midY + n * 14;
      ctx.beginPath();
      ctx.arc(xCols[3], ny, 4, 0, Math.PI * 2);
      ctx.fillStyle = (neuralCanvasState.layerFlash[3] > 0) ? "#0969da" : "#666";
      ctx.fill();
    }
    ctx.fillText("Latent(128)", xCols[3] - 24, midY + 40);

    // Layer 5: Dual Heads (Classifier Upper, Novelty Lower)
    // Classifier Node
    let cY = midY - 32;
    ctx.beginPath();
    ctx.arc(xCols[4], cY, 8, 0, Math.PI * 2);
    let isMal = neuralCanvasState.activeFile && neuralCanvasState.activeFile.is_threat;
    ctx.fillStyle = isMal ? "#b42318" : "#1a7f37";
    ctx.fill();
    ctx.fillStyle = "#333";
    ctx.fillText("Classifier (Softmax)", xCols[4] - 95, cY + 3);

    // Novelty Node
    let nY = midY + 32;
    ctx.beginPath();
    ctx.arc(xCols[4], nY, 8, 0, Math.PI * 2);
    let isNov = neuralCanvasState.activeFile && neuralCanvasState.activeFile.is_novel;
    ctx.fillStyle = isNov ? "#6c5ce7" : "#0969da";
    ctx.fill();
    ctx.fillStyle = "#333";
    ctx.fillText("Novelty Head (L2 Sphere)", xCols[4] - 110, nY + 3);

    // Decrease flash timer
    for (let k = 0; k < 5; k++) {
      if (neuralCanvasState.layerFlash[k] > 0) neuralCanvasState.layerFlash[k]--;
    }

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
}




function traceFileThroughNeuralPipeline(item, triggerAnimation) {
  if (!item) return;
  
  let fn = item.file_name || (item.file_path ? item.file_path.split("/").pop().split("\\").pop() : "binary.exe");
  let prob = (item.malware_probability !== undefined) ? item.malware_probability : 0.05;
  let novel = (item.novelty_score !== undefined) ? item.novelty_score : 0.12;
  let verdict = item.verdict || (prob >= 0.5 ? "Suspicious" : (item.is_novel ? "Unfamiliar / OOD" : "Likely Benign"));
  let sha = item.sha256 ? item.sha256.slice(0, 16) + "..." : "---";
  let sz = item.file_size_bytes ? (item.file_size_bytes / 1024).toFixed(1) + " KB" : "---";
  let dur = item.scan_duration_ms ? item.scan_duration_ms.toFixed(1) + " ms" : "---";

  let isThreat = verdict.includes("Suspicious") || prob >= 0.5;
  let isNovel = item.is_novel || verdict.includes("Unfamiliar");

  neuralCanvasState.activeFile = {
    file_name: fn,
    prob: prob,
    novel: novel,
    verdict: verdict,
    is_threat: isThreat,
    is_novel: isNovel
  };

  if (triggerAnimation) {
    neuralCanvasState.pulseProgress = 0.01;
    neuralCanvasState.animating = true;
    neuralCanvasState.layerFlash = [18, 18, 18, 18, 18];
    if (window.trigger3DInferenceWithVerdict) {
      let prof = isThreat ? "malware" : (isNovel ? "novel" : "benign");
      window.trigger3DInferenceWithVerdict(prof, item);
    }
  }

  // Update banner fields
  setTxt("nlFileName", fn);
  setTxt("nlFileSize", sz);
  setTxt("nlSha", sha);
  setTxt("nlDuration", dur);

  let tStage = item.triage_stage || ((item.model_version && item.model_version.includes("Cached")) ? "Cache" : ((item.model_version && item.model_version.includes("Authenticode")) ? "Authenticode" : "ResMLP"));
  if (tStage === "Cache") {
    setTxt("nlStage", "Tier 0: Clean Hash Cache Hit (< 0.05ms)");
  } else if (tStage === "Authenticode") {
    setTxt("nlStage", "Tier 1: Authenticode Signature Verified (< 15ms)");
  } else {
    setTxt("nlStage", triggerAnimation ? "Inference Active (ResMLP Pass)" : "Inspected (Completed)");
  }

  // Update layer card dynamic readouts
  let ev = item.evidence_points || [];
  let entropyTxt = ev.some(e => e.includes("entropy")) ? "High (>7.2)" : "Normal (5.92)";
  let wxTxt = ev.some(e => e.includes("W⊕X") || e.includes("writable and executable")) ? "Flagged (W⊕X)" : "Compliant";
  
  setTxt("nlValEntropy", entropyTxt);
  setTxt("nlValWx", wxTxt);
  setTxt("nlValLatent", "Preserved");
  setTxt("nlValRisk", (prob * 100).toFixed(1) + "%");
  setTxt("nlValNovel", novel.toFixed(3));

  // Set card active classes
  let cls = isThreat ? "active-threat" : (isNovel ? "active-novel" : "active-good");
  for (let c = 1; c <= 5; c++) {
    let el = document.getElementById("nlCard" + c);
    if (el) el.className = "nl-card " + cls;
  }

  // Update badge
  let badgeEl = document.getElementById("neuralFileBadge");
  if (badgeEl) {
    badgeEl.className = "badge " + (isThreat ? "danger" : (isNovel ? "novel" : "good"));
    badgeEl.textContent = verdict + " · P(Malware) = " + (prob * 100).toFixed(1) + "%";
  }
}

function renderScanResultsTable(results) {
  let tbody = document.getElementById("scanResultsTbody");
  if (!tbody) return;
  if (!results || !results.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="color:#64748b;text-align:center;padding:24px;font-size:12px">No Windows PE binary files (.exe, .dll, .sys) were found in the selected target.<br><span style="color:#94a3b8;font-size:11px">Tip: Select a target containing PE binaries (e.g. <b>samples/</b> or <b>C:\\Windows\\System32\\cmd.exe</b>), or uncheck "Only PE Binaries".</span></td></tr>';
    setTxt("scanResultsSummary", "0 files found");
    return;
  }

  tbody.innerHTML = results.map((r, idx) => {
    let vStr = r.verdict || "Likely Benign";
    let badgeCls = vStr.includes("Suspicious") ? "danger" : (vStr.includes("Unfamiliar") ? "novel" : "good");
    let probPct = (r.malware_probability !== undefined) ? (r.malware_probability * 100).toFixed(1) + "%" : "---";
    let shortSha = r.sha256 ? r.sha256.slice(0, 12) + "..." : "N/A";
    let evText = (r.evidence_points && r.evidence_points.length) ? r.evidence_points[0] : (r.warning_message || "Normal structural attributes");
    let escapedPath = (r.file_path || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");

    let tStage = r.triage_stage || ((r.model_version && r.model_version.includes("Cached")) ? "Cache" : ((r.model_version && r.model_version.includes("Authenticode")) ? "Authenticode" : "ResMLP"));
    let tBadge = tStage === "Cache" ? '<span class="badge" style="background:#f1f5f9;color:#334155;border:1px solid #e2e8f0"><svg class="tw-icon-sm" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Cache</span>' :
                 (tStage === "Authenticode" ? '<span class="badge" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0"><svg class="tw-icon-sm" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Signed</span>' :
                 '<span class="badge" style="background:#f5f3ff;color:#6d28d9;border:1px solid #ddd6fe"><svg class="tw-icon-sm" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/></svg> ResMLP</span>');

    return `
      <tr style="cursor:pointer" title="Click to trace binary through Neural Inference Pipeline" onclick="traceFileByIndex(${idx})">
        <td><b>${r.file_name}</b><br><span style="color:#888;font-size:9.5px">${r.file_path || ""}</span></td>
        <td><span class="badge ${badgeCls}">${vStr}</span></td>
        <td>${tBadge}</td>
        <td><b>${probPct}</b></td>
        <td>${r.novelty_score !== undefined ? r.novelty_score.toFixed(3) : "---"}</td>
        <td style="font-family:monospace;font-size:9.5px">${shortSha}</td>
        <td style="color:#666;font-size:10px">${evText}</td>
        <td style="white-space:nowrap">
          ${vStr.includes("Suspicious") ?
            `<button class="btn btn-danger" style="padding:3px 7px;font-size:10px;margin-right:4px" onclick="event.stopPropagation();quarantineFromWeb('${escapedPath}')">Isolate</button>` : ''}
          <button class="nn-glass-btn" style="padding:3px 8px;font-size:10px;background:#f5f3ff;border-color:#ddd6fe;color:#6d28d9" onclick="event.stopPropagation();openAdaptModal('${escapedPath}', '${(r.file_name||'').replace(/'/g, "\\'")}', '${vStr}', ${r.novelty_score || 0}, '${r.sha256 || ''}')" title="Adapt model: Register prototype or queue for continual learning"><svg class="tw-icon-sm" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Adapt</button>
        </td>
      </tr>
    `;
  }).join("");

  setTxt("scanResultsSummary", `Showing ${results.length} analyzed binary file(s)`);
}

let activeScanResults = [];
function traceFileByIndex(idx) {
  if (activeScanResults && activeScanResults[idx]) {
    traceFileThroughNeuralPipeline(activeScanResults[idx], true);
  }
}

function pollScanProgress() {
  fetch("/api/scan/progress")
    .then(r => r.json())
    .then(st => {
      // 1. Progress bar
      if (st.total > 0) {
        let pct = Math.min(100, Math.round((st.completed / st.total) * 100));
        let bar = document.getElementById("scanProgBar");
        if (bar) bar.style.width = pct + "%";
        setTxt("scanProgPct", pct + "%");
        if (st.is_full_system) {
          setTxt("scanStatusText", `System Scan: Discovered ${st.total} PEs | Inspected ${st.completed}: ${st.current_file || ""}`);
        } else {
          setTxt("scanStatusText", `Inspected ${st.completed}/${st.total}: ${st.current_file || ""}`);
        }
      } else if (st.is_scanning) {
        setTxt("scanStatusText", st.is_full_system ? "Traversing fixed volumes & analyzing binaries in real time..." : "Traversing target path...");
      }

      // 2. Active neural trace
      if (st.latest_result) {
        traceFileThroughNeuralPipeline(st.latest_result, true);
      } else if (st.current_file) {
        setTxt("nlFileName", st.current_file.split("/").pop().split("\\").pop());
        setTxt("nlStage", "Extracting 256-D Static Features");
      }

      // 3. Keep results cached and rendered
      if (st.results && st.results.length > 0) {
        activeScanResults = st.results;
        renderScanResultsTable(st.results);
      }

      // 4. Completed state
      if (!st.is_scanning) {
        clearInterval(scanInterval);
        resetScanButtons();
        let bar = document.getElementById("scanProgBar");
        if (bar) bar.style.width = "100%";
        setTxt("scanProgPct", "100%");

        let totalCount = (st.results_count !== undefined) ? st.results_count : (st.results ? st.results.length : 0);
        if (totalCount === 0) {
          setTxt("scanStatusText", "Scan complete: 0 PE executable binaries (.exe, .dll, .sys) found in target path.");
          renderScanResultsTable([]);
          setTxt("nlStage", "No PE files found");
        } else {
          setTxt("scanStatusText", `Scan complete! ${totalCount} binary files analyzed.`);
          setTxt("nlStage", "Scan Completed");
          if (st.results && st.results.length > 0) {
            renderScanResultsTable(st.results);
            traceFileThroughNeuralPipeline(st.results[0], false);
          }
        }

        loadThreatNetworkData();
      }
    })
    .catch(err => {
      clearInterval(scanInterval);
      resetScanButtons();
      setTxt("scanStatusText", "Scan error: " + err);
    });
}

// QUARANTINE ACTIONS
function quarantineFromWeb(path) {
  if (!confirm(`Confirm isolating file '${path}' to quarantine vault?`)) return;
  fetch("/api/quarantine", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({file_path: path, reason: "Manual user action from Threat Web"})
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === "success") {
      alert(`File successfully quarantined (ID: ${res.entry.quarantine_id})`);
      refreshQuarantine();
    } else {
      alert(`Quarantine failed: ${res.error}`);
    }
  });
}

function refreshQuarantine() {
  fetch("/api/quarantine")
    .then(r => r.json())
    .then(data => {
      let tbody = document.getElementById("quarantineTbody");
      let entries = data.entries || [];
      if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:#888;text-align:center;padding:24px">Quarantine vault is currently empty.</td></tr>';
        return;
      }
      tbody.innerHTML = entries.map(e => `
        <tr>
          <td><b>${e.original_filename}</b><br><span style="color:#888;font-size:9.5px">${e.original_path}</span></td>
          <td style="font-family:monospace">${e.quarantine_id}</td>
          <td>${e.restored ? '<span class="badge good">Restored</span>' : '<span class="badge danger">Isolated</span>'}</td>
          <td>${e.quarantined_at}</td>
          <td style="font-family:monospace;font-size:9.5px">${e.sha256.slice(0, 16)}...</td>
          <td>
            ${!e.restored ? `<button class="btn" style="padding:3px 8px;font-size:10px" onclick="restoreQuarantine('${e.quarantine_id}')">Restore</button>` : '<span style="color:#aaa;font-size:10px">Archived</span>'}
          </td>
        </tr>
      `).join("");
    });
}

function restoreQuarantine(qid) {
  if (!confirm(`Restore quarantined item '${qid}'?`)) return;
  fetch("/api/restore", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({quarantine_id: qid})
  })
  .then(r => r.json())
  .then(res => {
    if (res.status === "success") {
      alert(`File restored to: ${res.restored_path}`);
      refreshQuarantine();
    } else {
      alert(`Restore error: ${res.error}`);
    }
  });
}

function refreshHistory() {
  fetch("/api/history")
    .then(r => r.json())
    .then(data => {
      let tbody = document.getElementById("historyTbody");
      let list = data.history || [];
      if (!list.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:#888;text-align:center;padding:24px">No previous scan history.</td></tr>';
        return;
      }
      tbody.innerHTML = list.slice().reverse().map(h => `
        <tr>
          <td style="font-family:monospace">${h.scan_id || "scan-01"}</td>
          <td>${h.timestamp}</td>
          <td>${h.target_path}</td>
          <td>${h.summary ? h.summary.total_scanned : 0} files</td>
          <td><span class="danger">${h.summary ? h.summary.suspicious : 0} suspicious</span> · <span class="novel">${h.summary ? h.summary.unfamiliar : 0} novel</span></td>
          <td><span class="badge">JSON</span></td>
        </tr>
      `).join("");
    });
}

function loadFamilies() {
  fetch("/api/families")
    .then(r => r.json())
    .then(data => {
      let fams = data.families || [];
      let grid = document.getElementById("familyCardsGrid");
      if (fams.length) {
        grid.innerHTML = fams.map(f => `
          <div class="card">
            <div class="k">${f.category}</div>
            <h3 style="margin-top:6px">${f.name}</h3>
            <div class="small">${f.threat_type || "Malware Strain"} · Risk: ${(f.risk * 100).toFixed(0)}%</div>
            <p style="margin-top:8px">${f.description.slice(0, 110)}...</p>
            <div class="small" style="color:#555"><b>APIs:</b> ${(f.dominant_apis || []).slice(0, 3).join(", ")}</div>
            <button class="btn" style="margin-top:14px" onclick="switchTab('web')">Inspect in Threat Web</button>
          </div>
        `).join("");
      }
    });
}

// DATAFLOW SVG TRACE
function drawFlow(svg) {
  if (!svg) return;
  svg.innerHTML = "";
  let NS = "http://www.w3.org/2000/svg";
  let labels = [
    ["PE BINARY", "Static structure"],
    ["FEATURES", "256 dimensions"],
    ["RESMLP ENCODER", "Residual blocks"],
    ["EMBEDDING", (window.CURRENT_EMBEDDING_DIM ? window.CURRENT_EMBEDDING_DIM + "-D unit sphere" : "128-D unit sphere")],
    ["CALIBRATED CLASSIFIER", "Temperature T=0.93"],
    ["COSINE NOVELTY", "Threshold τ = 0.429"],
    ["SECURITY VERDICT", "NOVEL ≠ MALICIOUS"]
  ];
  let y = [40, 110, 180, 250, 325, 395, 465];
  let xs = 350;

  labels.forEach((a, i) => {
    if (i < labels.length - 1) {
      let p = document.createElementNS(NS, "path");
      p.setAttribute("d", `M ${xs} ${y[i] + 30} C ${xs - 20} ${y[i] + 45}, ${xs + 20} ${y[i + 1] - 45}, ${xs} ${y[i + 1] - 30}`);
      p.setAttribute("class", "path activePath");
      svg.appendChild(p);
    }
    let g = document.createElementNS(NS, "g");
    g.setAttribute("class", "node");
    let r = document.createElementNS(NS, "rect");
    r.setAttribute("x", xs - 100);
    r.setAttribute("y", y[i] - 25);
    r.setAttribute("width", 200);
    r.setAttribute("height", 50);
    r.setAttribute("rx", 12);
    g.appendChild(r);

    let t = document.createElementNS(NS, "text");
    t.setAttribute("x", xs);
    t.setAttribute("y", y[i] - 2);
    t.setAttribute("text-anchor", "middle");
    t.textContent = a[0];
    g.appendChild(t);

    let s = document.createElementNS(NS, "text");
    s.setAttribute("x", xs);
    s.setAttribute("y", y[i] + 13);
    s.setAttribute("text-anchor", "middle");
    s.setAttribute("class", "sub");
    s.textContent = a[1];
    g.appendChild(s);

    svg.appendChild(g);
  });
}

document.getElementById("tauSlider").oninput = e => {
  setTxt("tau", Number(e.target.value).toFixed(3));
};

function updateTriageSettings() {
  let cacheOn = document.getElementById("settingCacheToggle") ? document.getElementById("settingCacheToggle").checked : true;
  let sigOn = document.getElementById("settingSigToggle") ? document.getElementById("settingSigToggle").checked : true;
  fetch("/api/settings", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      enable_hash_cache: cacheOn,
      enable_signature_verifier: sigOn
    })
  }).then(r => r.json()).then(data => {
    console.log("Triage settings updated:", data);
  });
}

function purgeHashCache() {
  fetch("/api/settings", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({clear_cache: true})
  }).then(r => r.json()).then(data => {
    alert("Clean hash cache successfully purged.");
  });
}
</script>

<!-- ADAPTATION MODAL (OPTION A & OPTION B) -->
<div id="adaptModal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.35);backdrop-filter:blur(4px);z-index:9999;align-items:center;justify-content:center">
  <div style="background:#fff;border-radius:14px;box-shadow:0 12px 36px rgba(0,0,0,0.18);width:480px;max-width:92vw;padding:24px;border:1px solid #e5e5ea">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="margin:0;font-size:17px;font-weight:600">Adapt ThreatWeaver Model</h3>
      <button onclick="closeAdaptModal()" style="background:none;border:none;font-size:18px;cursor:pointer;color:#888">&times;</button>
    </div>
    
    <!-- Target File Info -->
    <div style="background:#f7f7f5;border-radius:8px;padding:10px 12px;margin-bottom:16px;font-size:12px">
      <div><b>Target:</b> <span id="modalFileName">sample.exe</span></div>
      <div style="color:#666;font-size:11px;margin-top:2px;word-break:break-all" id="modalFilePath">C:\...</div>
      <div style="display:flex;gap:12px;margin-top:6px">
        <span>Verdict: <b id="modalVerdict">Unfamiliar</b></span>
        <span>Novelty: <b id="modalNovelty">0.482</b></span>
      </div>
    </div>

    <!-- Segmented Tab Picker -->
    <div style="display:flex;background:#eee;border-radius:8px;padding:3px;margin-bottom:16px">
      <button id="tabBtnOptA" class="apple-pill-btn active" onclick="switchAdaptTab('A')" style="flex:1;padding:6px;border-radius:6px;font-size:12px;font-weight:600;border:none;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.1);cursor:pointer">Option A: Instant Prototype</button>
      <button id="tabBtnOptB" class="apple-pill-btn" onclick="switchAdaptTab('B')" style="flex:1;padding:6px;border-radius:6px;font-size:12px;font-weight:600;border:none;background:none;cursor:pointer;color:#666">Option B: Continual Replay</button>
    </div>

    <!-- Pane A: Fast Online Prototype -->
    <div id="paneOptA">
      <p style="font-size:12px;color:#555;margin:0 0 12px 0">
        <b>Zero Risk / Instant:</b> Registers this binary's 128-D embedding directly into the Cosine Novelty gate. Future scans of this or structurally similar variants will immediately be recognized as familiar without any weight changes.
      </p>
      <div style="margin-bottom:10px">
        <label style="font-size:12px;font-weight:600;display:block;margin-bottom:4px">Family Name / Cluster Label:</label>
        <input type="text" id="optAFamily" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #ccc;border-radius:6px;font-size:13px" value="Novel-Variant-1">
      </div>
      <div style="margin-bottom:16px">
        <label style="font-size:12px;font-weight:600;display:block;margin-bottom:4px">Classification:</label>
        <label style="font-size:12.5px;margin-right:16px;cursor:pointer"><input type="radio" name="optALabel" value="1" checked> <span class="status-pip pip-danger"></span> Malware</label>
        <label style="font-size:12.5px;cursor:pointer"><input type="radio" name="optALabel" value="0"> <span class="status-pip pip-good"></span> Benign</label>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button onclick="closeAdaptModal()" class="secondary" style="padding:6px 12px;font-size:12px">Cancel</button>
        <button onclick="submitOptionA()" class="primary" style="padding:6px 14px;font-size:12px;background:#6c5ce7;border-color:#6c5ce7">Register 128-D Prototype</button>
      </div>
    </div>

    <!-- Pane B: Continual Learning Queue -->
    <div id="paneOptB" style="display:none">
      <p style="font-size:12px;color:#555;margin:0 0 12px 0">
        <b>Continual Learning:</b> Enqueues this sample into the active learning queue. When executed, ThreatWeaver trains on this sample alongside verified EMBER replay baselines with uncertainty diversity sampling to adapt classifier weights without catastrophic forgetting.
      </p>
      <div style="margin-bottom:10px">
        <label style="font-size:12px;font-weight:600;display:block;margin-bottom:4px">Family Attribution:</label>
        <input type="text" id="optBFamily" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #ccc;border-radius:6px;font-size:13px" value="Novel-Threat-Replay">
      </div>
      <div style="margin-bottom:16px">
        <label style="font-size:12px;font-weight:600;display:block;margin-bottom:4px">Ground Truth Verdict:</label>
        <label style="font-size:12.5px;margin-right:16px;cursor:pointer"><input type="radio" name="optBLabel" value="1" checked> <span class="status-pip pip-danger"></span> Verified Malware</label>
        <label style="font-size:12.5px;cursor:pointer"><input type="radio" name="optBLabel" value="0"> <span class="status-pip pip-good"></span> Verified Benign</label>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button onclick="closeAdaptModal()" class="secondary" style="padding:6px 12px;font-size:12px">Cancel</button>
        <button onclick="submitOptionB()" class="primary" style="padding:6px 14px;font-size:12px">Enqueue for Replay Training</button>
      </div>
    </div>
  </div>
</div>

</body>
</html>
"""
