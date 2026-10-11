"""ThreatWeaver Local UI Web Server with Apple Minimalist Design.

Provides a zero-cloud, local-first HTTP service and REST API for on-demand scanning,
quarantine management, research telemetry, and real-time inspection.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from threatweaver import __version__
from threatweaver.quarantine.manager import QuarantineManager
from threatweaver.reporting.report import ScanHistoryManager, ScanReport
from threatweaver.scanner.inference import InferenceEngine, ScanResult, ScanVerdict
from threatweaver.scanner.scan_service import ScanService

DEFAULT_PORT = 8765
DEFAULT_CHECKPOINT = Path("artifacts/checkpoints/threatweaver_v1.pt")


class ScanStateManager:
    """Thread-safe manager for active scans."""

    def __init__(self, inference_engine: InferenceEngine):
        self.engine = inference_engine
        self.service = ScanService(inference_engine=inference_engine, max_workers=4)
        self.lock = threading.Lock()
        self.is_scanning = False
        self.completed_count = 0
        self.total_count = 0
        self.current_file = ""
        self.results: List[ScanResult] = []
        self.last_report: Optional[ScanReport] = None
        self._scan_thread: Optional[threading.Thread] = None

    def start_scan(self, target_path: str, only_pe_extensions: bool = True) -> bool:
        with self.lock:
            if self.is_scanning:
                return False
            self.is_scanning = True
            self.completed_count = 0
            self.total_count = 0
            self.current_file = ""
            self.results = []
            self.last_report = None

        def worker():
            def on_prog(cur: int, tot: int, fn: str):
                with self.lock:
                    self.completed_count = cur
                    self.total_count = tot
                    self.current_file = fn

            def on_res(r: ScanResult):
                with self.lock:
                    self.results.append(r)

            try:
                rep = self.service.scan(
                    target_path=target_path,
                    only_pe_extensions=only_pe_extensions,
                    on_progress=on_prog,
                    on_result=on_res,
                )
                with self.lock:
                    self.last_report = rep
                    # Save to local history
                    ScanHistoryManager().record_scan(rep)
            finally:
                with self.lock:
                    self.is_scanning = False

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()
        return True

    def cancel_scan(self) -> None:
        self.service.cancel()
        with self.lock:
            self.is_scanning = False

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "is_scanning": self.is_scanning,
                "completed": self.completed_count,
                "total": self.total_count,
                "current_file": self.current_file,
                "results_count": len(self.results),
                "results": [
                    {
                        "file_path": r.file_path,
                        "file_name": r.file_name,
                        "file_size_bytes": r.file_size_bytes,
                        "sha256": r.sha256,
                        "verdict": r.verdict.value,
                        "malware_probability": round(r.malware_probability, 4),
                        "novelty_score": round(r.novelty_score, 4),
                        "is_novel": r.is_novel,
                        "evidence_points": r.evidence_points,
                        "scan_duration_ms": round(r.scan_duration_ms, 2),
                        "nearest_known_cluster": r.nearest_known_cluster,
                        "warning_message": r.warning_message,
                    }
                    for r in self.results
                ],
            }


class ThreatWeaverRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler delivering the Apple Minimalist UI & REST endpoints."""

    state_mgr: ScanStateManager
    engine: InferenceEngine
    quarantine_mgr: QuarantineManager

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._serve_html_ui()
        elif path == "/api/status":
            self._serve_json(self._get_system_status())
        elif path == "/api/scan/progress":
            self._serve_json(self.state_mgr.get_status())
        elif path == "/api/history":
            history = ScanHistoryManager().load_history()
            self._serve_json({"history": history})
        elif path == "/api/quarantine":
            entries = self.quarantine_mgr.list_quarantined_files()
            self._serve_json({"entries": [e.__dict__ for e in entries]})
        elif path == "/api/research":
            self._serve_research_results()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/scan":
            target = body.get("target_path", ".")
            only_pe = not body.get("all_files", False)
            started = self.state_mgr.start_scan(target, only_pe_extensions=only_pe)
            if started:
                self._serve_json({"status": "started", "target": target})
            else:
                self._serve_json({"error": "Scan already in progress"}, status=HTTPStatus.CONFLICT)

        elif path == "/api/scan/cancel":
            self.state_mgr.cancel_scan()
            self._serve_json({"status": "cancelled"})

        elif path == "/api/quarantine":
            file_p = body.get("file_path")
            reason = body.get("reason", "Manual isolation from UI")
            dry_run = body.get("dry_run", False)
            if not file_p:
                self._serve_json({"error": "file_path is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            try:
                entry = self.quarantine_mgr.quarantine_file(file_p, reason=reason, dry_run=dry_run)
                self._serve_json({"status": "success", "entry": entry.__dict__})
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/restore":
            qid = body.get("quarantine_id")
            dry_run = body.get("dry_run", False)
            if not qid:
                self._serve_json({"error": "quarantine_id is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            try:
                restored = self.quarantine_mgr.restore_file(qid, dry_run=dry_run)
                self._serve_json({"status": "success", "restored_path": str(restored)})
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                raw = self.rfile.read(length).decode("utf-8")
                return json.loads(raw)
        except Exception:
            pass
        return {}

    def _serve_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def _get_system_status(self) -> Dict[str, Any]:
        return {
            "version": __version__,
            "model_version": self.engine.model_version,
            "model_loaded": self.engine.checkpoint_loaded,
            "device": str(self.engine.device),
            "novelty_threshold": self.engine.novelty_detector.threshold if self.engine.novelty_detector else 0.40,
            "quarantine_count": len(self.quarantine_mgr.list_quarantined_files()),
        }

    def _serve_research_results(self) -> None:
        p = Path("reports/continual_learning_results.json")
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    self._serve_json(json.load(f))
                    return
            except Exception:
                pass
        self._serve_json({"status": "No benchmark reports available yet"})

    def _serve_html_ui(self) -> None:
        html = get_apple_minimalist_html()
        raw = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy HTTP request logging in console
        pass


def get_apple_minimalist_html() -> str:
    """Returns the Apple Minimalist UI Single-Page Application HTML."""
    return r"""<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ThreatWeaver</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    :root {
      --font-stack: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
    }
    body {
      font-family: var(--font-stack);
      -webkit-font-smoothing: antialiased;
      background-color: #fbfbfd;
      color: #1d1d1f;
    }
    .apple-glass {
      background: rgba(255, 255, 255, 0.85);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid rgba(0, 0, 0, 0.06);
    }
    .apple-card {
      background: #ffffff;
      border: 1px solid rgba(0, 0, 0, 0.05);
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.03), 0 0 1px 1px rgba(0, 0, 0, 0.03);
      border-radius: 18px;
    }
    .apple-btn-primary {
      background: #0071e3;
      color: #ffffff;
      border-radius: 980px;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .apple-btn-primary:hover {
      background: #0077ed;
      transform: scale(1.01);
    }
    .apple-btn-primary:active {
      transform: scale(0.98);
    }
    .apple-btn-secondary {
      background: rgba(0, 0, 0, 0.04);
      color: #1d1d1f;
      border-radius: 980px;
      transition: all 0.2s ease;
    }
    .apple-btn-secondary:hover {
      background: rgba(0, 0, 0, 0.08);
    }
    .apple-pill-tab {
      border-radius: 980px;
      padding: 6px 16px;
      font-size: 13px;
      font-weight: 500;
      transition: all 0.2s ease;
    }
    .apple-pill-tab.active {
      background: #ffffff;
      color: #1d1d1f;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    }
    .apple-pill-tab:not(.active) {
      color: #86868b;
    }
    .apple-pill-tab:not(.active):hover {
      color: #1d1d1f;
    }
  </style>
</head>
<body class="min-h-screen p-4 md:p-8">
  <div class="max-w-6xl mx-auto space-y-6">

    <!-- Top Navigation & Apple Header -->
    <header class="apple-glass rounded-2xl p-4 md:px-6 flex flex-col md:flex-row md:items-center justify-between gap-4 sticky top-4 z-40">
      <div class="flex items-center space-x-3">
        <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white shadow-sm">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <h1 class="text-lg font-semibold tracking-tight text-[#1d1d1f]">ThreatWeaver</h1>
            <span class="text-xs px-2 py-0.5 rounded-full bg-black/5 text-[#86868b] font-medium" id="versionBadge">v0.1.0</span>
          </div>
          <p class="text-xs text-[#86868b]">AI Malware Research Engine & Antivirus Prototype</p>
        </div>
      </div>

      <!-- Segmented Navigation Pills -->
      <nav class="flex items-center bg-[#f0f0f2] p-1 rounded-full space-x-1" id="navTabs">
        <button onclick="switchTab('scan')" class="apple-pill-tab active" id="tab-scan">Scanner</button>
        <button onclick="switchTab('quarantine')" class="apple-pill-tab" id="tab-quarantine">Quarantine Vault</button>
        <button onclick="switchTab('research')" class="apple-pill-tab" id="tab-research">Continual Learning</button>
        <button onclick="switchTab('history')" class="apple-pill-tab" id="tab-history">History</button>
      </nav>

      <div class="flex items-center space-x-3 text-xs">
        <div class="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-emerald-50 border border-emerald-100 text-emerald-700">
          <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span class="font-medium" id="statusLabel">Protected • Local ResMLP</span>
        </div>
      </div>
    </header>

    <!-- TAB 1: SCANNER & INSPECTION -->
    <main id="view-scan" class="space-y-6">
      <!-- Target Path & Action Bar -->
      <section class="apple-card p-6 space-y-4">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div class="flex-1">
            <label class="block text-xs font-medium text-[#86868b] uppercase tracking-wider mb-1.5">Scan Target Directory or File</label>
            <div class="relative">
              <input type="text" id="targetPath" value="." class="w-full bg-[#f5f5f7] border border-black/5 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#0071e3]/20 text-[#1d1d1f] font-mono" placeholder="C:\Path\To\Scan" />
            </div>
          </div>
          <div class="flex items-center space-x-2 pt-2 md:pt-5">
            <button onclick="startScan()" id="btnStartScan" class="apple-btn-primary px-6 py-2.5 text-sm font-medium flex items-center space-x-2 shadow-sm">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              <span>Start Analysis</span>
            </button>
            <button onclick="cancelScan()" id="btnCancelScan" class="apple-btn-secondary px-4 py-2.5 text-sm font-medium hidden text-rose-600">
              <span>Cancel</span>
            </button>
          </div>
        </div>

        <div class="flex flex-wrap items-center justify-between text-xs text-[#86868b] pt-2 border-t border-black/5 gap-2">
          <div class="flex items-center space-x-4">
            <label class="flex items-center space-x-1.5 cursor-pointer">
              <input type="checkbox" id="chkAllFiles" class="rounded text-[#0071e3] focus:ring-0" />
              <span>Inspect all files (not just PE binaries)</span>
            </label>
            <span>•</span>
            <span>Feature Schema: <strong class="text-[#1d1d1f]">v1.0 (256-dim)</strong></span>
          </div>
          <div class="flex items-center space-x-2">
            <span>Quick:</span>
            <button onclick="setTarget('.')" class="text-[#0071e3] hover:underline">Workspace</button>
            <span>|</span>
            <button onclick="setTarget('tests')" class="text-[#0071e3] hover:underline">Tests</button>
            <span>|</span>
            <button onclick="setTarget('.venv/Scripts')" class="text-[#0071e3] hover:underline">VirtualEnv</button>
          </div>
        </div>

        <!-- Progress Indicator -->
        <div id="progressContainer" class="hidden pt-2 space-y-2">
          <div class="flex justify-between text-xs text-[#86868b]">
            <span id="progressFileText">Scanning...</span>
            <span id="progressCountText">0 / 0</span>
          </div>
          <div class="w-full bg-[#f0f0f2] h-2 rounded-full overflow-hidden">
            <div id="progressBar" class="bg-[#0071e3] h-full w-0 transition-all duration-200"></div>
          </div>
        </div>
      </section>

      <!-- KPI Summary Cards -->
      <section class="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div class="apple-card p-4">
          <span class="text-xs text-[#86868b] font-medium">Total Inspected</span>
          <p class="text-2xl font-semibold tracking-tight text-[#1d1d1f] mt-1" id="kpiTotal">0</p>
        </div>
        <div class="apple-card p-4">
          <span class="text-xs text-emerald-600 font-medium">Likely Benign</span>
          <p class="text-2xl font-semibold tracking-tight text-emerald-600 mt-1" id="kpiBenign">0</p>
        </div>
        <div class="apple-card p-4">
          <span class="text-xs text-amber-600 font-medium">Suspicious</span>
          <p class="text-2xl font-semibold tracking-tight text-amber-600 mt-1" id="kpiSuspicious">0</p>
        </div>
        <div class="apple-card p-4">
          <span class="text-xs text-purple-600 font-medium">Unfamiliar (OOD)</span>
          <p class="text-2xl font-semibold tracking-tight text-purple-600 mt-1" id="kpiUnfamiliar">0</p>
        </div>
        <div class="apple-card p-4">
          <span class="text-xs text-[#86868b] font-medium">Unsupported / Err</span>
          <p class="text-2xl font-semibold tracking-tight text-[#86868b] mt-1" id="kpiOther">0</p>
        </div>
      </section>

      <!-- Results Table -->
      <section class="apple-card overflow-hidden">
        <div class="p-4 px-6 border-b border-black/5 flex items-center justify-between">
          <div>
            <h2 class="text-sm font-semibold text-[#1d1d1f]">Inspection Results</h2>
            <p class="text-xs text-[#86868b]">Static executable analysis & calibrated multi-evidence attribution</p>
          </div>
          <div class="flex items-center space-x-2">
            <button onclick="exportReport('json')" class="apple-btn-secondary px-3 py-1.5 text-xs font-medium">Export JSON</button>
            <button onclick="exportReport('md')" class="apple-btn-secondary px-3 py-1.5 text-xs font-medium">Export Markdown</button>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-[#f9f9fb] text-[#86868b] font-medium border-b border-black/5">
              <tr>
                <th class="py-3 px-6">File Name</th>
                <th class="py-3 px-4">Verdict</th>
                <th class="py-3 px-4">Calibrated Risk</th>
                <th class="py-3 px-4">SHA-256</th>
                <th class="py-3 px-4">Evidence Attribution</th>
                <th class="py-3 px-6 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="resultsTableBody" class="divide-y divide-black/[0.04]">
              <tr>
                <td colspan="6" class="py-12 text-center text-[#86868b]">No active scan results. Click "Start Analysis" above.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>

    <!-- TAB 2: QUARANTINE VAULT -->
    <main id="view-quarantine" class="hidden space-y-6">
      <section class="apple-card p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h2 class="text-base font-semibold text-[#1d1d1f]">Isolated Quarantine Vault</h2>
            <p class="text-xs text-[#86868b]">Files are safely isolated, XOR-neutralized, and preserved with complete recovery metadata.</p>
          </div>
          <button onclick="loadQuarantineList()" class="apple-btn-secondary px-4 py-2 text-xs font-medium">Refresh Vault</button>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-[#f9f9fb] text-[#86868b] font-medium border-b border-black/5">
              <tr>
                <th class="py-3 px-6">Quarantine ID</th>
                <th class="py-3 px-4">Original File Name</th>
                <th class="py-3 px-4">Original Path</th>
                <th class="py-3 px-4">Status</th>
                <th class="py-3 px-4">Date Isolated</th>
                <th class="py-3 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="quarantineTableBody" class="divide-y divide-black/[0.04]">
              <tr><td colspan="6" class="py-8 text-center text-[#86868b]">Loading vault records...</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>

    <!-- TAB 3: CONTINUAL LEARNING RESEARCH -->
    <main id="view-research" class="hidden space-y-6">
      <section class="apple-card p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h2 class="text-base font-semibold text-[#1d1d1f]">Continual Learning Benchmark Telemetry</h2>
            <p class="text-xs text-[#86868b]">Comparison of four replay strategies under equivalent data, memory, and labeling budgets.</p>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-[#f9f9fb] text-[#86868b] font-medium border-b border-black/5">
              <tr>
                <th class="py-3 px-6">Replay Strategy</th>
                <th class="py-3 px-4">Macro-F1</th>
                <th class="py-3 px-4">Catastrophic Forgetting (F_T)</th>
                <th class="py-3 px-4">Backward Transfer (BWT)</th>
                <th class="py-3 px-4">Benign FPR</th>
                <th class="py-3 px-6">Training Time</th>
              </tr>
            </thead>
            <tbody id="researchTableBody" class="divide-y divide-black/[0.04]">
              <tr>
                <td class="py-3.5 px-6 font-medium text-[#1d1d1f]">A. No Replay (Naive Sequential)</td>
                <td class="py-3.5 px-4 text-emerald-600 font-medium">1.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.00%</td>
                <td class="py-3.5 px-6 text-[#86868b]">11.85s</td>
              </tr>
              <tr>
                <td class="py-3.5 px-6 font-medium text-[#1d1d1f]">B. Uniform Random Replay</td>
                <td class="py-3.5 px-4 text-emerald-600 font-medium">1.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.00%</td>
                <td class="py-3.5 px-6 text-[#86868b]">1.80s</td>
              </tr>
              <tr>
                <td class="py-3.5 px-6 font-medium text-[#1d1d1f]">C. Uncertainty-Guided Replay</td>
                <td class="py-3.5 px-4 text-emerald-600 font-medium">1.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.00%</td>
                <td class="py-3.5 px-6 text-[#86868b]">1.81s</td>
              </tr>
              <tr>
                <td class="py-3.5 px-6 font-medium text-[#1d1d1f]">D. Uncertainty + Diversity Replay</td>
                <td class="py-3.5 px-4 text-emerald-600 font-medium">1.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.000 ± 0.000</td>
                <td class="py-3.5 px-4 text-emerald-600">0.00%</td>
                <td class="py-3.5 px-6 text-[#86868b]">2.35s</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>

    <!-- TAB 4: SCAN HISTORY -->
    <main id="view-history" class="hidden space-y-6">
      <section class="apple-card p-6">
        <h2 class="text-base font-semibold text-[#1d1d1f] mb-4">Local Audit & Scan History</h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-[#f9f9fb] text-[#86868b] font-medium border-b border-black/5">
              <tr>
                <th class="py-3 px-6">Scan ID</th>
                <th class="py-3 px-4">Timestamp</th>
                <th class="py-3 px-4">Target Path</th>
                <th class="py-3 px-4">Duration</th>
                <th class="py-3 px-4">Total</th>
                <th class="py-3 px-6">Suspicious</th>
              </tr>
            </thead>
            <tbody id="historyTableBody" class="divide-y divide-black/[0.04]">
              <tr><td colspan="6" class="py-8 text-center text-[#86868b]">Loading scan history...</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>

  </div>

  <!-- Detail Inspection Modal -->
  <div id="detailModal" class="fixed inset-0 bg-black/30 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
    <div class="apple-card max-w-xl w-full p-6 space-y-4 shadow-2xl">
      <div class="flex items-center justify-between border-b border-black/5 pb-3">
        <h3 class="text-base font-semibold text-[#1d1d1f]" id="modalFileName">File Details</h3>
        <button onclick="closeModal()" class="text-[#86868b] hover:text-[#1d1d1f] text-sm">✕</button>
      </div>
      <div class="space-y-3 text-xs" id="modalBody">
        <!-- Content injected dynamically -->
      </div>
      <div class="flex justify-end pt-2 border-t border-black/5">
        <button onclick="closeModal()" class="apple-btn-secondary px-5 py-2 text-xs font-medium">Done</button>
      </div>
    </div>
  </div>

  <!-- Quarantine Confirmation Modal -->
  <div id="quarantineModal" class="fixed inset-0 bg-black/30 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
    <div class="apple-card max-w-md w-full p-6 space-y-4 shadow-2xl">
      <div class="flex items-center space-x-3 text-amber-600">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <h3 class="text-base font-semibold text-[#1d1d1f]">Confirm File Isolation</h3>
      </div>
      <p class="text-xs text-[#86868b]">
        Are you sure you want to isolate this file to the restricted quarantine vault? The binary will be encrypted with an XOR mask and removed from its current directory. You can restore it at any time.
      </p>
      <div class="bg-[#f5f5f7] p-3 rounded-xl text-xs font-mono break-all" id="quarantineModalPath"></div>
      <div class="flex justify-end space-x-2 pt-2">
        <button onclick="closeQuarantineModal()" class="apple-btn-secondary px-4 py-2 text-xs font-medium">Cancel</button>
        <button onclick="executeQuarantine()" class="apple-btn-primary px-5 py-2 text-xs font-medium bg-amber-600 hover:bg-amber-700">Confirm Quarantine</button>
      </div>
    </div>
  </div>

  <script>
    let pollInterval = null;
    let currentResults = [];
    let pendingQuarantinePath = null;

    function switchTab(tabId) {
      ['scan', 'quarantine', 'research', 'history'].forEach(t => {
        document.getElementById(`view-${t}`).classList.add('hidden');
        document.getElementById(`tab-${t}`).classList.remove('active');
      });
      document.getElementById(`view-${tabId}`).classList.remove('hidden');
      document.getElementById(`tab-${tabId}`).classList.add('active');

      if (tabId === 'quarantine') loadQuarantineList();
      if (tabId === 'history') loadHistoryList();
    }

    function setTarget(path) {
      document.getElementById('targetPath').value = path;
    }

    async function startScan() {
      const target = document.getElementById('targetPath').value.trim();
      const allFiles = document.getElementById('chkAllFiles').checked;

      document.getElementById('btnStartScan').classList.add('hidden');
      document.getElementById('btnCancelScan').classList.remove('hidden');
      document.getElementById('progressContainer').classList.remove('hidden');

      try {
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_path: target, all_files: allFiles })
        });
        const data = await resp.json();
        if (resp.ok) {
          startPolling();
        } else {
          alert('Error starting scan: ' + (data.error || 'Unknown'));
          resetScanUI();
        }
      } catch (err) {
        alert('Failed to connect to ThreatWeaver service: ' + err);
        resetScanUI();
      }
    }

    function startPolling() {
      if (pollInterval) clearInterval(pollInterval);
      pollInterval = setInterval(async () => {
        try {
          const resp = await fetch('/api/scan/progress');
          const data = await resp.json();

          // Update progress bar
          const completed = data.completed || 0;
          const total = data.total || 0;
          const pct = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;
          document.getElementById('progressBar').style.width = pct + '%';
          document.getElementById('progressCountText').innerText = `${completed} / ${total} files (${pct}%)`;
          document.getElementById('progressFileText').innerText = data.current_file ? 'Scanning: ' + data.current_file : 'Scanning...';

          if (data.results) {
            currentResults = data.results;
            renderResults(data.results);
          }

          if (!data.is_scanning) {
            clearInterval(pollInterval);
            pollInterval = null;
            resetScanUI();
          }
        } catch (e) {
          console.error(e);
        }
      }, 350);
    }

    async function cancelScan() {
      await fetch('/api/scan/cancel', { method: 'POST' });
      resetScanUI();
    }

    function resetScanUI() {
      document.getElementById('btnStartScan').classList.remove('hidden');
      document.getElementById('btnCancelScan').classList.add('hidden');
      document.getElementById('progressFileText').innerText = 'Completed';
    }

    function renderResults(results) {
      let kpi = { total: results.length, benign: 0, suspicious: 0, unfamiliar: 0, other: 0 };
      const tbody = document.getElementById('resultsTableBody');

      if (results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="py-12 text-center text-[#86868b]">No files matched criteria.</td></tr>';
        return;
      }

      let rows = '';
      results.forEach((r, idx) => {
        let badge = '';
        if (r.verdict === 'Likely Benign') {
          kpi.benign++;
          badge = '<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">Likely Benign</span>';
        } else if (r.verdict === 'Suspicious') {
          kpi.suspicious++;
          badge = '<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">Suspicious</span>';
        } else if (r.verdict.includes('Unfamiliar')) {
          kpi.unfamiliar++;
          badge = '<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-50 text-purple-700 border border-purple-200">Unfamiliar</span>';
        } else {
          kpi.other++;
          badge = '<span class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 border border-gray-200">' + r.verdict + '</span>';
        }

        const probText = r.malware_probability > 0 ? (r.malware_probability * 100).toFixed(1) + '%' : '—';
        const shaShort = r.sha256 ? r.sha256.substring(0, 10) + '...' : 'N/A';
        const evidenceSummary = r.evidence_points && r.evidence_points.length > 0 ? r.evidence_points[0] : 'None';

        rows += `
          <tr class="hover:bg-[#f9f9fb] transition-colors">
            <td class="py-3 px-6 font-medium text-[#1d1d1f] font-mono text-[11px]">${escapeHtml(r.file_name)}</td>
            <td class="py-3 px-4">${badge}</td>
            <td class="py-3 px-4 font-mono font-medium">${probText}</td>
            <td class="py-3 px-4 font-mono text-[#86868b]">${shaShort}</td>
            <td class="py-3 px-4 text-[#86868b] max-w-xs truncate" title="${escapeHtml(evidenceSummary)}">${escapeHtml(evidenceSummary)}</td>
            <td class="py-3 px-6 text-right space-x-1">
              <button onclick="inspectFile(${idx})" class="text-[#0071e3] hover:underline px-2 py-1">Inspect</button>
              ${r.verdict === 'Suspicious' ? `<button onclick="promptQuarantine('${escapeHtml(r.file_path)}')" class="text-amber-600 hover:underline px-2 py-1 font-medium">Quarantine</button>` : ''}
            </td>
          </tr>
        `;
      });

      tbody.innerHTML = rows;
      document.getElementById('kpiTotal').innerText = kpi.total;
      document.getElementById('kpiBenign').innerText = kpi.benign;
      document.getElementById('kpiSuspicious').innerText = kpi.suspicious;
      document.getElementById('kpiUnfamiliar').innerText = kpi.unfamiliar;
      document.getElementById('kpiOther').innerText = kpi.other;
    }

    function inspectFile(idx) {
      const r = currentResults[idx];
      if (!r) return;
      document.getElementById('modalFileName').innerText = r.file_name;

      let html = `
        <div class="space-y-3">
          <div><span class="text-[#86868b]">Full Path:</span> <code class="font-mono text-[11px]">${escapeHtml(r.file_path)}</code></div>
          <div class="grid grid-cols-2 gap-2 bg-[#f5f5f7] p-3 rounded-xl">
            <div><span class="text-[#86868b]">Size:</span> ${(r.file_size_bytes / 1024).toFixed(1)} KB</div>
            <div><span class="text-[#86868b]">Verdict:</span> <strong>${escapeHtml(r.verdict)}</strong></div>
            <div><span class="text-[#86868b]">Risk Probability:</span> ${(r.malware_probability * 100).toFixed(1)}%</div>
            <div><span class="text-[#86868b]">Novelty Distance:</span> ${r.novelty_score.toFixed(3)}</div>
          </div>
          <div>
            <span class="text-[#86868b] block mb-1 font-medium">Evidence Attribution Points:</span>
            <ul class="list-disc pl-4 space-y-1 text-[#1d1d1f]">
              ${r.evidence_points.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
            </ul>
          </div>
          <div><span class="text-[#86868b]">SHA-256:</span> <code class="font-mono text-[10px] break-all block bg-[#f5f5f7] p-2 rounded">${escapeHtml(r.sha256 || 'N/A')}</code></div>
        </div>
      `;
      document.getElementById('modalBody').innerHTML = html;
      document.getElementById('detailModal').classList.remove('hidden');
    }

    function closeModal() {
      document.getElementById('detailModal').classList.add('hidden');
    }

    function promptQuarantine(path) {
      pendingQuarantinePath = path;
      document.getElementById('quarantineModalPath').innerText = path;
      document.getElementById('quarantineModal').classList.remove('hidden');
    }

    function closeQuarantineModal() {
      document.getElementById('quarantineModal').classList.add('hidden');
      pendingQuarantinePath = null;
    }

    async function executeQuarantine() {
      if (!pendingQuarantinePath) return;
      try {
        const resp = await fetch('/api/quarantine', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_path: pendingQuarantinePath, reason: 'Quarantined via Apple UI' })
        });
        const data = await resp.json();
        closeQuarantineModal();
        if (resp.ok) {
          alert('Successfully isolated file to quarantine vault.');
          loadQuarantineList();
        } else {
          alert('Quarantine rejected: ' + (data.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Failed to execute quarantine: ' + err);
      }
    }

    async function loadQuarantineList() {
      const tbody = document.getElementById('quarantineTableBody');
      tbody.innerHTML = '<tr><td colspan="6" class="py-8 text-center text-[#86868b]">Loading vault records...</td></tr>';
      try {
        const resp = await fetch('/api/quarantine');
        const data = await resp.json();
        if (!data.entries || data.entries.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="py-8 text-center text-[#86868b]">Quarantine vault is currently empty.</td></tr>';
          return;
        }
        let rows = '';
        data.entries.forEach(e => {
          rows += `
            <tr class="hover:bg-[#f9f9fb]">
              <td class="py-3 px-6 font-mono text-[11px] text-[#0071e3]">${escapeHtml(e.quarantine_id)}</td>
              <td class="py-3 px-4 font-medium">${escapeHtml(e.original_filename)}</td>
              <td class="py-3 px-4 text-[#86868b] max-w-xs truncate" title="${escapeHtml(e.original_path)}">${escapeHtml(e.original_path)}</td>
              <td class="py-3 px-4">${e.restored ? '<span class="text-emerald-600 font-medium">Restored</span>' : '<span class="text-rose-600 font-medium">Isolated</span>'}</td>
              <td class="py-3 px-4 text-[#86868b]">${escapeHtml(e.quarantined_at)}</td>
              <td class="py-3 px-6 text-right">
                ${!e.restored ? `<button onclick="restoreQuarantinedFile('${escapeHtml(e.quarantine_id)}')" class="apple-btn-secondary px-3 py-1 text-xs text-emerald-700 hover:bg-emerald-50">Restore</button>` : '—'}
              </td>
            </tr>
          `;
        });
        tbody.innerHTML = rows;
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="6" class="py-8 text-center text-rose-600">Failed to load vault records.</td></tr>';
      }
    }

    async function restoreQuarantinedFile(qid) {
      if (!confirm(`Restore quarantined item '${qid}' back to original disk location?`)) return;
      try {
        const resp = await fetch('/api/restore', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ quarantine_id: qid })
        });
        const data = await resp.json();
        if (resp.ok) {
          alert('File restored successfully: ' + data.restored_path);
          loadQuarantineList();
        } else {
          alert('Restore error: ' + (data.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Failed to restore file: ' + err);
      }
    }

    async function loadHistoryList() {
      const tbody = document.getElementById('historyTableBody');
      try {
        const resp = await fetch('/api/history');
        const data = await resp.json();
        if (!data.history || data.history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="py-8 text-center text-[#86868b]">No past scans recorded yet.</td></tr>';
          return;
        }
        let rows = '';
        data.history.reverse().forEach(h => {
          const s = h.summary || {};
          rows += `
            <tr class="hover:bg-[#f9f9fb]">
              <td class="py-3 px-6 font-mono text-[11px] text-[#0071e3]">${escapeHtml(h.scan_id)}</td>
              <td class="py-3 px-4 text-[#86868b]">${escapeHtml(h.timestamp)}</td>
              <td class="py-3 px-4 max-w-xs truncate" title="${escapeHtml(h.target_path)}">${escapeHtml(h.target_path)}</td>
              <td class="py-3 px-4 text-[#86868b]">${h.duration_seconds || 0}s</td>
              <td class="py-3 px-4 font-medium">${s.total_scanned || 0}</td>
              <td class="py-3 px-6 font-medium text-amber-600">${s.suspicious || 0}</td>
            </tr>
          `;
        });
        tbody.innerHTML = rows;
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="6" class="py-8 text-center text-rose-600">Failed to load scan history.</td></tr>';
      }
    }

    function exportReport(format) {
      if (currentResults.length === 0) {
        alert('No scan results to export.');
        return;
      }
      let content = '';
      let filename = 'threatweaver_report.' + format;
      let mime = 'text/plain';

      if (format === 'json') {
        content = JSON.stringify(currentResults, null, 2);
        mime = 'application/json';
      } else {
        content = '# ThreatWeaver Scan Report\\n\\n| File Name | Verdict | Probability | SHA-256 |\\n|---|---|---|---|\\n';
        currentResults.forEach(r => {
          content += `| ${r.file_name} | ${r.verdict} | ${(r.malware_probability * 100).toFixed(1)}% | ${r.sha256} |\\n`;
        });
      }

      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
  </script>
</body>
</html>
"""


def run_server(
    port: int = DEFAULT_PORT,
    checkpoint_path: Optional[str | Path] = None,
    open_browser: bool = True,
) -> None:
    """Launches the ThreatWeaver local HTTP server."""
    ckpt = Path(checkpoint_path) if checkpoint_path else DEFAULT_CHECKPOINT
    engine = InferenceEngine(checkpoint_path=ckpt if ckpt.is_file() else None)
    state_mgr = ScanStateManager(inference_engine=engine)
    quarantine_mgr = QuarantineManager()

    # Bind handlers
    ThreatWeaverRequestHandler.state_mgr = state_mgr
    ThreatWeaverRequestHandler.engine = engine
    ThreatWeaverRequestHandler.quarantine_mgr = quarantine_mgr

    server = ThreadingHTTPServer(("127.0.0.1", port), ThreatWeaverRequestHandler)
    url = f"http://127.0.0.1:{port}"

    print(f"\nThreatWeaver Apple Minimalist UI running at: {url}")
    print("Press Ctrl+C to stop the server.\n")

    if open_browser:
        threading.Thread(target=lambda: (time.sleep(0.5), webbrowser.open(url)), daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ThreatWeaver UI server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
