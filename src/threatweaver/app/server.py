"""ThreatWeaver Local UI Web Server with Apple Minimalist Design.

Provides a zero-cloud, local-first HTTP service and REST API for on-demand scanning,
quarantine management, interactive threat relationship visualization, family exploration,
continual learning research telemetry, and real-time inspection.
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
from threatweaver.app import security
from threatweaver.app.security import PathPolicyError
from threatweaver.quarantine.manager import QuarantineManager
from threatweaver.learning.adaptation_service import AdaptationService
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
        self.target_path: str = ""
        self.is_full_system: bool = False

    def start_scan(self, target_path: str, only_pe_extensions: bool = True) -> bool:
        with self.lock:
            if self.is_scanning:
                return False
            self.service._cancel_requested.clear()
            self.is_scanning = True
            self.target_path = target_path
            self.is_full_system = (str(target_path).strip().upper() in ("FULL_SYSTEM", "SYSTEM"))
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
            def serialize_r(r: ScanResult) -> Dict[str, Any]:
                mv = r.model_version
                triage = "Cache" if "Cached" in mv else ("Authenticode" if "Authenticode" in mv else ("LightGBM" if "LightGBM" in mv else "Neural"))
                return {
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
                    "model_version": r.model_version,
                    "triage_stage": triage,
                    "nearest_known_cluster": r.nearest_known_cluster,
                    "warning_message": r.warning_message,
                    "explanation": r.explanation,
                }

            latest = serialize_r(self.results[-1]) if self.results else None
            cache_obj = getattr(self.service.engine, "hash_cache", None)
            sig_obj = getattr(self.service.engine, "signature_verifier", None)

            return {
                "is_scanning": self.is_scanning,
                "completed": self.completed_count,
                "total": self.total_count,
                "current_file": self.current_file,
                "results_count": len(self.results),
                "latest_result": latest,
                "results": [serialize_r(r) for r in (self.results[-150:] if self.is_scanning else self.results[-500:])],
                "cache_stats": {
                    "enabled": getattr(cache_obj, "enabled", False),
                    "entries": getattr(cache_obj, "count", lambda: 0)(),
                    "hits": getattr(cache_obj, "hits", 0),
                    "misses": getattr(cache_obj, "misses", 0),
                },
                "signature_verifier_enabled": getattr(sig_obj, "enabled", False),
                "target_path": self.target_path,
                "is_full_system": self.is_full_system,
            }


class ThreatWeaverRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler delivering the Apple Minimalist UI & REST endpoints."""

    state_mgr: ScanStateManager
    engine: InferenceEngine
    quarantine_mgr: QuarantineManager
    adaptation_svc: Optional[AdaptationService] = None
    api_token: str = ""
    allowed_host_set: set = set()

    def _reject_if_unauthorized(self, method: str, path: str) -> bool:
        """Applies Host/Origin/token/body checks. Returns True if the request was rejected."""
        verdict = security.guard_request(method, path, self.headers, self.api_token, self.allowed_host_set)
        if verdict is None:
            return False
        status, reason = verdict
        self._serve_json({"error": reason}, status=HTTPStatus(status))
        return True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if self._reject_if_unauthorized("GET", path):
            return
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._serve_html_ui()
        elif path == "/api/status":
            self._serve_json(self._get_system_status())
        elif path == "/api/browse-paths":
            self._serve_json(self._get_browse_paths())
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
        elif path == "/api/embedding-ablation":
            self._serve_embedding_ablation()
        elif path == "/api/threat-network":
            self._serve_json(self._get_threat_network_data())
        elif path == "/api/families":
            self._serve_json(self._get_families_data())
        elif path == "/api/timeline":
            self._serve_json(self._get_timeline_data())
        elif path == "/api/learning/prototypes":
            self._ensure_adaptation_svc()
            protos = self.engine.novelty_detector.get_prototypes_summary() if self.engine.novelty_detector else []
            self._serve_json({
                "prototypes": protos,
                "total_prototypes": len(protos),
                "novelty_threshold": getattr(self.engine.novelty_detector, "threshold", 0.40),
            })
        elif path == "/api/learning/queue":
            self._ensure_adaptation_svc()
            self._serve_json({
                "items": self.adaptation_svc.queue.list_all(),
                "pending_count": len(self.adaptation_svc.queue.get_pending()),
                "last_report": self.adaptation_svc.last_adaptation_report,
            })
        elif path == "/api/sample-details":
            sha = query.get("sha256", [""])[0] or query.get("id", [""])[0]
            self._serve_json(self._get_sample_details(sha))
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if self._reject_if_unauthorized("POST", path):
            return
        body = self._read_json_body()
        if body is None:
            self._serve_json({"error": "Request body must be a JSON object."}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            self._dispatch_post(path, body)
        except PathPolicyError as e:
            self._serve_json({"error": str(e)}, status=HTTPStatus.BAD_REQUEST)

    def _dispatch_post(self, path: str, body: Dict[str, Any]) -> None:

        if path == "/api/scan":
            raw_target = str(body.get("target_path", ".")).strip().strip("'\"")
            scan_mode = body.get("scan_mode", "custom")
            is_full = (scan_mode == "full_system") or (raw_target.upper() in ("FULL_SYSTEM", "SYSTEM"))
            if is_full:
                target_str = "FULL_SYSTEM"
                target_display = "Full System (All Drives)"
            else:
                target_p = security.validate_user_path(raw_target, must_exist=True)
                target_str = str(target_p)
                target_display = str(target_p)
            only_pe = not body.get("all_files", False)
            started = self.state_mgr.start_scan(target_str, only_pe_extensions=only_pe)
            if started:
                self._serve_json({"status": "started", "target": target_display, "is_full_system": is_full})
            else:
                self._serve_json({"error": "Scan already in progress"}, status=HTTPStatus.CONFLICT)
        elif path == "/api/scan/cancel":
            self.state_mgr.cancel_scan()
            self._serve_json({"status": "cancelled"})

        elif path == "/api/quarantine":
            file_p = str(security.validate_user_path(body.get("file_path"), must_exist=True))
            reason = str(body.get("reason", "Manual isolation from UI"))[:500]
            dry_run = bool(body.get("dry_run", False))
            try:
                entry = self.quarantine_mgr.quarantine_file(file_p, reason=reason, dry_run=dry_run)
                self._serve_json({"status": "success", "entry": entry.__dict__})
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/restore":
            qid = security.validate_quarantine_id(body.get("quarantine_id"))
            dry_run = bool(body.get("dry_run", False))
            try:
                restored = self.quarantine_mgr.restore_file(qid, dry_run=dry_run)
                self._serve_json({"status": "success", "restored_path": str(restored)})
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/learning/prototype":
            self._ensure_adaptation_svc()
            file_p = str(security.validate_user_path(body.get("file_path"), must_exist=True))
            lbl = int(body.get("label", 1))
            family = str(body.get("family_name", "UserVariant"))[:120]
            persist = bool(body.get("persist", False))
            if not file_p:
                self._serve_json({"error": "file_path is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            try:
                res = self.adaptation_svc.register_instant_prototype(
                    file_path=file_p,
                    label=lbl,
                    family_name=family,
                    persist=persist,
                )
                self._serve_json(res)
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/learning/queue":
            self._ensure_adaptation_svc()
            file_p = str(security.validate_user_path(body.get("file_path"), must_exist=True))
            lbl = int(body.get("label", 1))
            family = str(body.get("family_name", ""))[:120]
            verdict = str(body.get("detected_verdict", "Unfamiliar"))
            novelty = float(body.get("novelty_score", 0.0))
            if not file_p:
                self._serve_json({"error": "file_path is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            try:
                res = self.adaptation_svc.enqueue_for_continual_learning(
                    file_path=file_p,
                    assigned_label=lbl,
                    family_name=family,
                    detected_verdict=verdict,
                    novelty_score=novelty,
                )
                self._serve_json(res)
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/learning/queue/clear":
            self._ensure_adaptation_svc()
            self.adaptation_svc.queue.clear()
            self._serve_json({"status": "success", "cleared": True})

        elif path == "/api/learning/adapt":
            self._ensure_adaptation_svc()
            epochs = int(body.get("epochs", 5))
            lr = float(body.get("lr", 0.0003))
            replay_count = int(body.get("replay_count", 30))
            persist = bool(body.get("persist", False))
            try:
                res = self.adaptation_svc.run_continual_adaptation(
                    epochs=epochs,
                    lr=lr,
                    replay_count=replay_count,
                    persist=persist,
                )
                self._serve_json(res)
            except Exception as e:
                self._serve_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/settings":
            thresh = body.get("novelty_threshold")
            if thresh is not None and self.engine.novelty_detector:
                self.engine.novelty_detector.threshold = float(thresh)
            workers = body.get("max_workers")
            if workers is not None:
                self.state_mgr.service.max_workers = int(workers)
            enable_sig = body.get("enable_signature_verifier")
            if enable_sig is not None and hasattr(self.engine, "signature_verifier"):
                self.engine.signature_verifier.enabled = bool(enable_sig)
            enable_cache = body.get("enable_hash_cache")
            if enable_cache is not None and hasattr(self.engine, "hash_cache"):
                self.engine.hash_cache.enabled = bool(enable_cache)
            if body.get("clear_cache", False) and hasattr(self.engine, "hash_cache"):
                self.engine.hash_cache.clear()
            self._serve_json({
                "status": "success",
                "settings": {
                    "novelty_threshold": getattr(self.engine.novelty_detector, "threshold", 0.40),
                    "max_workers": self.state_mgr.service.max_workers,
                    "enable_signature_verifier": getattr(self.engine.signature_verifier, "enabled", False),
                    "enable_hash_cache": getattr(self.engine.hash_cache, "enabled", False),
                    "cached_entries": getattr(self.engine.hash_cache, "count", lambda: 0)(),
                }
            })

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")


    def _ensure_adaptation_svc(self) -> None:
        if getattr(ThreatWeaverRequestHandler, "adaptation_svc", None) is None:
            ThreatWeaverRequestHandler.adaptation_svc = AdaptationService(engine=self.engine)

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if self._reject_if_unauthorized("DELETE", path):
            return
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/learning/queue":
            self._ensure_adaptation_svc()
            item_id = query.get("id", [""])[0]
            if item_id:
                removed = self.adaptation_svc.queue.remove(item_id)
                self._serve_json({"status": "success", "removed": removed})
            else:
                self.adaptation_svc.queue.clear()
                self._serve_json({"status": "success", "cleared": True})
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        """Reads a JSON object body (size already capped by the request guard). None if malformed."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if length <= 0:
            return {}
        try:
            data = json.loads(self.rfile.read(min(length, security.MAX_BODY_BYTES)).decode("utf-8"))
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    def _serve_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _get_system_status(self) -> Dict[str, Any]:
        history = ScanHistoryManager().load_history()
        total_files_scanned = sum(h.get("summary", {}).get("total_scanned", 0) for h in history)
        suspicious_count = sum(
            h.get("summary", {}).get(k, 0) for h in history for k in ("suspicious", "likely_malicious", "known_malicious"))
        unfamiliar_count = sum(h.get("summary", {}).get("unfamiliar", 0) for h in history)

        # Include active session results
        with self.state_mgr.lock:
            if self.state_mgr.results:
                total_files_scanned = max(total_files_scanned, len(self.state_mgr.results))
                suspicious_count = max(suspicious_count, sum(1 for r in self.state_mgr.results if r.verdict == ScanVerdict.SUSPICIOUS))
                unfamiliar_count = max(unfamiliar_count, sum(1 for r in self.state_mgr.results if r.verdict == ScanVerdict.UNFAMILIAR))

        model = self.engine.model if self.engine else None
        emb_dim = getattr(model, "embedding_dim", None) if model is not None else None
        temp = float(getattr(model, "temperature", 1.0)) if model is not None else None
        residual_blocks = None
        model_kind = None
        architecture = "No model loaded"
        if model is not None:
            from threatweaver.models.encoder import ResidualBlock
            residual_blocks = sum(1 for m in model.modules() if isinstance(m, ResidualBlock))
            model_kind = "ResMLP" if residual_blocks else "MLP"
            architecture = f"{model.input_dim}-D static -> {model_kind} -> {emb_dim}-D L2 (T={temp:.2f})"
        return {
            "version": __version__,
            "model_version": self.engine.model_version,
            "model_kind": model_kind,
            "residual_blocks": residual_blocks,
            "embedding_dim": emb_dim,
            "temperature": temp,
            "architecture": architecture,
            "model_loaded": self.engine.checkpoint_loaded,
            "checkpoint_path": str(self.engine.checkpoint_path) if self.engine.checkpoint_path else None,
            "dataset": self._get_dataset_manifest_summary(),
            "device": str(self.engine.device),
            "novelty_threshold": self.engine.novelty_detector.threshold if self.engine.novelty_detector else None,
            "quarantine_count": len(self.quarantine_mgr.list_quarantined_files()),
            "total_files_scanned": total_files_scanned,
            "suspicious_count": suspicious_count,
            "unfamiliar_count": unfamiliar_count,
            "protection_mode": "On-Demand Only",
            "protection_note": "Research prototype — Background real-time protection is inactive.",
        }

    def _get_dataset_manifest_summary(self) -> Dict[str, Any]:
        """Reads the dataset manifest written by the EMBER2024 verifier (no hardcoded counts)."""
        p = Path("artifacts/dataset/ember2024_manifest.json")
        if not p.is_file():
            return {"available": False, "reason": "No dataset manifest at artifacts/dataset/ember2024_manifest.json"}
        try:
            with open(p, "r", encoding="utf-8") as f:
                m = json.load(f)
        except Exception as e:
            return {"available": False, "reason": f"Manifest unreadable: {e}"}
        keys = ("samples", "benign", "malicious", "unlabeled", "corrupt_records", "total_bytes",
                "time_span", "file_types", "verified", "manifest_timestamp")
        out = {k: m.get(k) for k in keys}
        out["available"] = True
        out["source"] = str(p)
        # EMBER2024 files contain every sample twice; prefer unique-SHA-256 counts when available.
        fam = Path("artifacts/dataset/family_summary.json")
        if fam.is_file():
            try:
                totals = json.loads(fam.read_text(encoding="utf-8")).get("totals", {})
                if "unique_samples" in totals:
                    out["unique_samples"] = totals["unique_samples"]
                    out["unique_benign"] = totals.get("unique_benign", 0)
                    out["unique_malicious"] = totals.get("unique_malicious", 0)
            except (OSError, ValueError):
                pass
        return out

    def _serve_embedding_ablation(self) -> None:
        p_res = Path("artifacts/benchmarks/embedding_dimension_results.json")
        p_sel = Path("artifacts/benchmarks/selected_embedding_dimension.json")
        data: Dict[str, Any] = {}
        if p_res.is_file():
            try:
                with open(p_res, "r", encoding="utf-8") as f:
                    data["results"] = json.load(f)
            except Exception:
                pass
        if p_sel.is_file():
            try:
                with open(p_sel, "r", encoding="utf-8") as f:
                    data["selection"] = json.load(f)
            except Exception:
                pass
        self._serve_json(data if data else {"status": "No embedding dimension ablation report available yet"})

    def _serve_research_results(self) -> None:
        p_bench = Path("artifacts/benchmarks/continual_learning_results.json")
        p_rep = Path("reports/continual_learning_results.json")
        target = p_bench if p_bench.is_file() else p_rep
        if target.is_file():
            try:
                with open(target, "r", encoding="utf-8") as f:
                    self._serve_json(json.load(f))
                    return
            except Exception:
                pass
        self._serve_json({"status": "No benchmark reports available yet"})

    # ------------------------------------------------------------------
    # Data-provenance rule: every value returned below is either measured
    # (scan results, checkpoint prototypes, dataset metadata, benchmark
    # artifacts) or explicitly reported as unavailable. Nothing is invented.
    # ------------------------------------------------------------------

    def _collect_scanned_samples(self) -> List[Dict[str, Any]]:
        """Returns results from the active session, else from the latest saved scan."""
        samples: List[Dict[str, Any]] = []
        with self.state_mgr.lock:
            for r in self.state_mgr.results:
                samples.append({
                    "file_name": r.file_name,
                    "file_path": r.file_path,
                    "file_size_bytes": r.file_size_bytes,
                    "sha256": r.sha256,
                    "verdict": r.verdict.value,
                    "malware_probability": r.malware_probability,
                    "novelty_score": r.novelty_score,
                    "is_novel": r.is_novel,
                    "evidence_points": r.evidence_points,
                    "scan_duration_ms": r.scan_duration_ms,
                    "nearest_known_cluster": r.nearest_known_cluster,
                    "model_version": r.model_version,
                    "warning_message": r.warning_message,
                    "explanation": r.explanation,
                })
        if not samples:
            try:
                hist = ScanHistoryManager().load_history()
                if hist:
                    samples = list(hist[-1].get("results", []))
            except Exception:
                pass
        return samples

    def _get_threat_network_data(self) -> Dict[str, Any]:
        """Graph of scanned files and the model's real prototype clusters.

        Sample -> cluster edges use the nearest prototype and cosine similarity
        (1 - novelty distance) actually computed by the novelty detector at scan time.
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        protos = self.engine.novelty_detector.get_prototypes_summary() if self.engine.novelty_detector else []
        proto_ids: Dict[str, str] = {}
        for p in protos:
            pid = f"proto-{p['family_name']}"
            proto_ids[p["family_name"]] = pid
            nodes.append({
                "id": pid,
                "label": p["family_name"],
                "type": "prototype",
                "category": "malware" if p["label"] == 1 else "benign",
                "sample_count": p["sample_count"],
                "dimension": p["dimension"],
                "source": "checkpoint prototype (k-means centroid of training embeddings)",
            })

        scanned = self._collect_scanned_samples()
        for idx, s in enumerate(scanned):
            sha = s.get("sha256") or ""
            node_id = f"s-{sha[:12]}" if sha else f"s-{idx}"
            verdict = str(s.get("verdict", ""))
            nodes.append({
                "id": node_id,
                "label": s.get("file_name", ""),
                "type": "sample",
                "verdict": verdict,
                "risk": s.get("malware_probability"),
                "novelty": s.get("novelty_score"),
                "is_novel": s.get("is_novel", False),
                "file_path": s.get("file_path", ""),
                "file_size_bytes": s.get("file_size_bytes", 0),
                "sha256": sha,
                "evidence_points": s.get("evidence_points", []),
                "scan_duration_ms": s.get("scan_duration_ms"),
                "nearest_cluster": s.get("nearest_known_cluster"),
            })
            nearest = s.get("nearest_known_cluster")
            # Only neural-tier results (fresh or cached) carry a measured embedding distance.
            mv = str(s.get("model_version", ""))
            if nearest and nearest in proto_ids and "Authenticode" not in mv and "Model Not Loaded" not in mv:
                distance = float(s.get("novelty_score") or 0.0)
                edges.append({
                    "source": node_id,
                    "target": proto_ids[nearest],
                    "similarity": round(1.0 - distance, 4),
                    "relationship": "Nearest prototype (measured cosine similarity)",
                    "type": "sample_to_prototype",
                })

        fs_items, fs_edges = self._build_filesystem_web(scanned)
        return {
            "nodes": nodes,
            "edges": edges,
            "fs_items": fs_items,
            "fs_edges": fs_edges,
            "available": bool(scanned),
            "reason": None if scanned else "No scan results yet. Run a scan to populate the graph.",
        }

    def _build_filesystem_web(
        self, scanned_samples: List[Dict[str, Any]]
    ) -> "tuple[List[Dict[str, Any]], List[List[int]]]":
        """Lays out scanned files around their directories (or verdict groups for one directory).

        Positions are a deterministic radial layout; states come from real scan verdicts.
        """
        import math
        import os

        if not scanned_samples:
            return [], []

        items: List[Dict[str, Any]] = []
        edges: List[List[int]] = []

        first_path = scanned_samples[0].get("file_path", "")
        if first_path:
            p_obj = Path(first_path)
            if len(scanned_samples) == 1:
                target_root_name = f"File Target: {p_obj.name}"
                root_path_str = str(p_obj.parent)
            else:
                parents = [str(Path(s.get("file_path", "")).parent) for s in scanned_samples if s.get("file_path")]
                try:
                    common = os.path.commonpath(parents) if parents else str(p_obj.parent)
                except ValueError:  # paths on different drives
                    common = "Multiple Drives"
                target_root_name = Path(common).name or common or "Scanned Target"
                root_path_str = str(common)
        else:
            target_root_name = "Scanned Target"
            root_path_str = "Target Root"

        root_idx = 0
        items.append({"name": target_root_name, "kind": "folder", "state": "benign",
                      "x": 0.50, "y": 0.50, "path": root_path_str})

        def file_state(f: Dict[str, Any]) -> str:
            verdict = str(f.get("verdict", ""))
            if "Suspicious" in verdict or "Malicious" in verdict:
                return "threat"
            if "Unfamiliar" in verdict or bool(f.get("is_novel")):
                return "novel"
            return "benign"

        dir_groups: Dict[str, List[Dict[str, Any]]] = {}
        for s in scanned_samples:
            p_str = s.get("file_path", "")
            d = str(Path(p_str).parent) if p_str else "Target Root"
            dir_groups.setdefault(d, []).append(s)

        hub_specs: List[Dict[str, Any]] = []
        if len(dir_groups) == 1:
            only_dir, all_files = next(iter(dir_groups.items()))
            groups = [
                ("Flagged by model", "threat", [f for f in all_files if file_state(f) == "threat"]),
                ("Unfamiliar / OOD", "novel", [f for f in all_files if file_state(f) == "novel"]),
                ("Executables (.exe)", "benign", [f for f in all_files if file_state(f) == "benign" and f.get("file_name", "").lower().endswith(".exe")]),
                ("Libraries (.dll)", "benign", [f for f in all_files if file_state(f) == "benign" and f.get("file_name", "").lower().endswith(".dll")]),
            ]
            grouped = {id(f) for _, _, fs in groups for f in fs}
            groups.append(("Other files", "benign", [f for f in all_files if id(f) not in grouped]))
            for name, state, files in groups:
                if files:
                    hub_specs.append({"name": name, "state": state, "files": files, "desc": only_dir})
        else:
            for d_path, d_files in dir_groups.items():
                states = {file_state(f) for f in d_files}
                h_state = "threat" if "threat" in states else ("novel" if "novel" in states else "benign")
                hub_specs.append({"name": Path(d_path).name or d_path, "state": h_state,
                                  "files": d_files, "desc": str(d_path)})

        num_hubs = max(len(hub_specs), 1)
        for h_idx, h_spec in enumerate(hub_specs):
            h_angle = (2.0 * math.pi * h_idx) / num_hubs
            hx = round(0.50 + 0.28 * math.cos(h_angle), 3)
            hy = round(0.50 + 0.24 * math.sin(h_angle), 3)
            hub_node_idx = len(items)
            items.append({"name": h_spec["name"], "kind": "folder", "state": h_spec["state"],
                          "x": hx, "y": hy, "path": h_spec.get("desc", h_spec["name"])})
            edges.append([root_idx, hub_node_idx])

            h_files = h_spec["files"]
            n_files = len(h_files)
            for f_idx, f_data in enumerate(h_files):
                f_spread = 0.40 if n_files > 4 else 0.60
                f_angle = h_angle - (f_spread * math.pi * 0.5) + (f_idx + 1) * (f_spread * math.pi / max(n_files, 1))
                f_dist = 0.10 + (0.04 * (f_idx % 2))
                fx = round(max(0.04, min(0.96, hx + f_dist * math.cos(f_angle))), 3)
                fy = round(max(0.04, min(0.96, hy + f_dist * math.sin(f_angle))), 3)
                file_node_idx = len(items)
                items.append({
                    "name": f_data.get("file_name", ""),
                    "kind": "file",
                    "state": file_state(f_data),
                    "x": fx,
                    "y": fy,
                    "prob": round(float(f_data.get("malware_probability") or 0.0), 3),
                    "novel": round(float(f_data.get("novelty_score") or 0.0), 3),
                    "sha256": f_data.get("sha256", ""),
                    "path": f_data.get("file_path", ""),
                    "verdict": f_data.get("verdict", ""),
                    "evidence": f_data.get("evidence_points", []),
                })
                edges.append([hub_node_idx, file_node_idx])

        return items, edges

    def _get_families_data(self) -> Dict[str, Any]:
        """Serves family statistics counted from local EMBER2024 metadata (tools/build_family_summary.py)."""
        p = Path("artifacts/dataset/family_summary.json")
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                return {"available": False, "families": [], "reason": f"Family summary unreadable: {e}"}
        return {
            "available": False,
            "families": [],
            "reason": "No family summary yet. Run: python tools/build_family_summary.py",
        }

    def _get_timeline_data(self) -> Dict[str, Any]:
        """Continual-learning results with explicit provenance.

        Real results: artifacts/benchmarks/continual_learning_results.json, produced by
        tools/run_real_ember_benchmarks.py from 5 consecutive 2-week windows of EMBER2024 Dot_Net_test.
        reports/continual_learning_results.json is produced from SYNTHETIC data and is labelled as such.
        """
        real_p = Path("artifacts/benchmarks/continual_learning_results.json")
        synth_p = Path("reports/continual_learning_results.json")

        if real_p.is_file():
            try:
                with open(real_p, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                return {"available": False, "reason": f"Benchmark artifact unreadable: {e}"}
            strategies = {
                k: {
                    "name": k,
                    "macro_f1_mean": v.get("final_macro_f1"),
                    "forgetting_mean": v.get("catastrophic_forgetting"),
                    "bwt_mean": v.get("backward_transfer"),
                    "fpr_mean": v.get("final_fpr"),
                    "time_sec_mean": v.get("training_time_sec"),
                    "r_matrix": v.get("r_matrix"),
                }
                for k, v in raw.items() if isinstance(v, dict)
            }
            batches: List[Dict[str, Any]] = []
            dn_files = sorted(Path("data/ember2024/Dot_Net_test").glob("*.jsonl"))
            for b in range(5):
                pair = dn_files[2 * b: 2 * b + 2]
                if len(pair) == 2:
                    start = pair[0].name.split("_")[0]
                    end = pair[1].name.split("_")[1]
                    batches.append({"batch_id": f"T{b + 1}", "window_start": start, "window_end": end,
                                    "partition": "Dot_Net_test", "files": [x.name for x in pair]})
            return {
                "available": True,
                "kind": "benchmark",
                "source": str(real_p),
                "dataset": "EMBER2024 Dot_Net_test (5 consecutive two-week windows)",
                "caveats": [
                    "Single run (no seed repetition); uses the legacy 256-D harmonized features.",
                    "Batch windows are derived from the weekly file names used by tools/run_real_ember_benchmarks.py.",
                ],
                "batches": batches,
                "strategies": strategies,
            }

        if synth_p.is_file():
            try:
                with open(synth_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {
                    "available": True,
                    "kind": "synthetic",
                    "source": str(synth_p),
                    "caveats": ["Produced from generate_synthetic_benchmark_dataset; not real malware data."],
                    "batches": [],
                    "strategies": data.get("strategy_summaries", {}),
                    "metadata": data.get("metadata", {}),
                }
            except Exception:
                pass
        return {"available": False, "reason": "No continual-learning results found."}

    def _get_sample_details(self, identifier: str) -> Dict[str, Any]:
        """Returns the stored scan result for a file. Per-feature attribution is not yet implemented."""
        if not identifier:
            return {"available": False, "reason": "Provide ?sha256=<hash> or ?id=<node id>."}
        for s in self._collect_scanned_samples():
            sha = s.get("sha256") or ""
            if identifier in (sha, f"s-{sha[:12]}") or (len(identifier) >= 8 and sha.startswith(identifier)):
                expl = s.get("explanation")
                return {
                    "available": True,
                    "sample": s,
                    "feature_attribution": expl,
                    "feature_attribution_note": None if expl else (
                        "Attribution is computed by the LightGBM (v2) detector for fresh scans; this result came "
                        "from the legacy model or the cache."),
                }
        return {"available": False, "reason": f"No scanned sample matches '{identifier}'."}

    def _get_browse_paths(self) -> Dict[str, Any]:
        """Provides curated system paths and detectable local targets for quick selection."""
        base_dir = Path.cwd().resolve()
        presets = []

        # 1. Primary: Curated Synthetic PE Test Samples
        samples_dir = base_dir / "samples"
        if samples_dir.is_dir():
            presets.append({"group": "Curated PE Test Samples", "label": "Synthetic PE Samples Vault (samples/)", "path": str(samples_dir)})
            presets.append({"group": "Curated PE Test Samples", "label": "Benign Utility Binary (benign_utility.exe)", "path": str(samples_dir / "benign_utility.exe")})
            presets.append({"group": "Curated PE Test Samples", "label": "Suspicious W+X Packed (suspicious_packed.exe)", "path": str(samples_dir / "suspicious_packed.exe")})
            presets.append({"group": "Curated PE Test Samples", "label": "Out-of-Distribution Stub (novelty_stub.exe)", "path": str(samples_dir / "novelty_stub.exe")})

        # 2. Windows System Executables
        sys32 = Path("C:/Windows/System32")
        if sys32.is_dir():
            presets.extend([
                {"group": "Windows System Binaries", "label": "C:\\Windows\\System32\\cmd.exe (Command Shell)", "path": "C:\\Windows\\System32\\cmd.exe"},
                {"group": "Windows System Binaries", "label": "C:\\Windows\\System32\\calc.exe (Calculator)", "path": "C:\\Windows\\System32\\calc.exe"},
                {"group": "Windows System Binaries", "label": "C:\\Windows\\System32\\notepad.exe (Notepad)", "path": "C:\\Windows\\System32\\notepad.exe"},
                {"group": "Windows System Binaries", "label": "C:\\Windows\\System32\\taskmgr.exe (Task Manager)", "path": "C:\\Windows\\System32\\taskmgr.exe"},
                {"group": "Windows System Binaries", "label": "C:\\Windows\\System32 (Entire Directory)", "path": "C:\\Windows\\System32"},
                {"group": "Windows System Binaries", "label": "C:\\Windows\\explorer.exe (Windows Shell)", "path": "C:\\Windows\\explorer.exe"},
            ])

        # 3. ThreatWeaver Workspace Directories
        venv_scripts = base_dir / ".venv" / "Scripts"
        if venv_scripts.is_dir():
            presets.append({"group": "ThreatWeaver Workspace", "label": "Python Virtualenv (.venv/Scripts)", "path": str(venv_scripts)})

        presets.extend([
            {"group": "ThreatWeaver Workspace", "label": "Full Project Workspace (Repo Root)", "path": str(base_dir)},
            {"group": "ThreatWeaver Workspace", "label": "Test Fixtures & Binaries", "path": str(base_dir / "tests")},
            {"group": "ThreatWeaver Workspace", "label": "Model Checkpoints Vault", "path": str(base_dir / "artifacts" / "checkpoints")},
            {"group": "ThreatWeaver Workspace", "label": "Quarantine Store Vault", "path": str(base_dir / "quarantine_store")},
        ])

        ember_dir = base_dir / "data" / "ember2024"
        if ember_dir.is_dir():
            presets.append({"group": "ThreatWeaver Workspace", "label": "EMBER2024 Local Dataset", "path": str(ember_dir)})
        drives = []
        if os.name == "nt":
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                dp = Path(f"{letter}:\\")
                if dp.exists():
                    drives.append({"drive": f"{letter}:\\", "label": f"Drive {letter}: ({'System' if letter == 'C' else 'Volume'})"})
        else:
            drives.append({"drive": "/", "label": "Root Filesystem (/)"})

        return {"presets": presets, "drives": drives}

    def _serve_html_ui(self) -> None:
        html = get_apple_minimalist_html().replace("__TW_API_TOKEN__", self.api_token, 1)
        raw = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: Any) -> None:
        pass


from threatweaver.app.ui_html import get_apple_minimalist_html


def create_server(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    checkpoint_path: Optional[str | Path] = None,
    bundle_path: Optional[str | Path] = None,
) -> tuple[ThreadingHTTPServer, str]:
    """Configures and instantiates the ThreatWeaver HTTP server instance."""
    ckpt = Path(checkpoint_path) if checkpoint_path else DEFAULT_CHECKPOINT
    engine = InferenceEngine(checkpoint_path=ckpt if ckpt.is_file() else None, isolate_extraction=True,
                             bundle_path=bundle_path)
    state_mgr = ScanStateManager(inference_engine=engine)
    quarantine_mgr = QuarantineManager()

    # Bind handlers
    adaptation_svc = AdaptationService(engine=engine)
    ThreatWeaverRequestHandler.state_mgr = state_mgr
    ThreatWeaverRequestHandler.engine = engine
    ThreatWeaverRequestHandler.quarantine_mgr = quarantine_mgr
    ThreatWeaverRequestHandler.adaptation_svc = adaptation_svc

    server = ThreadingHTTPServer((host, port), ThreatWeaverRequestHandler)
    bound_port = server.server_address[1]
    ThreatWeaverRequestHandler.api_token = security.generate_token()
    ThreatWeaverRequestHandler.allowed_host_set = security.allowed_hosts(host, bound_port)
    server.api_token = ThreatWeaverRequestHandler.api_token  # type: ignore[attr-defined]
    url = f"http://{host}:{bound_port}"
    return server, url


def run_server(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    checkpoint_path: Optional[str | Path] = None,
    bundle_path: Optional[str | Path] = None,
    open_browser: bool = True,
    print_token: bool = False,
) -> None:
    """Launches the ThreatWeaver local HTTP server."""
    server, url = create_server(host=host, port=port, checkpoint_path=checkpoint_path, bundle_path=bundle_path)

    print(f"\nThreatWeaver Apple Minimalist UI running at: {url}")
    if print_token:
        print(f"API token for scripts (send as {security.TOKEN_HEADER}): {server.api_token}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: bound to {host}; the API is reachable from other machines on this network.")
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