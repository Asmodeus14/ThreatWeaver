"""FastAPI application for ThreatWeaver (v1 API paths preserved, OpenAPI contract added).

The endpoint logic is NOT re-implemented here: ``ApiCore`` runs the existing request
handler's dispatch code without a socket and captures its responses, so the stdlib server
and this app share one implementation and v1 behaviour is identical by construction.
FastAPI adds typed request models, the OpenAPI schema (``/api/openapi.json``) and the same
security guard (Host / Origin / token / JSON-only / size limit) as middleware.
"""

# (no `from __future__ import annotations`: FastAPI must see real types on dynamic endpoints)

import json
import urllib.parse
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from threatweaver import __version__
from threatweaver.app import security
from threatweaver.app.server import ThreatWeaverRequestHandler


class ApiCore(ThreatWeaverRequestHandler):
    """The request handler's endpoint logic, callable without a socket."""

    def __init__(self):  # noqa: D401 - deliberately skip BaseHTTPRequestHandler.__init__
        self._captured: Optional[Tuple[int, Any]] = None
        self._body: Dict[str, Any] = {}
        self.headers = {}

    # transport hooks -------------------------------------------------------
    def _reject_if_unauthorized(self, method: str, path: str) -> bool:
        return False  # enforced by the FastAPI middleware

    def _read_json_body(self):
        return self._body

    def _serve_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._captured = (int(status), data)

    def send_error(self, code, message=None, explain=None):  # noqa: D401
        self._captured = (int(code), {"error": message or HTTPStatus(code).phrase})

    def call(self, method: str, path: str, query: str = "", body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        core = ApiCore()  # fresh per request: no state shared between concurrent calls
        core.path = path + (f"?{query}" if query else "")
        core._body = body or {}
        {"GET": core.do_GET, "POST": core.do_POST, "DELETE": core.do_DELETE}[method]()
        return core._captured or (500, {"error": "no response produced"})


# ---------------------------------------------------------------- request models (OpenAPI)

class _Loose(BaseModel):
    model_config = ConfigDict(extra="allow")  # v1 clients may send extra keys; they are ignored


class ScanRequest(_Loose):
    target_path: Optional[str] = Field(None, description="File or folder to scan (ignored for full-system scans)")
    scan_mode: Optional[str] = Field(None, description='"custom" (default) or "full_system"')
    all_files: bool = Field(False, description="Scan all files, not only PE extensions")


class QuarantineRequest(_Loose):
    file_path: str
    reason: Optional[str] = None
    dry_run: bool = False


class RestoreRequest(_Loose):
    quarantine_id: str
    dry_run: bool = False


class PrototypeRequest(_Loose):
    file_path: str
    label: int = 1
    family_name: Optional[str] = None
    persist: bool = False


class QueueRequest(_Loose):
    file_path: str
    label: int = 1
    family_name: Optional[str] = None
    detected_verdict: Optional[str] = None
    novelty_score: Optional[float] = None


class AdaptRequest(_Loose):
    epochs: int = 5
    lr: float = 3e-4
    replay_count: int = 30
    persist: bool = False


class SettingsRequest(_Loose):
    novelty_threshold: Optional[float] = None
    max_workers: Optional[int] = None
    enable_signature_verifier: Optional[bool] = None
    enable_hash_cache: Optional[bool] = None
    clear_cache: Optional[bool] = None


GET_PATHS: List[Tuple[str, str]] = [
    ("/api/status", "System, model and dataset status"),
    ("/api/browse-paths", "Suggested scan targets"),
    ("/api/scan/progress", "Full scan progress (legacy; prefer /api/scan/events)"),
    ("/api/scan/events", "Incremental scan progress (?since=N&seq=S)"),
    ("/api/history", "Scan history"),
    ("/api/quarantine", "Quarantine vault entries"),
    ("/api/research", "Continual-learning benchmark results"),
    ("/api/embedding-ablation", "Embedding-dimension ablation results"),
    ("/api/threat-network", "Graph of scanned files and model prototypes"),
    ("/api/families", "Malware families counted from dataset metadata"),
    ("/api/timeline", "Continual-learning timeline with provenance"),
    ("/api/learning/prototypes", "Registered novelty prototypes"),
    ("/api/learning/queue", "Adaptation queue"),
    ("/api/sample-details", "Stored result and attribution for one file (?sha256=)"),
]


def create_app(api_token: str, allowed_hosts: set) -> FastAPI:
    app = FastAPI(title="ThreatWeaver API", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")
    core = ApiCore()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        verdict = security.guard_request(request.method, request.url.path, request.headers, api_token, allowed_hosts)
        if verdict is not None:
            status, reason = verdict
            return JSONResponse({"error": reason}, status_code=status, headers={"Cache-Control": "no-store"})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def respond(result: Tuple[int, Any]) -> JSONResponse:
        status, payload = result
        return JSONResponse(payload, status_code=status)

    @app.get("/", include_in_schema=False)
    def index() -> HTMLResponse:
        from threatweaver.app.ui_html import get_apple_minimalist_html
        html = get_apple_minimalist_html().replace("__TW_API_TOKEN__", api_token, 1)
        return HTMLResponse(html, headers={"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
                                           "Referrer-Policy": "no-referrer"})

    for path, summary in GET_PATHS:
        def make(p=path):
            def endpoint(request: Request):
                return respond(core.call("GET", p, request.url.query))
            return endpoint
        app.add_api_route(path, make(), methods=["GET"], summary=summary)

    def post(path: str, model, summary: str):
        def endpoint(req: model):  # type: ignore[valid-type]
            return respond(core.call("POST", path, body=req.model_dump(exclude_unset=True)))
        app.add_api_route(path, endpoint, methods=["POST"], summary=summary)

    post("/api/scan", ScanRequest, "Start a scan")
    post("/api/quarantine", QuarantineRequest, "Quarantine a file")
    post("/api/restore", RestoreRequest, "Restore a quarantined file")
    post("/api/learning/prototype", PrototypeRequest, "Register a similarity prototype")
    post("/api/learning/queue", QueueRequest, "Queue a file for gated adaptation")
    post("/api/learning/adapt", AdaptRequest, "Run continual adaptation")
    post("/api/settings", SettingsRequest, "Change detection settings")

    @app.post("/api/scan/cancel", summary="Cancel the running scan")
    def cancel():
        return respond(core.call("POST", "/api/scan/cancel"))

    @app.post("/api/learning/queue/clear", summary="Clear the adaptation queue")
    def clear_queue():
        return respond(core.call("POST", "/api/learning/queue/clear"))

    @app.delete("/api/learning/queue", summary="Remove one queue item (?id=) or clear the queue")
    def delete_queue(request: Request):
        return respond(core.call("DELETE", "/api/learning/queue", request.url.query))

    return app
