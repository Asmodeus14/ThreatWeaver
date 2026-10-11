"""Tests for ThreatWeaver Apple UI server and REST endpoints."""

import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

from threatweaver.app.server import ThreatWeaverRequestHandler, ScanStateManager
from threatweaver.scanner.inference import InferenceEngine
from threatweaver.quarantine.manager import QuarantineManager


@pytest.fixture(scope="module")
def test_server():
    """Runs test server in a background thread on an ephemeral port."""
    engine = InferenceEngine()
    state_mgr = ScanStateManager(inference_engine=engine)
    quarantine_mgr = QuarantineManager()

    ThreatWeaverRequestHandler.state_mgr = state_mgr
    ThreatWeaverRequestHandler.engine = engine
    ThreatWeaverRequestHandler.quarantine_mgr = quarantine_mgr

    # Port 8799 for testing
    port = 8799
    server = ThreadingHTTPServer(("127.0.0.1", port), ThreatWeaverRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


def test_server_html_ui(test_server: str):
    """Verifies that root URL serves the Apple Minimalist HTML UI."""
    with urllib.request.urlopen(f"{test_server}/") as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "ThreatWeaver" in content
        assert "apple-glass" in content
        assert "apple-pill-tab" in content


def test_server_status_api(test_server: str):
    """Verifies /api/status JSON endpoint."""
    with urllib.request.urlopen(f"{test_server}/api/status") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "version" in data
        assert "quarantine_count" in data


def test_server_quarantine_api(test_server: str):
    """Verifies /api/quarantine GET endpoint."""
    with urllib.request.urlopen(f"{test_server}/api/quarantine") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "entries" in data


def test_server_history_api(test_server: str):
    """Verifies /api/history GET endpoint."""
    with urllib.request.urlopen(f"{test_server}/api/history") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "history" in data
