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


def test_server_threat_network_api(test_server: str):
    """Verifies /api/threat-network GET endpoint returning nodes and similarity edges."""
    with urllib.request.urlopen(f"{test_server}/api/threat-network") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) >= 8
        # Verify family and sample node attributes
        has_family = any(n.get("type") == "family" for n in data["nodes"])
        assert has_family


def test_server_families_api(test_server: str):
    """Verifies /api/families GET endpoint returning rich malware family profiles."""
    with urllib.request.urlopen(f"{test_server}/api/families") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "families" in data
        assert len(data["families"]) >= 5
        emotet = next(f for f in data["families"] if "Emotet" in f["name"])
        assert "dominant_apis" in emotet
        assert emotet["risk"] > 0.8


def test_server_timeline_api(test_server: str):
    """Verifies /api/timeline GET endpoint returning chronological batches and strategy metrics."""
    with urllib.request.urlopen(f"{test_server}/api/timeline") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "batches" in data
        assert len(data["batches"]) == 5
        assert "strategies" in data


def test_server_sample_details_api(test_server: str):
    """Verifies /api/sample-details GET endpoint."""
    with urllib.request.urlopen(f"{test_server}/api/sample-details?id=fam-emotet") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "node" in data
        assert "feature_attribution" in data
        assert "nearest_neighbors" in data


def test_server_settings_api(test_server: str):
    """Verifies /api/settings POST endpoint."""
    payload = json.dumps({"novelty_threshold": 0.45, "max_workers": 2}).encode("utf-8")
    req = urllib.request.Request(
        f"{test_server}/api/settings",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("status") == "success"



def test_server_full_system_scan_api(tmp_path: Path):
    """Validates full system scan trigger via /api/scan."""
    import json
    import threading
    import urllib.request
    from http.server import HTTPServer
    from threatweaver.app.server import ThreatWeaverRequestHandler, ScanStateManager
    from threatweaver.scanner.inference import InferenceEngine

    engine = InferenceEngine(checkpoint_path=None)
    state_mgr = ScanStateManager(inference_engine=engine)
    ThreatWeaverRequestHandler.state_mgr = state_mgr
    ThreatWeaverRequestHandler.engine = engine

    httpd = HTTPServer(("127.0.0.1", 0), ThreatWeaverRequestHandler)
    port = httpd.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        payload = json.dumps({"scan_mode": "full_system"}).encode("utf-8")
        req = urllib.request.Request(f"{base_url}/api/scan", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "started"
            assert data["is_full_system"] is True
            state_mgr.cancel_scan()
    finally:
        httpd.shutdown()
        httpd.server_close()
