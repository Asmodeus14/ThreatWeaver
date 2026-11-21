"""Tests for ThreatWeaver Apple UI server and REST endpoints."""

import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

from threatweaver.app import security
from threatweaver.app.server import ThreatWeaverRequestHandler, ScanStateManager
from threatweaver.scanner.inference import InferenceEngine
from threatweaver.quarantine.manager import QuarantineManager

TEST_TOKEN = "test-session-token"


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
    ThreatWeaverRequestHandler.api_token = TEST_TOKEN
    ThreatWeaverRequestHandler.allowed_host_set = security.allowed_hosts("127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Legitimate client: every request carries the session token.
    opener = urllib.request.build_opener()
    opener.addheaders = [(security.TOKEN_HEADER, TEST_TOKEN)]
    urllib.request.install_opener(opener)

    yield f"http://127.0.0.1:{port}"

    urllib.request.install_opener(urllib.request.build_opener())
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


FABRICATED_MARKERS = ("Emotet", "LockBit", "AgentTesla", "a4c281093f61b0c9", "svchost.exe")


def _get(url: str):
    with urllib.request.urlopen(url) as resp:
        assert resp.status == 200
        return json.loads(resp.read().decode("utf-8"))


def test_server_threat_network_api(test_server: str):
    """Graph contains only real prototypes/scan results; no invented families or default nodes."""
    data = _get(f"{test_server}/api/threat-network")
    for key in ("nodes", "edges", "fs_items", "fs_edges", "available"):
        assert key in data
    assert all(n["type"] in ("prototype", "sample") for n in data["nodes"])
    assert not any(e.get("type") == "inter_family" for e in data["edges"])
    if not data["available"]:
        assert data["fs_items"] == [] and data["reason"]
    raw = json.dumps(data)
    assert not any(m in raw for m in FABRICATED_MARKERS)


def test_server_families_api(test_server: str):
    """Families come from the dataset metadata summary, or are explicitly unavailable."""
    data = _get(f"{test_server}/api/families")
    assert "families" in data and "available" in data
    raw = json.dumps(data)
    assert "dominant_apis" not in raw and "Emotet" not in raw
    if data["available"]:
        assert data["kind"] == "dataset_metadata"
        for fam in data["families"]:
            assert fam["sample_count"] > 0
            assert 0.0 <= fam["mean_family_confidence"] <= 1.0
    else:
        assert data["families"] == [] and data["reason"]


def test_server_timeline_api(test_server: str):
    """Timeline carries provenance; synthetic results are labelled as synthetic."""
    data = _get(f"{test_server}/api/timeline")
    assert "available" in data
    if data["available"]:
        assert data["kind"] in ("benchmark", "synthetic")
        assert "strategies" in data and "source" in data
        assert not any(str(b.get("window_start", "")).startswith("2026") for b in data.get("batches", []))


def test_server_sample_details_api(test_server: str):
    """Unknown identifiers return an explicit 'unavailable' answer instead of invented attribution."""
    data = _get(f"{test_server}/api/sample-details?id=fam-emotet")
    assert data["available"] is False
    assert "nearest_neighbors" not in data
    assert "feature_attribution" not in data or data["feature_attribution"] is None


def test_server_status_reports_real_model_and_dataset(test_server: str):
    data = _get(f"{test_server}/api/status")
    assert "dataset" in data and "available" in data["dataset"]
    assert "residual_blocks" in data and "model_kind" in data


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
    ThreatWeaverRequestHandler.api_token = TEST_TOKEN
    ThreatWeaverRequestHandler.allowed_host_set = security.allowed_hosts("127.0.0.1", port)

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        payload = json.dumps({"scan_mode": "full_system"}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json", security.TOKEN_HEADER: TEST_TOKEN},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "started"
            assert data["is_full_system"] is True
            state_mgr.cancel_scan()
    finally:
        httpd.shutdown()
        httpd.server_close()
