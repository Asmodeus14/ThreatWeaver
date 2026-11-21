"""FastAPI app: same v1 contract and security behaviour as the stdlib server."""

import json
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from threatweaver.app import security  # noqa: E402
from threatweaver.app.api import create_app  # noqa: E402
from threatweaver.app.server import ScanStateManager, ThreatWeaverRequestHandler  # noqa: E402
from threatweaver.quarantine.manager import QuarantineManager  # noqa: E402
from threatweaver.scanner.inference import InferenceEngine  # noqa: E402

TOKEN = "fastapi-test-token"
AUTH = {security.TOKEN_HEADER: TOKEN}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    engine = InferenceEngine(enable_hash_cache=False)
    ThreatWeaverRequestHandler.state_mgr = ScanStateManager(inference_engine=engine)
    ThreatWeaverRequestHandler.engine = engine
    ThreatWeaverRequestHandler.quarantine_mgr = QuarantineManager(tmp_path_factory.mktemp("vault"))
    app = create_app(TOKEN, {"testserver"})
    with TestClient(app) as c:
        yield c


def test_requires_token_and_host(client):
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/status", headers=AUTH).status_code == 200
    assert client.get("/api/status", headers={**AUTH, "Host": "evil.example"}).status_code == 403
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403


def test_cross_site_text_plain_post_blocked(client, tmp_path):
    victim = tmp_path / "doc.exe"
    victim.write_bytes(b"MZ" + bytes(300))
    r = client.post("/api/quarantine", content=json.dumps({"file_path": str(victim)}),
                    headers={"Content-Type": "text/plain", "Origin": "https://evil.example"})
    assert r.status_code in (401, 403) and victim.exists()


def test_no_wildcard_cors_and_security_headers(client):
    r = client.get("/api/status", headers=AUTH)
    assert "access-control-allow-origin" not in r.headers
    assert r.headers["cache-control"] == "no-store"
    page = client.get("/")
    assert page.status_code == 200 and TOKEN in page.text and page.headers["x-frame-options"] == "DENY"


def test_v1_endpoints_return_same_shapes(client):
    for path in ("/api/status", "/api/families", "/api/timeline", "/api/threat-network", "/api/history",
                 "/api/quarantine", "/api/learning/prototypes", "/api/embedding-ablation"):
        r = client.get(path, headers=AUTH)
        assert r.status_code == 200, path
    assert "dataset" in client.get("/api/status", headers=AUTH).json()
    assert client.get("/api/sample-details?id=nothing", headers=AUTH).json()["available"] is False


def test_path_policy_and_validation(client):
    r = client.post("/api/quarantine", json={"file_path": "C:\\Windows\\notepad.exe:ads"}, headers=AUTH)
    assert r.status_code == 400
    r = client.post("/api/quarantine", json={}, headers=AUTH)       # missing required field
    assert r.status_code == 422
    r = client.post("/api/restore", json={"quarantine_id": "../x"}, headers=AUTH)
    assert r.status_code == 400


def test_scan_and_incremental_events(client, tmp_path):
    for i in range(2):
        (tmp_path / f"a{i}.exe").write_bytes(b"MZ" + bytes(300))
    assert client.post("/api/scan", json={"target_path": str(tmp_path)}, headers=AUTH).json()["status"] == "started"
    for _ in range(100):
        ev = client.get("/api/scan/events?since=0", headers=AUTH).json()
        if not ev["is_scanning"] and ev["results_count"] == 2:
            break
        time.sleep(0.1)
    assert ev["results_count"] == 2 and len(ev["new_results"]) == 2


def test_openapi_contract_lists_v1_paths(client):
    spec = client.get("/api/openapi.json", headers=AUTH).json()
    for p in ("/api/scan", "/api/scan/events", "/api/quarantine", "/api/restore", "/api/families", "/api/status"):
        assert p in spec["paths"], p
    assert "file_path" in spec["components"]["schemas"]["QuarantineRequest"]["properties"]


def test_eval_and_detections_endpoints(client):
    evals = client.get("/api/eval", headers=AUTH).json()["evals"]
    ids = {e["id"] for e in evals}
    assert "legacy-v0.1-128d" in ids and "lgbm-v3-dotnet" in ids
    d = client.get("/api/eval/detail?id=lgbm-v3-dotnet", headers=AUTH).json()
    assert d["schema"] == "eval/1" and "roc_curve" in d["splits"]["test"] and "Valid" in d["_signature"]
    assert client.get("/api/eval/detail?id=nope", headers=AUTH).status_code == 404
    assert "results" in client.get("/api/detections?verdict=Suspicious&q=x", headers=AUTH).json()


def test_new_ui_served_with_token_and_legacy_kept(client):
    from pathlib import Path as _P
    built = (_P(__file__).resolve().parent.parent / "src/threatweaver/app/static/v2/index.html").is_file()
    root = client.get("/")
    assert root.status_code == 200 and TOKEN in root.text
    if built:
        assert '<div id="root"></div>' in root.text
    legacy = client.get("/legacy")
    assert legacy.status_code == 200 and "apple-pill-tab" in legacy.text and TOKEN in legacy.text


def test_asset_route_blocks_traversal(client):
    for bad in ("../index.html", "..%2F..%2Fapi.py", "%2e%2e%2fapi.py"):
        assert client.get(f"/v2/assets/{bad}").status_code == 404
