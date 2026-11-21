"""Attack-oriented tests for the local API: CSRF, DNS rebinding, token, body limits, path policy."""

import http.client
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from threatweaver.app import security
from threatweaver.app.security import PathPolicyError, validate_quarantine_id, validate_user_path
from threatweaver.app.server import ScanStateManager, ThreatWeaverRequestHandler
from threatweaver.quarantine.manager import QuarantineManager
from threatweaver.scanner.inference import InferenceEngine

TOKEN = "sec-test-token-0123456789"


@pytest.fixture(scope="module")
def server_port(tmp_path_factory):
    engine = InferenceEngine(enable_hash_cache=False)
    ThreatWeaverRequestHandler.state_mgr = ScanStateManager(inference_engine=engine)
    ThreatWeaverRequestHandler.engine = engine
    ThreatWeaverRequestHandler.quarantine_mgr = QuarantineManager(tmp_path_factory.mktemp("vault"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ThreatWeaverRequestHandler)
    port = srv.server_address[1]
    ThreatWeaverRequestHandler.api_token = TOKEN
    ThreatWeaverRequestHandler.allowed_host_set = security.allowed_hosts("127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()
    srv.server_close()


def raw(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Host": f"127.0.0.1:{port}"}
    hdrs.update(headers or {})
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp.getheaders(), data


def authed(port):
    return {security.TOKEN_HEADER: TOKEN, "Content-Type": "application/json"}


def test_api_requires_token(server_port):
    status, _, _ = raw(server_port, "GET", "/api/status")
    assert status == 401


def test_wrong_token_rejected(server_port):
    status, _, _ = raw(server_port, "GET", "/api/status", headers={security.TOKEN_HEADER: "guess"})
    assert status == 401


def test_valid_token_accepted(server_port):
    status, _, _ = raw(server_port, "GET", "/api/status", headers=authed(server_port))
    assert status == 200


def test_cross_site_simple_post_blocked(server_port, tmp_path):
    """A web page can send text/plain POSTs without a preflight; it must not be able to quarantine files."""
    victim = tmp_path / "document.exe"
    victim.write_bytes(b"MZ" + b"\x00" * 300)
    body = json.dumps({"file_path": str(victim)})
    status, _, _ = raw(server_port, "POST", "/api/quarantine", body=body,
                       headers={"Content-Type": "text/plain", "Origin": "https://evil.example"})
    assert status in (401, 403)
    assert victim.exists()


def test_foreign_origin_rejected_even_with_token(server_port):
    hdrs = authed(server_port)
    hdrs["Origin"] = "https://evil.example"
    status, _, _ = raw(server_port, "POST", "/api/scan/cancel", body="{}", headers=hdrs)
    assert status == 403


def test_dns_rebinding_host_rejected(server_port):
    """A rebinding attack arrives with the attacker's hostname in Host; even the UI page must be refused."""
    for path in ("/", "/api/status"):
        status, _, _ = raw(server_port, "GET", path, headers={"Host": "evil.example", security.TOKEN_HEADER: TOKEN})
        assert status == 403


def test_no_wildcard_cors(server_port):
    _, headers, _ = raw(server_port, "GET", "/api/status", headers=authed(server_port))
    assert not any(k.lower() == "access-control-allow-origin" for k, _ in headers)


def test_ui_page_embeds_token_and_denies_framing(server_port):
    status, headers, data = raw(server_port, "GET", "/")
    assert status == 200
    assert TOKEN.encode() in data
    hd = {k.lower(): v for k, v in headers}
    assert hd.get("x-frame-options") == "DENY"


def test_non_json_content_type_rejected(server_port):
    hdrs = authed(server_port)
    hdrs["Content-Type"] = "text/plain"
    status, _, _ = raw(server_port, "POST", "/api/settings", body='{"novelty_threshold": 9}', headers=hdrs)
    assert status == 415


def test_oversized_body_rejected(server_port):
    """The declared length is checked before any body bytes are read (no memory exhaustion)."""
    hdrs = authed(server_port)
    hdrs["Content-Length"] = str(security.MAX_BODY_BYTES + 1)
    status, _, _ = raw(server_port, "POST", "/api/settings", body="{}", headers=hdrs)
    assert status == 413


def test_malformed_json_rejected(server_port):
    status, _, _ = raw(server_port, "POST", "/api/settings", body="[1,2,3]", headers=authed(server_port))
    assert status == 400


def test_quarantine_rejects_ads_and_device_paths(server_port):
    for bad in ("C:\\Windows\\notepad.exe:hidden", "\\\\.\\PhysicalDrive0", "\\\\server\\share\\x.exe"):
        status, _, data = raw(server_port, "POST", "/api/quarantine",
                              body=json.dumps({"file_path": bad}), headers=authed(server_port))
        assert status == 400, (bad, data)


def test_restore_rejects_bad_ids(server_port):
    status, _, _ = raw(server_port, "POST", "/api/restore",
                       body=json.dumps({"quarantine_id": "../../etc"}), headers=authed(server_port))
    assert status == 400


# ---- unit tests for the policy helpers ----

def test_validate_user_path_accepts_normal_paths(tmp_path):
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ")
    assert validate_user_path(str(f)) == f.resolve()


@pytest.mark.parametrize("bad", ["", "   ", None, 5, "a\x00b", "\\\\?\\C:\\x", "\\\\.\\pipe\\x", "C:\\x.exe:stream", "\\\\host\\share"])
def test_validate_user_path_rejects(bad):
    with pytest.raises(PathPolicyError):
        validate_user_path(bad, must_exist=False)


def test_validate_quarantine_id():
    assert validate_quarantine_id("1a2b3c4d-5e6f") == "1a2b3c4d-5e6f"
    with pytest.raises(PathPolicyError):
        validate_quarantine_id("../x")


def test_allowed_hosts_and_origin():
    hosts = security.allowed_hosts("127.0.0.1", 8765)
    assert security.check_host("localhost:8765", hosts)
    assert not security.check_host("evil.example:8765", hosts)
    assert security.check_origin(None, hosts)
    assert security.check_origin("http://127.0.0.1:8765", hosts)
    assert not security.check_origin("null", hosts)
