"""Opt-in hash reputation: off by default, hash-only, cached, failure-tolerant (network mocked)."""

import io
import json
import urllib.parse

import pytest

from threatweaver.detectors import threat_intel as ti


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_opener(payload, calls):
    def opener(req, timeout=None):
        calls.append(req)
        return FakeResp(json.dumps(payload).encode())
    return opener


@pytest.fixture(autouse=True)
def fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATWEAVER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("THREATWEAVER_KEY_DIR", str(tmp_path / "keys"))


SHA = "a" * 64


def test_disabled_by_default_sends_nothing():
    calls = []
    r = ti.MalwareBazaarLookup(opener=make_opener({}, calls)).lookup(SHA)
    assert r.status == "disabled" and calls == []


def test_enabling_requires_a_key():
    assert ti.save_config(True)["enabled"] is False
    assert ti.save_config(True, "secret-key")["enabled"] is True


def test_only_the_hash_is_sent_and_result_cached():
    ti.save_config(True, "secret-key")
    calls = []
    lk = ti.MalwareBazaarLookup(opener=make_opener(
        {"query_status": "ok", "data": [{"signature": "AgentTesla", "tags": ["exe"], "first_seen": "2024-01-01"}]}, calls))
    r = lk.lookup(SHA)
    assert r.status == "listed" and r.signature == "AgentTesla"
    sent = urllib.parse.parse_qs(calls[0].data.decode())
    assert sent == {"query": ["get_info"], "hash": [SHA]}
    assert calls[0].get_header("Auth-key") == "secret-key"
    again = lk.lookup(SHA)
    assert again.cached and len(calls) == 1


def test_not_found_and_errors():
    ti.save_config(True, "k")
    assert ti.MalwareBazaarLookup(opener=make_opener({"query_status": "hash_not_found"}, [])).lookup("b" * 64).status == "not_listed"

    def boom(req, timeout=None):
        raise OSError("offline")
    r = ti.MalwareBazaarLookup(opener=boom).lookup("c" * 64)
    assert r.status == "error" and "offline" in r.detail


def test_invalid_hash_never_sent():
    ti.save_config(True, "k")
    calls = []
    assert ti.MalwareBazaarLookup(opener=make_opener({}, calls)).lookup("../etc/passwd").status == "error"
    assert calls == []


def test_api_key_is_not_stored_in_plaintext_config(tmp_path):
    ti.save_config(True, "super-secret")
    cfg_file = tmp_path / "home" / "config" / "threat_intel.json"
    assert "super-secret" not in cfg_file.read_text()
