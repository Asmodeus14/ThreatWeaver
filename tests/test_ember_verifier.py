"""Tests for EMBER2024 dataset verifier and CLI audit integration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import pytest

from threatweaver.data.ember_verifier import audit_dataset_directory, evaluate_dataset_readiness
from threatweaver.app.cli import cmd_dataset


def test_audit_dataset_directory_nonexistent(tmp_path: Path):
    """Checks audit behavior on non-existent directory."""
    manifest = audit_dataset_directory(tmp_path / "missing", tmp_path / "manifest.json")
    assert manifest["status"] == "NOT_FOUND"
    assert manifest["verified"] is False
    assert (tmp_path / "manifest.json").is_file()


def test_audit_dataset_directory_with_records(tmp_path: Path):
    """Verifies parsing of valid JSONL records."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    # Create dummy JSONL file with 1 benign, 1 malware
    jsonl_file = data_dir / "test.jsonl"
    with open(jsonl_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({
            "sha256": "abc123def456",
            "label": 0,
            "first_submission_date": 1696000000,
            "file_type": "Win32",
        }) + "\n")
        f.write(json.dumps({
            "sha256": "fed654cba321",
            "label": 1,
            "first_submission_date": 1696086400,
            "file_type": "Win64",
        }) + "\n")

    manifest_p = tmp_path / "manifest.json"
    manifest = audit_dataset_directory(data_dir, manifest_p)

    assert manifest["verified"] is True
    assert manifest["samples"] == 2
    assert manifest["benign"] == 1
    assert manifest["malicious"] == 1
    assert manifest["corrupt_records"] == 0
    assert manifest["status"] == "VERIFIED"
    assert len(manifest["sample_hashes_preview"]) == 2


def test_evaluate_dataset_readiness():
    """Validates readiness logic for balanced vs unbalanced datasets."""
    # Unverified
    ready, msgs = evaluate_dataset_readiness({"verified": False})
    assert ready is False

    # Low count
    ready, msgs = evaluate_dataset_readiness({"verified": True, "samples": 10, "benign": 5, "malicious": 5})
    assert ready is False

    # Balanced
    ready, msgs = evaluate_dataset_readiness({
        "verified": True,
        "samples": 1000,
        "benign": 500,
        "malicious": 500,
        "time_span": ["2023-09", "2024-12"],
    })
    assert ready is True
    assert any("Balanced" in m for m in msgs)


def test_cli_cmd_dataset(tmp_path: Path):
    """Validates cmd_dataset invocation through CLI handler."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    jsonl_file = data_dir / "sample.jsonl"
    with open(jsonl_file, "w", encoding="utf-8") as f:
        for i in range(150):
            f.write(json.dumps({
                "sha256": f"hash_{i}",
                "label": i % 2,
                "first_submission_date": 1696000000 + i * 3600,
                "file_type": "Dot_Net",
            }) + "\n")

    manifest_out = tmp_path / "out_manifest.json"
    args = argparse.Namespace(
        action="verify",
        dest=str(data_dir),
        manifest=str(manifest_out),
    )

    exit_code = cmd_dataset(args)
    assert exit_code == 0
    assert manifest_out.is_file()
