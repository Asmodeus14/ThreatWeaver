"""Tests for ThreatWeaver CLI subcommands."""

import argparse
from pathlib import Path
import pytest

from threatweaver.app.cli import (
    cmd_scan,
    cmd_quarantine,
    cmd_restore,
    cmd_list_quarantine,
    cmd_history,
)
from tests.fixtures import create_minimal_pe


def test_cli_scan_subcommand(tmp_path: Path):
    """Validates CLI scan subcommand execution and export flags."""
    sample = create_minimal_pe(tmp_path / "target.exe")
    json_rep = tmp_path / "rep.json"
    md_rep = tmp_path / "rep.md"

    args = argparse.Namespace(
        path=str(sample),
        checkpoint=None,
        workers=1,
        all_files=False,
        export_json=str(json_rep),
        export_md=str(md_rep),
        no_prompt=True,
    )

    exit_code = cmd_scan(args)
    assert exit_code == 0
    assert json_rep.is_file()
    assert md_rep.is_file()


def test_cli_quarantine_and_restore(tmp_path: Path):
    """Validates CLI quarantine and restore workflow with --yes and --vault."""
    sample = create_minimal_pe(tmp_path / "bad.exe")
    vault_dir = tmp_path / "vault"

    # Quarantine
    q_args = argparse.Namespace(
        path=str(sample),
        reason="CLI test",
        vault=str(vault_dir),
        dry_run=False,
        yes=True,
    )
    assert cmd_quarantine(q_args) == 0
    assert not sample.exists()

    # List
    list_args = argparse.Namespace(vault=str(vault_dir))
    assert cmd_list_quarantine(list_args) == 0

    # Get quarantine ID from manifest
    import json
    with open(vault_dir / "quarantine.manifest.json", "r") as f:
        manifest = json.load(f)
    qid = next(iter(manifest.keys()))

    # Restore
    r_args = argparse.Namespace(
        quarantine_id=qid,
        dest=None,
        vault=str(vault_dir),
        overwrite=False,
        dry_run=False,
        yes=True,
    )
    assert cmd_restore(r_args) == 0
    assert sample.exists()


def test_cli_history_subcommand():
    """Validates CLI history subcommand runs without error."""
    args = argparse.Namespace()
    assert cmd_history(args) == 0


def test_cli_ui_parser(monkeypatch):
    """Validates CLI ui subcommand setup."""
    from threatweaver.app.cli import cmd_ui
    called = []
    def fake_run_server(port, checkpoint_path, open_browser):
        called.append((port, open_browser))

    monkeypatch.setattr("threatweaver.app.server.run_server", fake_run_server)
    args = argparse.Namespace(port=9999, checkpoint=None, no_browser=True)
    res = cmd_ui(args)
    assert res == 0
    assert called == [(9999, False)]

