"""ThreatWeaver Command-Line Interface and Scanning Console.

Provides an interactive, local-first interface for PE file scanning,
continual learning evaluation, safe quarantine management, and observational monitoring.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm
from rich.table import Table

from threatweaver import __version__
from threatweaver.quarantine.manager import (
    CriticalSystemFileError,
    QuarantineManager,
    SymlinkReparsePointError,
)
from threatweaver.reporting.report import ScanHistoryManager, ScanReport
from threatweaver.scanner.inference import InferenceEngine, ScanResult, ScanVerdict
from threatweaver.scanner.scan_service import ScanService

# Configure UTF-8 stdout/stderr for Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False)
DEFAULT_CHECKPOINT = Path("artifacts/checkpoints/threatweaver_v1.pt")


def print_banner() -> None:
    """Displays ThreatWeaver header banner."""
    banner_text = (
        f"[bold cyan]ThreatWeaver v{__version__}[/bold cyan] — "
        "[dim]AI-Powered Malware Research Engine & Antivirus Prototype[/dim]\n"
        "[dim]Defensive security platform combining static PE inspection, ResMLP embeddings, and novelty detection.[/dim]"
    )
    console.print(Panel(banner_text, border_style="cyan"))


def cmd_scan(args: argparse.Namespace) -> int:
    """Executes on-demand scan of a file or folder."""
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path does not exist: {target_path}[/bold red]")
        return 1

    ckpt_path = Path(args.checkpoint) if args.checkpoint else DEFAULT_CHECKPOINT
    if not ckpt_path.is_file():
        console.print(
            f"[yellow]Warning: Model checkpoint '{ckpt_path}' not found. "
            "Proceeding with static PE structural inspection only.[/yellow]\n"
        )
        engine = InferenceEngine(checkpoint_path=None)
    else:
        console.print(f"[green]Loading calibrated checkpoint: {ckpt_path.name}[/green]")
        engine = InferenceEngine(checkpoint_path=ckpt_path)

    service = ScanService(inference_engine=engine, max_workers=args.workers)

    console.print(f"[bold]Scanning target:[/bold] [cyan]{target_path}[/cyan]")
    console.print(f"[dim]Extension filter: {'All files' if args.all_files else 'PE files (.exe, .dll, .sys, etc.)'}[/dim]\n")

    # Progress bar and streaming results table
    results: List[ScanResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=None)

        def on_prog(cur: int, tot: int, fn: str) -> None:
            progress.update(task, completed=cur, total=tot, description=f"[cyan]Scanning: {fn[:30]}")

        def on_res(r: ScanResult) -> None:
            results.append(r)

        report = service.scan(
            target_path=target_path,
            only_pe_extensions=not args.all_files,
            on_progress=on_prog,
            on_result=on_res,
        )

    # Format Results Table
    table = Table(title=f"Scan Results — {report.summary.total_scanned} files inspected")
    table.add_column("File Name", style="cyan", justify="left")
    table.add_column("Verdict", justify="center")
    table.add_column("Risk Score", justify="right")
    table.add_column("SHA-256", style="dim", justify="left")
    table.add_column("Evidence & Anomalies", justify="left")

    for r in report.results:
        # Verdict color coding
        if r.verdict == ScanVerdict.SUSPICIOUS:
            verdict_style = "[bold red]SUSPICIOUS[/bold red]"
        elif r.verdict == ScanVerdict.UNFAMILIAR:
            verdict_style = "[bold magenta]UNFAMILIAR[/bold magenta]"
        elif r.verdict == ScanVerdict.LIKELY_BENIGN:
            verdict_style = "[bold green]Likely Benign[/bold green]"
        elif r.verdict == ScanVerdict.UNSUPPORTED:
            verdict_style = "[yellow]Unsupported[/yellow]"
        else:
            verdict_style = "[dim red]Error[/dim red]"

        prob_str = f"{r.malware_probability:.1%}" if r.malware_probability > 0 else "---"
        short_sha = r.sha256[:12] + "..." if r.sha256 else "N/A"
        evidence_text = "\n".join(r.evidence_points[:2]) if r.evidence_points else "None"

        table.add_row(r.file_name, verdict_style, prob_str, short_sha, evidence_text)

    console.print(table)

    # Print summary panel
    s = report.summary
    summary_text = (
        f"[bold]Total Files Scanned:[/bold] {s.total_scanned} in {report.duration_seconds}s\n"
        f"[green]Likely Benign:[/green] {s.likely_benign}  |  "
        f"[red]Suspicious:[/red] {s.suspicious}  |  "
        f"[magenta]Unfamiliar / OOD:[/magenta] {s.unfamiliar}  |  "
        f"[yellow]Unsupported:[/yellow] {s.unsupported}  |  "
        f"[dim]Errors:[/dim] {s.analysis_errors}"
    )
    console.print(Panel(summary_text, title="Scan Summary", border_style="cyan"))

    # Record scan history
    hist_mgr = ScanHistoryManager()
    hist_mgr.record_scan(report)

    # Export reports if requested
    if args.export_json:
        p_json = report.export_json(args.export_json)
        console.print(f"[green]Exported JSON report to: {p_json}[/green]")
    if args.export_md:
        p_md = report.export_markdown(args.export_md)
        console.print(f"[green]Exported Markdown report to: {p_md}[/green]")

    # If suspicious files exist and interactive mode is enabled, prompt user
    suspicious_files = [r for r in report.results if r.verdict == ScanVerdict.SUSPICIOUS]
    if suspicious_files and not args.no_prompt:
        console.print(f"\n[bold yellow]Found {len(suspicious_files)} suspicious file(s).[/bold yellow]")
        if Confirm.ask("Would you like to quarantine these suspicious files into the isolated vault?"):
            q_mgr = QuarantineManager()
            for sf in suspicious_files:
                try:
                    entry = q_mgr.quarantine_file(sf.file_path, reason="Automated user confirmation post-scan")
                    console.print(f"[green]Isolated '{sf.file_name}' -> ID: {entry.quarantine_id}[/green]")
                except Exception as e:
                    console.print(f"[red]Failed to quarantine '{sf.file_name}': {str(e)}[/red]")

    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Manually isolates a file with confirmation."""
    path = Path(args.path).resolve()
    if not path.is_file():
        console.print(f"[bold red]File not found: {path}[/bold red]")
        return 1

    console.print(f"[bold]Target file:[/bold] {path}")
    console.print(f"[dim]File size: {path.stat().st_size} bytes[/dim]")

    if not args.yes and not args.dry_run:
        if not Confirm.ask(f"Confirm isolating file '{path.name}' to quarantine vault?"):
            console.print("[yellow]Quarantine operation cancelled by user.[/yellow]")
            return 0

    mgr = QuarantineManager(quarantine_dir=args.vault)
    try:
        entry = mgr.quarantine_file(path, reason=args.reason, dry_run=args.dry_run)
        if args.dry_run:
            console.print(f"[cyan][DRY RUN] Validated quarantine for '{path.name}'. No changes made.[/cyan]")
        else:
            console.print(f"[bold green]Successfully quarantined '{path.name}'[/bold green]")
            console.print(f"Quarantine ID: [bold cyan]{entry.quarantine_id}[/bold cyan]")
            console.print(f"SHA-256: [dim]{entry.sha256}[/dim]")
        return 0
    except (CriticalSystemFileError, SymlinkReparsePointError) as e:
        console.print(f"[bold red]Security Policy Violation: {str(e)}[/bold red]")
        return 1
    except Exception as e:
        console.print(f"[bold red]Quarantine Error: {str(e)}[/bold red]")
        return 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Restores a quarantined file to disk with confirmation."""
    mgr = QuarantineManager(quarantine_dir=args.vault)
    qid = args.quarantine_id

    if not args.yes and not args.dry_run:
        if not Confirm.ask(f"Confirm restoring quarantined item '{qid}'?"):
            console.print("[yellow]Restoration cancelled by user.[/yellow]")
            return 0

    try:
        restored_path = mgr.restore_file(
            quarantine_id=qid,
            restore_destination=args.dest,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
        if args.dry_run:
            console.print(f"[cyan][DRY RUN] Validated restoration to '{restored_path}'. No changes made.[/cyan]")
        else:
            console.print(f"[bold green]Successfully restored file to:[/bold green] [cyan]{restored_path}[/cyan]")
        return 0
    except Exception as e:
        console.print(f"[bold red]Restoration Error: {str(e)}[/bold red]")
        return 1


def cmd_list_quarantine(args: argparse.Namespace) -> int:
    """Lists all entries in quarantine store."""
    mgr = QuarantineManager(quarantine_dir=args.vault)
    entries = mgr.list_quarantined_files()

    if not entries:
        console.print("[dim]Quarantine vault is currently empty.[/dim]")
        return 0

    table = Table(title=f"Quarantine Vault — {len(entries)} item(s)")
    table.add_column("ID", style="cyan", justify="left")
    table.add_column("Original Name", style="bold", justify="left")
    table.add_column("Status", justify="center")
    table.add_column("Quarantined At", style="dim", justify="left")
    table.add_column("SHA-256", style="dim", justify="left")

    for e in entries:
        status_str = "[dim green]Restored[/dim green]" if e.restored else "[bold red]Isolated[/bold red]"
        short_sha = e.sha256[:12] + "..."
        table.add_row(e.quarantine_id, e.original_filename, status_str, e.quarantined_at, short_sha)

    console.print(table)
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Displays previous scan history."""
    mgr = ScanHistoryManager()
    records = mgr.load_history()

    if not records:
        console.print("[dim]No scan history found.[/dim]")
        return 0

    table = Table(title=f"Scan History ({len(records)} previous session(s))")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Timestamp", style="dim")
    table.add_column("Target Path")
    table.add_column("Total", justify="right")
    table.add_column("Suspicious", style="red", justify="right")
    table.add_column("Unfamiliar", style="magenta", justify="right")

    for r in reversed(records[-10:]):  # show last 10
        s = r.get("summary", {})
        table.add_row(
            r.get("scan_id", "N/A"),
            r.get("timestamp", "N/A"),
            r.get("target_path", "N/A"),
            str(s.get("total_scanned", 0)),
            str(s.get("suspicious", 0)),
            str(s.get("unfamiliar", 0)),
        )

    console.print(table)
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    """Launches the ThreatWeaver Apple Minimalist Web UI and server."""
    from threatweaver.app.server import run_server
    console.print(f"[bold cyan]Launching ThreatWeaver Apple Minimalist UI on http://127.0.0.1:{args.port}...[/bold cyan]")
    run_server(port=args.port, checkpoint_path=args.checkpoint, open_browser=not args.no_browser)
    return 0


def main() -> None:
    """CLI entry point for ThreatWeaver."""
    print_banner()

    parser = argparse.ArgumentParser(
        prog="threatweaver",
        description="ThreatWeaver: AI-Powered Malware Research Engine & AV Prototype",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # ui subcommand
    p_ui = subparsers.add_parser("ui", help="Launch the Apple Minimalist Web UI")
    p_ui.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    p_ui.add_argument("--checkpoint", default=None, help="Model checkpoint path")
    p_ui.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")

    # scan subcommand
    p_scan = subparsers.add_parser("scan", help="Scan a file or directory for threats")
    p_scan.add_argument("path", help="Path to file or directory to scan")
    p_scan.add_argument("--checkpoint", default=None, help="Path to model checkpoint")
    p_scan.add_argument("--workers", type=int, default=4, help="Max worker threads")
    p_scan.add_argument("--all-files", action="store_true", help="Scan all files, not just PE extensions")
    p_scan.add_argument("--export-json", default=None, help="Save report to JSON file")
    p_scan.add_argument("--export-md", default=None, help="Save report to Markdown file")
    p_scan.add_argument("--no-prompt", action="store_true", help="Do not prompt for quarantine after scan")

    # quarantine subcommand
    p_quar = subparsers.add_parser("quarantine", help="Safely isolate a file to vault")
    p_quar.add_argument("path", help="Path of file to quarantine")
    p_quar.add_argument("--reason", default="Manual isolation", help="Reason for quarantine")
    p_quar.add_argument("--vault", default="quarantine_store", help="Quarantine directory")
    p_quar.add_argument("--dry-run", action="store_true", help="Perform checks without moving file")
    p_quar.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # restore subcommand
    p_rest = subparsers.add_parser("restore", help="Restore an isolated file from vault")
    p_rest.add_argument("quarantine_id", help="Quarantine record ID to restore")
    p_rest.add_argument("--dest", default=None, help="Optional alternative restore destination")
    p_rest.add_argument("--vault", default="quarantine_store", help="Quarantine directory")
    p_rest.add_argument("--overwrite", action="store_true", help="Overwrite destination if present")
    p_rest.add_argument("--dry-run", action="store_true", help="Perform checks without restoring")
    p_rest.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # list-quarantine subcommand
    p_lsq = subparsers.add_parser("list-quarantine", help="List all quarantined files")
    p_lsq.add_argument("--vault", default="quarantine_store", help="Quarantine directory")

    # history subcommand
    subparsers.add_parser("history", help="Show past scan sessions")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "ui": cmd_ui,
        "scan": cmd_scan,
        "quarantine": cmd_quarantine,
        "restore": cmd_restore,
        "list-quarantine": cmd_list_quarantine,
        "history": cmd_history,
    }

    cmd_fn = dispatch.get(args.command)
    if cmd_fn:
        sys.exit(cmd_fn(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

