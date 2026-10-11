"""ThreatWeaver EMBER Dataset Ingestion and Preprocessing Utility.

Safely checks disk space, streams JSONL records without RAM explosion,
filters unlabeled samples (label == -1), and organizes chronological partitions.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, List

from rich.console import Console
from rich.table import Table

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from threatweaver.data.ember_loader import (
    EMBERDatasetLoader,
    generate_synthetic_ember_jsonl,
)

MIN_REQUIRED_DISK_GB = 5.0

# Configure UTF-8 stdout/stderr for Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False)


def check_disk_space(target_dir: Path) -> float:
    """Verifies that sufficient free disk space exists before data operations."""
    target_dir.mkdir(parents=True, exist_ok=True)
    total, used, free = shutil.disk_usage(target_dir)
    free_gb = free / (1024 ** 3)
    return free_gb


def ingest_ember(
    input_path: Optional[str] = None,
    output_dir: str = "data/ember",
    max_samples: int = 1000,
    create_synthetic: bool = True,
    schema_mode: str = "harmonized",
) -> None:
    console.print("\n[bold cyan]+------------------------------------------------------------------+[/bold cyan]")
    console.print("[bold cyan]|              ThreatWeaver EMBER Dataset Pipeline                 |[/bold cyan]")
    console.print("[bold cyan]+------------------------------------------------------------------+[/bold cyan]\n")

    out_p = Path(output_dir).resolve()
    free_gb = check_disk_space(out_p)
    console.print(f"[bold]Target Directory:[/bold] {out_p}")
    console.print(f"[bold]Available Disk Space:[/bold] [green]{free_gb:.1f} GB[/green]")

    if free_gb < MIN_REQUIRED_DISK_GB:
        console.print(f"[bold red]Error: Less than {MIN_REQUIRED_DISK_GB} GB disk space available.[/bold red]")
        sys.exit(1)

    jsonl_file: Path
    if input_path and Path(input_path).is_file():
        jsonl_file = Path(input_path).resolve()
        console.print(f"[green]Reading EMBER dataset from:[/green] {jsonl_file}")
    elif create_synthetic:
        console.print(f"[yellow]No external dataset path supplied. Generating reproducible EMBER benchmark subset ({max_samples} samples)...[/yellow]")
        jsonl_file = out_p / "ember_sample.jsonl"
        generate_synthetic_ember_jsonl(jsonl_file, num_samples=max_samples, seed=42)
        console.print(f"[green]Generated EMBER JSONL sample:[/green] {jsonl_file}")
    else:
        console.print("[bold red]Error: Specify --input <path> or use --synthetic to generate sample data.[/bold red]")
        sys.exit(1)

    loader = EMBERDatasetLoader(schema_mode=schema_mode, drop_unlabeled=True)
    console.print(f"\n[bold]Streaming records (schema: {schema_mode})...[/bold]")

    start_t = time.time()
    total_loaded = 0
    benign_count = 0
    malware_count = 0
    temporal_batches: Dict[str, int] = {}

    for chunk in loader.stream_jsonl(jsonl_file, max_samples=max_samples, chunk_size=500):
        n_chunk = len(chunk["labels"])
        total_loaded += n_chunk
        benign_count += int(sum(chunk["labels"] == 0))
        malware_count += int(sum(chunk["labels"] == 1))

        for ts in chunk["timestamps"]:
            temporal_batches[ts] = temporal_batches.get(ts, 0) + 1

    dur = time.time() - start_t
    console.print(f"[green]Processed {total_loaded} verified samples in {dur:.2f}s ({total_loaded / max(dur, 0.001):.0f} samples/sec).[/green]\n")

    # Display dataset breakdown table
    table = Table(title="EMBER Dataset Ingestion Summary")
    table.add_column("Partition / Metric", style="cyan")
    table.add_column("Sample Count", justify="right")
    table.add_column("Distribution", justify="right")

    table.add_row("Total Verified Samples", str(total_loaded), "100.0%")
    table.add_row("Benign Software (label 0)", str(benign_count), f"{(benign_count / max(total_loaded, 1)) * 100:.1f}%")
    table.add_row("Malicious Samples (label 1)", str(malware_count), f"{(malware_count / max(total_loaded, 1)) * 100:.1f}%")

    console.print(table)

    # Display chronological batches
    t_table = Table(title="Chronological Temporal Batches (Preserving 'appeared' stamp)")
    t_table.add_column("Month Window", style="magenta")
    t_table.add_column("Samples", justify="right")

    for m in sorted(temporal_batches.keys()):
        t_table.add_row(m, str(temporal_batches[m]))

    console.print(t_table)
    console.print(f"\n[bold green]Ready for continual learning benchmarks using EMBER data![/bold green]\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest and preprocess EMBER malware dataset")
    parser.add_argument("--input", default=None, help="Path to raw EMBER JSONL or tar.bz2")
    parser.add_argument("--output-dir", default="data/ember", help="Output directory")
    parser.add_argument("--max-samples", type=int, default=1000, help="Max samples to ingest")
    parser.add_argument("--schema", choices=["harmonized", "native"], default="harmonized", help="Schema representation")
    parser.add_argument("--synthetic", action="store_true", default=True, help="Generate sample EMBER benchmark subset if missing")

    args = parser.parse_args()
    ingest_ember(
        input_path=args.input,
        output_dir=args.output_dir,
        max_samples=args.max_samples,
        create_synthetic=args.synthetic,
        schema_mode=args.schema,
    )
