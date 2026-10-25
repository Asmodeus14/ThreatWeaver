"""ThreatWeaver Windows App Packaging and Distribution Script."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def package_app():
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    print("=" * 60)
    print("Building ThreatWeaver Windows Desktop App...")
    print("=" * 60)

    # 1. Run PyInstaller
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "ThreatWeaver.spec",
    ]
    print(f"Running command: {' '.join(cmd)}")
    res = subprocess.run(cmd, check=True)
    if res.returncode != 0:
        print(f"PyInstaller failed with code {res.returncode}")
        sys.exit(res.returncode)

    dist_dir = root / "dist" / "ThreatWeaver"
    exe_path = dist_dir / "ThreatWeaver.exe"
    if not exe_path.is_file():
        print(f"Error: Executable not found at {exe_path}")
        sys.exit(1)

    print(f"\n[SUCCESS] Executable built at: {exe_path}")

    # Copy launcher script and shortcut helper into dist directory
    shutil.copy(root / "ThreatWeaver.bat", dist_dir / "ThreatWeaver-Console.bat")
    shutil.copy(root / "ThreatWeaver.vbs", dist_dir / "ThreatWeaver-Silent.vbs")

    # Ensure quarantine_store exists
    (dist_dir / "quarantine_store").mkdir(exist_ok=True)

    # 2. Package into ZIP distribution
    zip_dest = root / "dist" / "ThreatWeaver-v0.1.0-win64.zip"
    print(f"\nCreating Portable ZIP package: {zip_dest} ...")
    with zipfile.ZipFile(zip_dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in dist_dir.rglob("*"):
            if p.is_file():
                arcname = p.relative_to(root / "dist")
                zf.write(p, arcname)

    zip_mb = zip_dest.stat().st_size / (1024 * 1024)
    print(f"[SUCCESS] Packaged distribution ZIP: {zip_dest} ({zip_mb:.1f} MB)")
    print("=" * 60)
    print("ThreatWeaver Windows App is ready for distribution!")
    print("=" * 60)


if __name__ == "__main__":
    package_app()
