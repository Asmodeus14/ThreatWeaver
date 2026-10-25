"""ThreatWeaver — Standalone Desktop Application Entrypoint."""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path
root = Path(__file__).resolve().parent
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from threatweaver.app.desktop import launch_desktop

if __name__ == "__main__":
    launch_desktop()
