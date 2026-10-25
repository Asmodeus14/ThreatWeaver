"""ThreatWeaver Native Windows Desktop Application Launcher."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Optional

from threatweaver.app.server import create_server


def launch_desktop(
    host: str = "127.0.0.1",
    port: int = 8765,
    checkpoint_path: Optional[str | Path] = None,
) -> None:
    """Launches ThreatWeaver in a dedicated native Windows Desktop application window."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    try:
        os.chdir(repo_root)
    except Exception:
        pass

    server, url = create_server(host=host, port=port, checkpoint_path=checkpoint_path)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Wait for server to become responsive
    ready = False
    for _ in range(40):
        try:
            with urllib.request.urlopen(f"{url}/api/browse-paths", timeout=0.5) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.1)

    window_title = "ThreatWeaver — Static PE Security Platform"

    # 1. Primary Native Windows Window via pywebview (Edge WebView2)
    webview_launched = False
    try:
        import webview
        window = webview.create_window(
            title=window_title,
            url=url,
            width=1340,
            height=880,
            min_size=(1060, 720),
            background_color="#ffffff",
        )
        webview_launched = True
        webview.start()
    except Exception as e:
        print(f"pywebview window could not be opened ({e}), using desktop app fallback...")

    # 2. Secondary Native Window: Microsoft Edge Chromium App Mode
    if not webview_launched:
        edge_candidates = [
            Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/Application/msedge.exe",
        ]
        edge_bin = next((p for p in edge_candidates if p.is_file()), None)
        if edge_bin:
            proc = subprocess.Popen([str(edge_bin), f"--app={url}", "--new-window"])
            try:
                proc.wait()
            except KeyboardInterrupt:
                pass
        else:
            # 3. Tertiary: Default System Web Browser
            webbrowser.open(url)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


if __name__ == "__main__":
    launch_desktop()
