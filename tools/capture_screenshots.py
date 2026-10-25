import subprocess
import time
import os
from pathlib import Path

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
USER_DATA_DIR = r"C:\CODE\ThreatWeaver\.chrome_profile_ss"
OUT_DIR = Path(r"C:\CODE\ThreatWeaver\assets\screenshots")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TABS = [
    ("overview", "threatweaver_overview.png", 2),
    ("scan", "threatweaver_scan.png", 3),
    ("web", "threatweaver_threat_web.png", 3),
    ("model", "threatweaver_neural_trace.png", 3),
]

for tab, filename, delay in TABS:
    url = f"http://127.0.0.1:8765/#{tab}"
    out_file = OUT_DIR / filename
    print(f"Capturing #{tab} to {out_file}...")
    
    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        f"--user-data-dir={USER_DATA_DIR}",
        "--window-size=1400,900",
        "--hide-scrollbars",
        f"--run-all-compositor-stages-before-draw",
        f"--virtual-time-budget={delay * 1000}",
        f"--screenshot={out_file}",
        url
    ]
    res = subprocess.run(cmd, capture_output=True, timeout=25)
    if out_file.exists() and out_file.stat().st_size > 0:
        print(f"Successfully generated {filename} ({out_file.stat().st_size} bytes)")
    else:
        print(f"Failed to generate {filename}. stderr: {res.stderr.decode(errors='ignore')}")

print("Done taking screenshots.")
