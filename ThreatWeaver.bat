@echo off
title ThreatWeaver — Static PE Security Platform
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" "ThreatWeaver.py" %*
) else (
    python "ThreatWeaver.py" %*
)
