@echo off
title Cisco Config Dashboard
cd /d "%~dp0"

echo Starting Cisco Config Dashboard (Desktop)...
echo.

python desktop_app.py
if errorlevel 1 (
    echo.
    echo If Python is not found, install Python 3.9+ from https://www.python.org
    echo Then run:  pip install -r requirements.txt pywebview
    pause
)
