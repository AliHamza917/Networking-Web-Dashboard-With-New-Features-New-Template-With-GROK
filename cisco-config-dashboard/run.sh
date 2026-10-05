#!/bin/bash
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"
export PYTHONPATH="/root/.local/lib/python3.12/site-packages:$PYTHONPATH"
echo "Starting Cisco Config Dashboard on http://0.0.0.0:8000"
echo "Open http://localhost:8000 in your browser"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
