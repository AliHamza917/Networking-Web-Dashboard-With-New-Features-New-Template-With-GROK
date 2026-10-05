"""
Cisco Config Dashboard – Windows Desktop Application
Opens the web UI inside a native desktop window (similar to Termius).
"""

import sys
import os
import threading
import time
import socket

# Ensure packages are found
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "packages"))
user_site = os.path.expanduser("~/.local/lib/python3.12/site-packages")
if os.path.isdir(user_site):
    sys.path.insert(0, user_site)

from app.main import app
import uvicorn
import webview


def find_free_port(start=8765):
    port = start
    while port < start + 50:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    return start


def start_server(port: int):
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )


def main():
    port = find_free_port()
    url = f"http://127.0.0.1:{port}"

    # Start FastAPI in background thread
    t = threading.Thread(target=start_server, args=(port,), daemon=True)
    t.start()

    # Wait until server is ready
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                break
        except OSError:
            time.sleep(0.15)
    else:
        print("Server failed to start")
        sys.exit(1)

    # Native desktop window
    window = webview.create_window(
        title="Ali Hamza Cisco Networking Dashboard",
        url=url,
        width=1280,
        height=820,
        min_size=(900, 600),
        background_color="#0f172a",
        text_select=True,
    )
    webview.start()


if __name__ == "__main__":
    main()
