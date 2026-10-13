"""Functions the desktop window (pywebview) lets the web page call."""
import os
import re


class DesktopApi:
    def save_file(self, filename, content):
        """Show the native Save-as window and write the text file. Returns {ok, path | cancelled | error}."""
        try:
            import webview
            safe = re.sub(r'[\\/:*?"<>|]+', "_", str(filename or "")).strip() or "backup.cfg"
            kind = webview.FileDialog.SAVE if hasattr(webview, "FileDialog") else webview.SAVE_DIALOG
            path = webview.windows[0].create_file_dialog(kind, directory=os.path.expanduser("~/Downloads"), save_filename=safe)
            if not path:
                return {"ok": False, "cancelled": True}
            if isinstance(path, (list, tuple)):
                path = path[0]
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(str(content))
            return {"ok": True, "path": str(path)}
        except Exception as e:
            return {"ok": False, "error": str(e)}
