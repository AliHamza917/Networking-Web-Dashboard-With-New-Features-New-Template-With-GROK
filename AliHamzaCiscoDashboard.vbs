Set WshShell = CreateObject("WScript.Shell")

WshShell.Run "cmd /c cd /d ""C:\Users\Faisal IT\Downloads\Ali-Hamza-Cisco-Networking-Dashboard-v3\cisco-config-dashboard"" && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload", 0, False
