@echo off
title Build Cisco Config Dashboard EXE
cd /d "%~dp0"

echo ========================================
echo  Building Windows .exe
echo ========================================
echo.

pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Creating executable (this may take a few minutes)...
pyinstaller --noconfirm --onefile --windowed ^
    --name "CiscoConfigDashboard" ^
    --add-data "templates;templates" ^
    --add-data "static;static" ^
    --hidden-import=uvicorn.logging ^
    --hidden-import=uvicorn.loops ^
    --hidden-import=uvicorn.loops.auto ^
    --hidden-import=uvicorn.protocols ^
    --hidden-import=uvicorn.protocols.http ^
    --hidden-import=uvicorn.protocols.http.auto ^
    --hidden-import=uvicorn.protocols.websockets.auto ^
    --hidden-import=uvicorn.lifespan ^
    --hidden-import=uvicorn.lifespan.on ^
    --hidden-import=netmiko ^
    --hidden-import=paramiko ^
    --hidden-import=ntc_templates ^
    desktop_app.py

if errorlevel 1 (
    echo Build failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Done!
echo  Executable: dist\CiscoConfigDashboard.exe
echo ========================================
echo.
pause
