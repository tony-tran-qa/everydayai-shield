@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

echo ============================================================
echo  EverydayAI-Shield - AI Tool Security Monitor
echo  Setup Script
echo ============================================================
echo.

:: Check Python
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo [ERROR] Python not found in PATH.
    echo         Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

FOR /F "tokens=2" %%V IN ('python --version 2^>^&1') DO SET PYVER=%%V
echo [OK] Python %PYVER% found

:: Install optional deps
echo.
echo [1/3] Installing optional dependencies (tray icon + service support)...
pip install pystray Pillow pywin32 --quiet
IF ERRORLEVEL 1 (
    echo [WARN] Some optional packages failed - tray icon may be disabled
) ELSE (
    echo [OK] Dependencies installed
)

:: Create logs dir
echo.
echo [2/3] Creating directories...
IF NOT EXIST logs mkdir logs
echo [OK] logs\ ready

:: Create desktop shortcut
echo.
echo [3/3] Creating shortcuts...
SET SCRIPT_DIR=%~dp0
SET TARGET="%SCRIPT_DIR%everydayai-shield.py"
SET SHORTCUT="%USERPROFILE%\Desktop\EverydayAI-Shield.lnk"

powershell -NoProfile -Command ^
    "$ws = New-Object -ComObject WScript.Shell;" ^
    "$s = $ws.CreateShortcut('%SHORTCUT%');" ^
    "$s.TargetPath = 'pythonw.exe';" ^
    "$s.Arguments = '%SCRIPT_DIR%everydayai-shield.py';" ^
    "$s.WorkingDirectory = '%SCRIPT_DIR%';" ^
    "$s.IconLocation = 'shell32.dll,167';" ^
    "$s.Description = 'EverydayAI-Shield - AI Tool Security Monitor';" ^
    "$s.Save()"

IF EXIST %SHORTCUT% (
    echo [OK] Desktop shortcut created
) ELSE (
    echo [WARN] Shortcut creation failed - run everydayai-shield.py manually
)

echo.
echo ============================================================
echo  Setup complete!
echo.
echo  To launch the dashboard:   python everydayai-shield.py
echo  To run as service:         python everydayai-shield_service.py install
echo                             python everydayai-shield_service.py start
echo  To run headless (CLI):     python everydayai-shield_service.py
echo ============================================================
echo.
pause
