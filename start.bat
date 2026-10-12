@echo off
setlocal EnableDelayedExpansion

title ExfilTrace Security Monitor

echo.
echo  ======================================================
echo   ExfilTrace Security Monitor — Application Launcher
echo  ======================================================
echo.

:: ─── 1. Prerequisite checks ──────────────────────────────────────────────────

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not on PATH.
    echo         Download Python 3.10 or later from https://www.python.org/downloads/
    echo         Make sure to tick "Add Python to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo [OK] Found %PYTHON_VER%

node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not on PATH.
    echo         Download Node.js 18 LTS or later from https://nodejs.org/
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('node --version 2^>^&1') do set NODE_VER=%%v
echo [OK] Found Node.js %NODE_VER%

npm --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm is not available. Please reinstall Node.js.
    pause
    exit /b 1
)

:: ─── 2. Backend — Python virtual environment ─────────────────────────────────

echo.
echo [*] Setting up Python backend...

set VENV_DIR=.venv

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [*] Creating Python virtual environment in .venv\...
    python -m venv %VENV_DIR%
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

:: Activate and install dependencies only when needed
set PIP=%VENV_DIR%\Scripts\pip.exe
set PYTHON_VENV=%VENV_DIR%\Scripts\python.exe

:: Use a sentinel file to skip reinstall if requirements haven't changed
set SENTINEL=%VENV_DIR%\.deps_installed

if not exist "%SENTINEL%" (
    echo [*] Installing backend dependencies...
    %PIP% install -q -r backend\requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install backend dependencies.
        echo         Check backend\requirements.txt and your network connection.
        pause
        exit /b 1
    )
    echo installed > "%SENTINEL%"
    echo [OK] Backend dependencies installed.
) else (
    :: Check if requirements.txt is newer than the sentinel
    for %%f in (backend\requirements.txt) do set REQ_DATE=%%~tf
    for %%f in ("%SENTINEL%") do set SEN_DATE=%%~tf
    if "!REQ_DATE!" gtr "!SEN_DATE!" (
        echo [*] requirements.txt changed — updating dependencies...
        %PIP% install -q -r backend\requirements.txt
        if errorlevel 1 (
            echo [ERROR] Failed to update backend dependencies.
            pause
            exit /b 1
        )
        echo installed > "%SENTINEL%"
        echo [OK] Backend dependencies updated.
    ) else (
        echo [OK] Backend dependencies up to date.
    )
)

:: ─── 3. Frontend — Node dependencies ─────────────────────────────────────────

echo.
echo [*] Setting up React frontend...

if not exist "node_modules\.package-lock.json" (
    echo [*] Installing frontend dependencies (this may take a moment)...
    npm ci --silent
    if errorlevel 1 (
        echo [ERROR] npm ci failed. Trying npm install...
        npm install --silent
        if errorlevel 1 (
            echo [ERROR] Failed to install frontend dependencies.
            echo         Check package.json and your network connection.
            pause
            exit /b 1
        )
    )
    echo [OK] Frontend dependencies installed.
) else (
    echo [OK] Frontend dependencies already installed.
)

:: ─── 4. Port availability check ──────────────────────────────────────────────

echo.
echo [*] Checking port availability...

netstat -ano 2>nul | findstr ":5000 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARNING] Port 5000 is already in use.
    echo          The backend may fail to start. Stop the existing process or change
    echo          the port in backend\config.json (api.port) and set VITE_API_URL.
)

netstat -ano 2>nul | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [WARNING] Port 5173 is already in use.
    echo          The frontend may start on a different port (Vite auto-selects).
)

:: ─── 5. Start the backend ─────────────────────────────────────────────────────

echo.
echo [*] Starting Python backend on http://127.0.0.1:5000/api ...
start "ExfilTrace Backend" /min cmd /c "%PYTHON_VENV% backend\run.py 2>&1 | more"

:: Give the backend a moment to initialise before starting the frontend
timeout /t 3 /nobreak >nul

:: Quick connectivity check
%PYTHON_VENV% -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/status', timeout=3)" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Backend did not respond in time. Check the "ExfilTrace Backend" window.
    echo          The frontend will still start; it falls back to mock data automatically.
) else (
    echo [OK] Backend is live at http://127.0.0.1:5000/api
)

:: ─── 6. Start the frontend ────────────────────────────────────────────────────

echo.
echo [*] Starting React frontend...
start "ExfilTrace Frontend" /min cmd /c "npm run dev"

:: Brief wait then open browser
timeout /t 3 /nobreak >nul

echo.
echo  ======================================================
echo   ExfilTrace is running!
echo.
echo   Frontend  :  http://localhost:5173
echo   Backend   :  http://127.0.0.1:5000/api
echo   API Status:  http://127.0.0.1:5000/api/status
echo.
echo   Close the "ExfilTrace Backend" and "ExfilTrace Frontend"
echo   console windows, or press Ctrl+C here to stop them.
echo  ======================================================
echo.

:: Open the browser automatically
start "" "http://localhost:5173"

:: ─── 7. Wait and keep alive ───────────────────────────────────────────────────

echo Press any key to stop both services and exit...
pause >nul

:: Kill both services cleanly by window title
echo.
echo [*] Shutting down ExfilTrace services...
taskkill /fi "WINDOWTITLE eq ExfilTrace Backend*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq ExfilTrace Frontend*" /f >nul 2>&1

echo [OK] Services stopped.
echo.
endlocal
