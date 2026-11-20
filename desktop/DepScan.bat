@echo off
REM Double-click launcher for DepScan Desktop (no build needed).
REM Opens the full-screen DepScan app. Requires Node.js + Java 17+.
cd /d "%~dp0"
if not exist node_modules (
  echo Installing DepScan Desktop (first run only)...
  call npm install
)
start "" /min cmd /c "npx electron ."
