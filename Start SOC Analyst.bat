@echo off
rem Opens the SOC Analyst in 12 Weeks site in its own app window.
setlocal
set "PAGE=%~dp0index.html"
if not exist "%PAGE%" (
  echo index.html was not found next to this file.
  pause
  exit /b 1
)
echo Syncing with TryHackMe...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync-thm.ps1"
rem Keep syncing in the background (hidden, every 2 minutes, stops after 12 hours).
start "" /min powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0sync-thm.ps1" -Loop
set "URL=file:///%PAGE:\=/%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" >nul 2>&1
if %errorlevel%==0 (
  start "" msedge --app="%URL%"
  exit /b 0
)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" >nul 2>&1
if %errorlevel%==0 (
  start "" chrome --app="%URL%"
  exit /b 0
)
start "" "%PAGE%"
