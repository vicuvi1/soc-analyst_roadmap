@echo off
rem Puts a "SOC Analyst in 12 Weeks" icon on your Desktop that opens the site.
setlocal
set "DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=[Environment]::GetFolderPath('Desktop'); $s=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $d 'SOC Analyst in 12 Weeks.lnk')); $s.TargetPath=(Join-Path $env:DIR 'Start SOC Analyst.bat'); $s.WorkingDirectory=$env:DIR; $s.IconLocation=(Join-Path $env:DIR 'icon.ico'); $s.WindowStyle=7; $s.Description='SOC Analyst in 12 Weeks'; $s.Save()"
if %errorlevel%==0 (echo Shortcut created on your Desktop.) else (echo Could not create the shortcut.)
pause
