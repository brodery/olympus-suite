@echo off
rem Turns Aegis on (one UAC prompt). See install.ps1 for what it does.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
echo.
pause
