@echo off
rem Turns Aegis off and puts your DNS settings back (one UAC prompt). See uninstall.ps1.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %*
echo.
pause
