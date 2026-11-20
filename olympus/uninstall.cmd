@echo off
rem Removes Olympus (keeps your backups in A:\Ark). Windows asks once for admin rights.
rem   uninstall.cmd -KeepFirewallRules   keeps programs you blocked in Cerberus blocked
rem   uninstall.cmd -Purge               also deletes C:\ProgramData\Olympus (logs and history)
setlocal
set "OlympusRelease=%ProgramFiles%\Olympus Release\olympus-release.ps1"
if not exist "%OlympusRelease%" (
    echo Stage the reviewed Olympus uninstall scripts under "%ProgramFiles%\Olympus Release" first. See README.md.
    exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%OlympusRelease%" -Operation Uninstall %*
