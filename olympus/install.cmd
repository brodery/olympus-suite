@echo off
setlocal
set "OlympusRelease=%ProgramFiles%\Olympus Release\olympus-release.ps1"
if not exist "%OlympusRelease%" (
    echo Stage a reviewed release under "%ProgramFiles%\Olympus Release" first. See README.md.
    exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%OlympusRelease%" -Operation Install %*
