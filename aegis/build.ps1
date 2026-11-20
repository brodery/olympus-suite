<#
  build.ps1 - compiles Aegis with the C# compiler that ships with Windows (.NET Framework 4.8), tests it,
  and puts it in place, even while Aegis is running. No admin rights needed.

    Aegis.exe        tray icon, window and command line
    AegisEngine.exe  the background DNS filter
    aegis.ico        the shield icon (drawn by Aegis.exe itself)
    build\           the fresh builds, and AegisTests.exe (unit tests, run unless -NoTests)

  Putting it in place (skipped with -NoDeploy):
    - The tray icon, if it's running, is closed and started again from the new Aegis.exe.
    - A running program's file can't be overwritten, but it can be renamed: it's set aside as
      <name>.<time>.old.exe (deleted when the next engine starts) and the new file goes in.
    - The engine is then asked to exit (restart.aegis.invalid) and its scheduled task started again,
      so the new engine takes over in about a second. An engine older than 1.0.1 doesn't know that
      command; if its task can't be stopped without admin rights either, the new engine takes over
      at the next restart of the PC, or run install.cmd to switch now.
#>
param([switch]$NoTests, [switch]$NoDeploy)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'aegis-setup.ps1')         # $Engine, $Tray, $TaskName, Get-AegisProcess, Test-Admin
. (Join-Path $here 'release-signing.ps1')
$signingPin = Get-OlympusBuildSigningPin
if ($signingPin) { $buildSigner = Get-OlympusBuildSigner $signingPin }
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "C# compiler not found at $csc" }
$src = Join-Path $here 'src'
$build = Join-Path $here 'build'
New-Item -ItemType Directory -Force $build | Out-Null

$common = Join-Path $src 'Common.cs'
$engineSrc = Join-Path $src 'Engine.cs'
$traySrc = Join-Path $src 'Tray.cs'
$program = Join-Path $src 'Program.cs'
$tests = Join-Path $src 'Tests.cs'
$icon = Join-Path $here 'aegis.ico'
$refs = @('/r:System.dll', '/r:System.Core.dll', '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll')

function Invoke-Csc([string[]]$CscArgs) {
    $all = @('/nologo', '/langversion:5', '/optimize+', '/platform:anycpu', '/warn:4') + $refs + $CscArgs
    $out = & $csc @all
    $code = $LASTEXITCODE
    $out | Where-Object { $_ -and $_ -notmatch 'only supports language versions up to C# 5|For more information|go.microsoft.com' } | ForEach-Object { "  $_" }
    if ($code -ne 0) { throw "csc failed ($code)" }
}

Write-Host 'Building the icon...'
$plain = Join-Path $build 'Aegis-noicon.exe'
Invoke-Csc @('/target:winexe', "/out:$plain", $common, $traySrc, $program)
$p = Start-Process -FilePath $plain -ArgumentList @('--make-icon', "`"$icon`"") -Wait -PassThru
if ($p.ExitCode -ne 0 -or -not (Test-Path $icon)) { throw 'drawing the icon failed' }

Write-Host 'Building Aegis.exe and AegisEngine.exe into build\...'
$newTray = Join-Path $build 'Aegis.exe'
$newEngine = Join-Path $build 'AegisEngine.exe'
Invoke-Csc @('/target:winexe', "/out:$newTray", "/win32icon:$icon", $common, $traySrc, $program)
Invoke-Csc @('/target:winexe', '/define:ENGINE', "/out:$newEngine", "/win32icon:$icon", $common, $engineSrc, $program)
Invoke-Csc @('/target:exe', '/define:TESTS', "/out:$(Join-Path $build 'AegisTests.exe')", $common, $engineSrc, $tests, $program)
Remove-Item $plain -ErrorAction SilentlyContinue

if (-not $NoTests) {
    Write-Host 'Running unit tests...'
    & (Join-Path $build 'AegisTests.exe')
    if ($LASTEXITCODE -ne 0) { throw 'unit tests failed: nothing was put in place' }
}
if ($signingPin) {
    Write-Host 'Signing the Aegis release executables...'
    Set-OlympusArtifactSignature $newTray $buildSigner $signingPin
    Set-OlympusArtifactSignature $newEngine $buildSigner $signingPin
}
if ($NoDeploy) { Write-Host 'Built and tested; nothing put in place (-NoDeploy).'; return }

# ------------------------------------------------------------------ putting it in place

$version = (Get-Item $newEngine).VersionInfo.ProductVersion

function Get-EngineStatus {
    try {
        $r = Resolve-DnsName -Name 'status.aegis.invalid' -Type TXT -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop
        $txt = (@($r | ForEach-Object { $_.Strings }) -join '')
        if ($txt -match 'app=Aegis') { return $txt }
    } catch { }
    return $null
}

function Get-StatusField([string]$Status, [string]$Name) {
    if ($Status -match "(?:^|;)$Name=([^;]*)") { return $Matches[1] }
    return $null
}

# Copies a new build over the old file. A running program's file can't be overwritten but can be renamed,
# so then the old file is set aside first. Returns $true if it was set aside.
function Install-Build([string]$From, [string]$To) {
    try { Copy-Item -LiteralPath $From -Destination $To -Force; return $false }
    catch { if (-not (Test-Path -LiteralPath $To)) { throw } }
    $asideName = '{0}.{1}.old.exe' -f [IO.Path]::GetFileNameWithoutExtension($To), (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
    Rename-Item -LiteralPath $To -NewName $asideName
    try { Copy-Item -LiteralPath $From -Destination $To }
    catch { Rename-Item -LiteralPath (Join-Path (Split-Path -Parent $To) $asideName) -NewName (Split-Path -Leaf $To); throw }
    return $true
}

# The tray icon goes through WMI so it doesn't belong to this console window (closing it won't close the tray).
function Start-TrayDetached {
    if (Test-Admin) { Start-TrayUnelevated; return }       # never start the tray elevated
    try {
        $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = ('"{0}" --tray' -f $Tray); CurrentDirectory = $here } -ErrorAction Stop
        if ($r.ReturnValue -eq 0) { return }
    } catch { }
    Start-Process -FilePath $Tray -ArgumentList '--tray' -WorkingDirectory $here
}

# copies set aside by an earlier update, once nothing runs from them any more
foreach ($old in @(Get-ChildItem -LiteralPath $here -Filter '*.old.exe' -File -ErrorAction SilentlyContinue)) {
    try { Remove-Item -LiteralPath $old.FullName -Force -ErrorAction Stop } catch { }
}

# 1. the tray icon: closed now, started again at the end
$trays = Get-AegisProcess 'Aegis'
if ($trays.Count -gt 0) {
    Write-Host 'Closing the tray icon...'
    try { Start-Process -FilePath $newTray -ArgumentList '--exit' -Wait } catch { }
    Wait-Process -Id ($trays | ForEach-Object { $_.Id }) -Timeout 10 -ErrorAction SilentlyContinue
}
if (Install-Build $newTray $Tray) { Write-Host '  Aegis.exe was in use: the old copy was set aside.' }
Write-Host "Aegis.exe $version in place."

# 2. the engine
$status = Get-EngineStatus
$aside = Install-Build $newEngine $Engine
Write-Host ("AegisEngine.exe {0} in place{1}." -f $version, $(if ($aside) { ' (the running copy was set aside)' } else { '' }))
if ($status) {
    $oldPid = Get-StatusField $status 'pid'
    $oldVer = Get-StatusField $status 'ver'
    Write-Host "Switching the running engine ($oldVer, pid $oldPid) to the new one..."
    $reply = ''
    try { $reply = (@(Resolve-DnsName -Name 'restart.aegis.invalid' -Type TXT -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop | ForEach-Object { $_.Strings }) -join '') } catch { }
    $asked = $false
    if ($reply -eq 'restarting') { $asked = $true }
    else {
        # an engine older than 1.0.1 has no restart command: try stopping its task instead
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop; $asked = $true } catch { }
    }
    $gone = $false
    if ($asked) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $gone -and $sw.Elapsed.TotalSeconds -lt 8) {
            $s = Get-EngineStatus
            $gone = (-not $s) -or ((Get-StatusField $s 'pid') -ne $oldPid)
            if (-not $gone) { Start-Sleep -Milliseconds 100 }
        }
    }
    if ($gone) {
        try { Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop } catch { }   # its every-minute trigger would start it too
        $new = $null
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $new -and $sw.Elapsed.TotalSeconds -lt 30) {
            $s = Get-EngineStatus
            if ($s -and (Get-StatusField $s 'pid') -ne $oldPid) { $new = $s } else { Start-Sleep -Milliseconds 200 }
        }
        if ($new -and (Get-StatusField $new 'ver') -eq $version) {
            Write-Host ("  Engine {0} is running (pid {1}), took over after {2:0.0} s." -f $version, (Get-StatusField $new 'pid'), $sw.Elapsed.TotalSeconds)
        }
        elseif ($new) { Write-Warning ("An engine answers, but it reports version {0}, not {1}." -f (Get-StatusField $new 'ver'), $version) }
        else { Write-Warning 'The engine has not come back yet; its task starts it within a minute (see logs\engine.log).' }
    }
    else {
        Write-Host "  The running engine ($oldVer) can't be switched without admin rights. The new one takes over at the next restart of the PC; run install.cmd to switch now."
    }
}

# 3. the tray icon again
if ($trays.Count -gt 0) {
    if ((Get-AegisProcess 'Aegis').Count -eq 0) { Start-TrayDetached; Write-Host 'Tray icon started again.' }
    else { Write-Warning 'The old tray icon is still running: right-click it, choose Exit, then start Aegis from the desktop shortcut.' }
}
Write-Host 'Done.'
