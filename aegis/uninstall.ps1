<#
  uninstall.ps1 - turns Aegis off. Asks for administrator rights once (one UAC prompt).

  Puts your previous DNS settings back first, adapter by adapter (also for adapters that are unplugged
  right now), and only once every adapter is known not to point at Aegis removes the two scheduled tasks
  and stops the engine. If anything is uncertain the engine is left running, so lookups keep working.
  Then closes the tray icon and removes its logon entry and the desktop shortcut. The folder stays
  (settings, your lists, logs): install.cmd turns Aegis back on.
#>
param(
    [switch]$Elevated,
    [string]$ResultFile,
    [string]$RequesterSid
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'aegis-setup.ps1')
Assert-AegisRequester $RequesterSid

function Uninstall-System {
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    Start-Transcript -Path (Join-Path $StateDir 'uninstall-log.txt') -Force | Out-Null
    $messages = New-Object System.Collections.Generic.List[string]
    $ok = $false
    $lock = Enter-SetupLock
    try {
        if (-not $lock) { throw 'another Aegis install or uninstall is running; try again once it has finished' }

        # 1. DNS back to what it was (from state\install.json or its .bak copy)
        $problems = @()
        $backup = Read-Backup
        if ($backup) { $problems = Restore-Dns $backup.adapters }
        else { $messages.Add('No usable backup of your old DNS settings, so adapters pointing at Aegis go back to automatic.') }
        # anything still pointing at this PC goes back to automatic (wired and Wi-Fi adapters only)
        foreach ($a in Get-FilterAdapters) {
            try { if (Test-PointsAtAegis $a) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses } }
            catch { $problems += ('{0}: {1}' -f $a.Name, $_.Exception.Message) }
        }
        try { Clear-DnsClientCache } catch { }

        # 2. only when it's certain that nothing uses Aegis any more: the tasks and the engine
        $still = Get-AdaptersOnAegis
        if ($null -eq $still) { throw "Couldn't read the adapters' DNS settings, so the engine was left running to keep lookups working. Try again in a minute." }
        if ($still.Count -gt 0) {
            throw ('DNS still points at Aegis on ' + (($still | ForEach-Object { $_.Name }) -join ', ') + ' (' + ($problems -join '; ') +
                '). The engine was left running so lookups keep working. Set DNS to automatic in Settings, then run uninstall.cmd again.')
        }
        if ($problems.Count) {
            throw ('Some adapters could not be put back: ' + ($problems -join '; ') +
                '. The engine was left running so an adapter that comes back still gets answers. Fix that adapter''s DNS in Settings, then run uninstall.cmd again.')
        }
        $messages.Add('DNS settings put back.')
        $left = Remove-AegisTasks
        if ($left.Count) { throw ('DNS is back to normal, but these could not be removed: ' + ($left -join '; ') + '. Run uninstall.cmd again.') }
        $messages.Add('Removed the Aegis tasks and stopped the engine.')
        Retire-Backup

        # 3. lookups work without Aegis?
        Start-Sleep -Seconds 2
        $web = $null
        try { $web = (Resolve-DnsName -Name 'www.microsoft.com' -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress } catch { }
        if ($web) { $messages.Add("Lookups work without Aegis (www.microsoft.com -> $web).") }
        else { $messages.Add('Warning: www.microsoft.com did not resolve right away; give the network a few seconds.') }
        $ok = $true
    }
    catch { $messages.Add('Uninstall stopped: ' + $_.Exception.Message) }
    finally {
        Exit-SetupLock $lock
        $messages | ForEach-Object { Write-Host $_ }
        if ($ResultFile) { [ordered]@{ ok = $ok; messages = $messages.ToArray() } | ConvertTo-Json | Set-Content -Path $ResultFile -Encoding UTF8 }
        Stop-Transcript | Out-Null
    }
    return $ok
}

function Uninstall-UserParts {
    try { if (Test-Path $Tray) { Start-Process -FilePath $Tray -ArgumentList '--exit' -Wait } } catch { }
    Start-Sleep -Seconds 1
    Get-AegisProcess 'Aegis' | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $RunKey -Name 'Aegis' -ErrorAction SilentlyContinue
    Remove-Item $Shortcut -ErrorAction SilentlyContinue
    Write-Host 'Tray icon closed; it no longer starts at logon. Desktop shortcut removed.'
    Write-Host "Aegis is off. Its folder ($PSScriptRoot) is untouched: install.cmd turns it back on."
}

if (-not (Test-Admin)) {
    if (Test-BundledAegis) { exit (Invoke-BundledAegisElevation $PSCommandPath) }
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $result = Join-Path $StateDir ('uninstall-result-{0}.json' -f [guid]::NewGuid().ToString('N'))
    Write-Host 'Turning Aegis off needs administrator rights once (to put your DNS settings back)...'
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated -ResultFile "{1}"' -f $PSCommandPath, $result
    try { Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList $argList -Wait | Out-Null }
    catch { Write-Host 'Cancelled at the UAC prompt; nothing was changed.'; exit 1 }
    if (-not (Test-Path $result)) { Write-Host 'The admin step ended without a result; see state\uninstall-log.txt.'; exit 1 }
    $r = Get-Content $result -Raw | ConvertFrom-Json
    Remove-Item $result -ErrorAction SilentlyContinue
    @($r.messages) | ForEach-Object { Write-Host $_ }
    if (-not $r.ok) { exit 1 }
    Uninstall-UserParts
    exit 0
}

$ok = [bool](Uninstall-System | Select-Object -Last 1)
if ($ok -and -not $Elevated) { Uninstall-UserParts }
if (-not $ok) { exit 1 }
