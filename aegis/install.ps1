<#
  install.ps1 - turns Aegis on for this PC. Asks for administrator rights once (one UAC prompt).

  What it does (uninstall.ps1 undoes all of it):
    1. Saves your current DNS settings to state\install.json (checked, with a last good copy as .bak).
    2. Runs AegisEngine.exe in the background as you: scheduled task "Aegis DNS filter", started at
       boot (before you log in) and restarted within a minute if it ever stops.
    3. Once that copy of the engine answers on 127.0.0.1 and ::1 (UDP and TCP), adds a safety switch:
       task "Aegis DNS filter safety" (SYSTEM). It starts whenever Windows logs that a lookup failed
       (DNS Client event 1014), and every 15 minutes. If Windows points at Aegis but the engine has been
       silent for 90 seconds, it sets the adapters Aegis manages back to automatic DNS.
    4. Points Ethernet and Wi-Fi at 127.0.0.1 and ::1, then checks that the adapters took it, that
       Windows' lookups reach Aegis and that normal sites resolve.
    5. Starts the tray icon now (with your normal rights) and at every logon; desktop shortcut "Aegis".

  If anything in 1-4 fails, DNS goes back to how it was and the tasks are removed again (they're only
  left in place when DNS couldn't be put back, so lookups keep working).
  -DryRun shows what it would do without changing anything.
#>
param(
    [switch]$DryRun,
    [switch]$Elevated,
    [string]$User,
    [string]$ResultFile,
    [string]$RequesterSid
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'aegis-setup.ps1')
. (Join-Path $PSScriptRoot 'release-signing.ps1')
Assert-AegisRequester $RequesterSid

function Show-Plan {
    Write-Host 'Aegis install plan (dry run: nothing is changed)'
    Write-Host ("  Engine:            {0} ({1})" -f $Engine, $(if (Test-Path $Engine) { 'present' } else { 'MISSING - run build.ps1' }))
    Write-Host ("  Runs as:           {0}, task ""{1}"": at boot, plus a check every minute that restarts it" -f $User, $TaskName)
    Write-Host '  Adapters to point at 127.0.0.1 and ::1:'
    foreach ($a in Get-FilterAdapters) {
        $s = Get-RegistryDns $a.InterfaceGuid
        $mode = if ($s.v4 -or $s.v6) { "typed in: $($s.v4) $($s.v6)".Trim() } else { 'automatic (DHCP)' }
        $now = $(try { (Get-AdapterDns $a) -join ', ' } catch { "(couldn't read: $($_.Exception.Message))" })
        Write-Host ("     {0} ({1}) {2}: now {3}  [{4}]" -f $a.Name, $a.Status, $a.InterfaceGuid, $now, $mode)
    }
    Write-Host ("  Local names go to: {0}" -f (Get-RouterDns))
    $old = Read-Backup
    Write-Host ("  Earlier backup:    {0}" -f $(if ($old) { "found ($(@($old.adapters).Count) adapters, saved $($old.installed))" } else { 'none' }))
    $tasks = @(Get-ScheduledTask -TaskName $TaskName, $SafetyName -ErrorAction SilentlyContinue | ForEach-Object { $_.TaskName + ' (' + $_.State + ')' })
    Write-Host ("  Existing tasks:    {0}" -f $(if ($tasks.Count) { $tasks -join ', ' } else { 'none' }))
    $holders = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; '{0} {1} (pid {2})' -f $_.LocalAddress, $p.ProcessName, $_.OwningProcess })
    Write-Host ("  Port 53 now:       {0}" -f $(if ($holders.Count) { ($holders -join ', ') + ' - an AegisEngine started by hand from this folder is stopped first' } else { 'free' }))
    Write-Host ("  Safety switch:     task ""{0}"" (SYSTEM; starts when a lookup fails, and every 15 minutes; only these adapters, only back to automatic)" -f $SafetyName)
    Write-Host ("  Tray at logon:     HKCU Run ""Aegis"" = ""{0}"" --tray" -f $Tray)
    Write-Host ("  Desktop shortcut:  {0}" -f $Shortcut)
}

function Install-System {
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    Start-Transcript -Path (Join-Path $StateDir 'install-log.txt') -Force | Out-Null
    $messages = New-Object System.Collections.Generic.List[string]
    $ok = $false
    $saved = @()
    $touched = $false          # true from the moment anything on the PC is changed
    $lock = Enter-SetupLock
    try {
        if (-not $lock) { throw 'another Aegis install or uninstall is running; try again once it has finished' }
        $adapters = Get-FilterAdapters
        $old = Read-Backup
        $onAegis = Get-AdaptersOnAegis
        if ($null -eq $onAegis) { throw "couldn't read the adapters' DNS settings" }

        # 1. the settings from before Aegis: kept from the earlier backup where Aegis already took over;
        #    records for adapters that aren't present right now are kept too
        foreach ($a in $adapters) {
            $s = Get-RegistryDns $a.InterfaceGuid
            $prev = $null
            if ($old) { $prev = @($old.adapters) | Where-Object { $_.guid -eq $a.InterfaceGuid } | Select-Object -First 1 }
            if ($prev -and (Test-StaticAegis $s)) { $saved += $prev }
            else { $saved += [pscustomobject]@{ alias = $a.Name; guid = $a.InterfaceGuid; static_v4 = $s.v4; static_v6 = $s.v6 } }
        }
        if ($old) {
            foreach ($p in @($old.adapters)) { if (-not (@($saved) | Where-Object { $_.guid -eq $p.guid })) { $saved += $p } }
        }
        $router = $null
        if ($onAegis.Count -gt 0 -and $old -and $old.router) { $router = $old.router } else { $router = Get-RouterDns }
        if ((-not $router) -and $old) { $router = $old.router }
        Write-Backup ([ordered]@{ installed = (Get-Date).ToString('s'); user = $User; router = $router; adapters = @($saved) })
        $messages.Add("Saved your current DNS settings (state\install.json). Local names will go to $router.")

        # 2. stop an older copy (the task, or an engine started by hand from this folder) so port 53 is free
        $touched = $true
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
        Get-AegisProcess 'AegisEngine' | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        # 3. the engine: as you (not SYSTEM: this folder is user-writable), at boot whether or not you're
        #    logged on; the every-minute trigger restarts it if it stops (a running copy makes it a no-op)
        $action = New-ScheduledTaskAction -Execute $Engine -WorkingDirectory $PSScriptRoot
        $atBoot = New-ScheduledTaskTrigger -AtStartup
        $watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
        $watchdog.Repetition.StopAtDurationEnd = $false
        $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType S4U -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 5 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($atBoot, $watchdog) -Principal $principal -Settings $settings -Force `
            -Description "Aegis: blocks ad, tracker and malware sites by answering this PC's DNS lookups on 127.0.0.1. Remove with uninstall.cmd in $PSScriptRoot." | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        $up = $false
        for ($i = 0; $i -lt 30 -and -not $up; $i++) { Start-Sleep -Seconds 1; $up = Test-EngineEverywhere }
        if (-not $up) { throw 'The engine did not answer on 127.0.0.1 and ::1 (UDP and TCP) within 30 seconds; see logs\engine.log.' }
        $enginePid = Get-EnginePid
        $proc = $null
        if ($enginePid) { $proc = Get-Process -Id $enginePid -ErrorAction SilentlyContinue }
        if (-not $proc -or $proc.Path -ne $Engine) {
            throw ("DNS on this PC is answered by another copy of the engine ({0}), not {1}; close it and try again." -f $(if ($proc) { $proc.Path } else { "pid $enginePid" }), $Engine)
        }
        $messages.Add('Engine running in the background (task "Aegis DNS filter"), answering on 127.0.0.1 and ::1, UDP and TCP.')

        # 4. the safety switch, with every adapter Aegis manages written into it (unplugged ones too)
        $guids = (@($saved) | Where-Object { "$($_.guid)" -match $GuidPattern } | ForEach-Object { "'" + $_.guid + "'" }) -join ','
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($SafetyTemplate.Replace('__MANAGED__', $guids)))
        if (-not [Diagnostics.EventLog]::SourceExists('Aegis')) { New-EventLog -LogName Application -Source 'Aegis' }
        $sAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encoded"
        $sBoot = New-ScheduledTaskTrigger -AtStartup
        $sBoot.Delay = 'PT3M'
        $sPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $sSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
        $sDescription = 'Aegis safety switch: if Windows points at Aegis but it has been silent for 90 seconds, sets DNS back to automatic.'
        $watching = $false
        try {
            # started by Windows' "lookup failed" event, with a check every 15 minutes besides
            $sEvent = New-CimInstance -CimClass (Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler) -ClientOnly
            $sEvent.Enabled = $true
            $sEvent.Subscription = $DnsFailureQuery
            Register-ScheduledTask -TaskName $SafetyName -Action $sAction -Trigger @($sBoot, $sEvent, (New-RepeatTrigger 15)) -Principal $sPrincipal -Settings $sSettings -Force `
                -Description $sDescription | Out-Null
            $watching = [bool](@((Get-ScheduledTask -TaskName $SafetyName).Triggers) | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskEventTrigger' })
            if (-not $watching) { $messages.Add('Note: the safety switch did not take the "lookup failed" trigger.') }
        }
        catch { $messages.Add("Note: the safety switch can't watch for failed lookups here ($($_.Exception.Message)).") }
        if ($watching) {
            $messages.Add('Safety switch installed (task "Aegis DNS filter safety"): it starts as soon as a lookup fails, and every 15 minutes.')
        }
        else {
            # the timed check alone, as often as before
            Register-ScheduledTask -TaskName $SafetyName -Action $sAction -Trigger @($sBoot, (New-RepeatTrigger 3)) -Principal $sPrincipal -Settings $sSettings -Force `
                -Description $sDescription | Out-Null
            $messages.Add('Safety switch installed (task "Aegis DNS filter safety", checks every 3 minutes).')
        }

        # 5. point Windows at Aegis
        foreach ($a in $adapters) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @('127.0.0.1', '::1') }
        Clear-DnsClientCache

        # 6. check it end to end: the connected adapters use exactly Aegis on IPv4 and IPv6, Windows'
        #    lookups reach Aegis, and a normal site gets a real address
        foreach ($a in $adapters) {
            $wrong = Test-AdapterOnAegis $a
            if ($wrong) { throw "$($a.Name) didn't take the new DNS settings ($wrong)." }
        }
        $routing = $null
        for ($i = 0; $i -lt 5; $i++) {
            Start-Sleep -Seconds 1
            $routing = Test-Routing
            if ($routing -eq 'ok' -or $routing -eq 'unverified') { break }
        }
        if ($routing -ne 'ok' -and $routing -ne 'unverified') { throw "Windows isn't sending its lookups through Aegis ($routing)." }
        if ($routing -eq 'unverified') { $messages.Add("Couldn't confirm the route through Windows (filtering is paused or the test ad server is allowed), but the adapters point at Aegis.") }
        $web = $null
        try { $web = (Resolve-DnsName -Name 'www.microsoft.com' -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress } catch { }
        if ((-not $web) -or $web -eq '0.0.0.0') { throw 'Windows could not look up www.microsoft.com through Aegis.' }
        $messages.Add("Windows now uses Aegis: www.microsoft.com -> $web; Aegis's own status name answers through Windows.")
        $ok = $true
    }
    catch {
        $messages.Add('Install failed: ' + $_.Exception.Message)
        if ($lock -and -not $touched) { $messages.Add('Nothing on the PC was changed.') }
        if ($lock -and $touched) {
            # Leave the PC as it was before Aegis: DNS first, and the tasks only once DNS is known to be safe.
            $problems = @()
            if (@($saved).Count -gt 0) {
                try { $problems = Restore-Dns $saved } catch { $problems = @($_.Exception.Message) }
            }
            try {
                foreach ($a in Get-FilterAdapters) {
                    try { if (Test-PointsAtAegis $a) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses } } catch { }
                }
            } catch { }
            $still = Get-AdaptersOnAegis
            if ($null -ne $still -and $still.Count -eq 0) {
                $messages.Add('Your DNS settings are as they were.' + $(if ($problems.Count) { ' (Notes: ' + ($problems -join '; ') + ')' } else { '' }))
                $left = Remove-AegisTasks
                if ($left.Count) { $messages.Add('Some Aegis tasks could not be removed: ' + ($left -join '; ') + '. Run uninstall.cmd.') }
                else { $messages.Add('The Aegis tasks were removed again; nothing of Aegis is running.') }
            }
            else {
                $where = if ($null -eq $still) { "(the adapters' DNS settings couldn't be read)" } else { 'on ' + (($still | ForEach-Object { $_.Name }) -join ', ') }
                $messages.Add("DNS may still point at Aegis $where, so the Aegis tasks were left running to keep lookups working. Run uninstall.cmd, or set DNS to automatic in Settings.")
            }
        }
    }
    finally {
        Exit-SetupLock $lock
        $messages | ForEach-Object { Write-Host $_ }
        if ($ResultFile) { [ordered]@{ ok = $ok; messages = $messages.ToArray() } | ConvertTo-Json | Set-Content -Path $ResultFile -Encoding UTF8 }
        Stop-Transcript | Out-Null
    }
    return $ok
}

# Conveniences; Aegis filters without them, so a failure here is only reported.
function Install-UserParts {
    $warnings = @()
    try { Set-ItemProperty -Path $RunKey -Name 'Aegis' -Value ('"{0}" --tray' -f $Tray) } catch { $warnings += 'start at logon: ' + $_.Exception.Message }
    try {
        $ws = New-Object -ComObject WScript.Shell
        $lnk = $ws.CreateShortcut($Shortcut)
        $lnk.TargetPath = $Tray
        $lnk.WorkingDirectory = $PSScriptRoot
        $lnk.IconLocation = "$Tray,0"
        $lnk.Description = 'Aegis DNS filter: status, recent blocks, allow or block a site'
        $lnk.Save()
    } catch { $warnings += 'desktop shortcut: ' + $_.Exception.Message }
    try { Start-TrayUnelevated } catch { $warnings += 'tray icon: ' + $_.Exception.Message }
    Write-Host ''
    Write-Host 'Aegis is on. Its shield is in the system tray (if you can''t see it, drag it out of the ^ overflow menu).'
    Write-Host 'The "Aegis" desktop shortcut opens its window. To turn it off: uninstall.cmd in this folder.'
    if ($warnings.Count) { Write-Host ('Aegis is filtering, but these extras failed: ' + ($warnings -join '; ')) }
}

# ---------------------------------------------------------------------------- main
if (-not (Test-Path $Engine) -or -not (Test-Path $Tray)) { throw 'Build first: run build.ps1 (AegisEngine.exe or Aegis.exe is missing).' }
$signingPin = Get-OlympusSigningPin
if ($signingPin) {
    Assert-OlympusArtifactSignature $Engine $signingPin
    Assert-OlympusArtifactSignature $Tray $signingPin
}
if (-not $User) { $User = [Security.Principal.WindowsIdentity]::GetCurrent().Name }

if ($DryRun) { Show-Plan; exit 0 }

if (-not (Test-Admin)) {
    if (Test-BundledAegis) { exit (Invoke-BundledAegisElevation $PSCommandPath) }
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $result = Join-Path $StateDir ('install-result-{0}.json' -f [guid]::NewGuid().ToString('N'))
    Write-Host 'Aegis needs administrator rights once, to set up its background task and point Windows at it...'
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated -User "{1}" -ResultFile "{2}"' -f $PSCommandPath, $User, $result
    try { Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList $argList -Wait | Out-Null }
    catch { Write-Host 'Cancelled at the UAC prompt; nothing was changed.'; exit 1 }
    if (-not (Test-Path $result)) { Write-Host 'The admin step ended without a result; see state\install-log.txt.'; exit 1 }
    $r = Get-Content $result -Raw | ConvertFrom-Json
    Remove-Item $result -ErrorAction SilentlyContinue
    @($r.messages) | ForEach-Object { Write-Host $_ }
    if (-not $r.ok) { exit 1 }
    Install-UserParts
    exit 0
}

# already elevated: either the relaunch from above, or run directly as administrator
$ok = [bool](Install-System | Select-Object -Last 1)
if ($ok -and -not $Elevated) { Install-UserParts }
if (-not $ok) { exit 1 }
