# aegis-setup.ps1 - shared by install.ps1 and uninstall.ps1 (dot-sourced). Only defines things; runs nothing.

$Engine = Join-Path $PSScriptRoot 'AegisEngine.exe'
$Tray = Join-Path $PSScriptRoot 'Aegis.exe'
$StateDir = Join-Path $PSScriptRoot 'state'
$BackupPath = Join-Path $StateDir 'install.json'
$BackupPrev = Join-Path $StateDir 'install.json.bak'
$TaskName = 'Aegis DNS filter'
$SafetyName = 'Aegis DNS filter safety'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Shortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Aegis.lnk'
$GuidPattern = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-BundledAegis {
    (Split-Path -Parent $Engine) -eq (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Olympus Aegis')
}

function Invoke-BundledAegisElevation([string]$Script) {
    $requesterSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -RequesterSid {1}' -f $Script, $requesterSid
    try {
        $child = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $argList -PassThru -Wait
        return $child.ExitCode
    } catch {
        Write-Host "Aegis could not start as administrator. $($_.Exception.Message)"
        return 1
    }
}

function Assert-AegisRequester([string]$RequesterSid) {
    if ($RequesterSid -and $RequesterSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw 'Approve the Windows prompt using the same account that launched Aegis setup.'
    }
}

# Wired and Wi-Fi adapters; Bluetooth, VPN and virtual adapters are left alone.
function Get-FilterAdapters {
    @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.InterfaceDescription -notmatch 'Bluetooth' })
}

# A NameServer value ("a,b" or "a b") as a list of addresses.
function Split-Servers([string]$Value) { @("$Value" -split '[,\s]+' | Where-Object { $_ }) }

# The DNS servers stored for an adapter (empty = automatic, from the router).
function Get-RegistryDns([string]$Guid) {
    $k4 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
    $k6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    [pscustomobject]@{
        v4   = "$((Get-ItemProperty $k4 -ErrorAction SilentlyContinue).NameServer)"
        v6   = "$((Get-ItemProperty $k6 -ErrorAction SilentlyContinue).NameServer)"
        Has6 = (Test-Path $k6)
    }
}

# Stored settings pointing at Aegis: exact addresses, not a substring match (2606:4700:4700::1111 isn't ::1).
function Test-StaticAegis($Dns) { ((Split-Servers $Dns.v4) -contains '127.0.0.1') -or ((Split-Servers $Dns.v6) -contains '::1') }

# The DNS servers an adapter uses right now, IPv4 and IPv6. Throws if they can't be read.
function Get-AdapterDns($Adapter) {
    @(Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
}

# Does the adapter use Aegis right now? Throws when that can't be read: callers treat it as "maybe".
function Test-PointsAtAegis($Adapter) {
    $s = Get-AdapterDns $Adapter
    return ($s -contains '127.0.0.1' -or $s -contains '::1')
}

# The adapters using Aegis now, or $null when that can't be determined.
function Get-AdaptersOnAegis {
    try { return , @(Get-FilterAdapters | Where-Object { Test-PointsAtAegis $_ }) } catch { return $null }
}

function Test-Engine([string]$Server = '127.0.0.1', [switch]$Tcp) {
    try {
        $p = @{ Name = 'status.aegis.invalid'; Type = 'TXT'; Server = $Server; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
        if ($Tcp) { $p['TcpOnly'] = $true }
        $r = Resolve-DnsName @p
        return [bool](((@($r | ForEach-Object { $_.Strings }) -join '') -match 'app=Aegis'))
    } catch { return $false }
}

# Both loopback addresses, UDP and TCP: everything Windows may use once it points at Aegis.
function Test-EngineEverywhere {
    (Test-Engine '127.0.0.1') -and (Test-Engine '127.0.0.1' -Tcp) -and (Test-Engine '::1') -and (Test-Engine '::1' -Tcp)
}

# The process id the answering engine reports, so we know which copy it is.
function Get-EnginePid {
    try {
        $r = Resolve-DnsName -Name 'status.aegis.invalid' -Type TXT -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop
        $txt = (@($r | ForEach-Object { $_.Strings }) -join '')
        if ($txt -match 'pid=(\d+)') { return [int]$Matches[1] }
    } catch { }
    return $null
}

# Is Windows' own resolver sending lookups to Aegis? Asks Aegis's status name through it; if Windows
# won't pass that name on, compares an ad server's answer with what Aegis itself says right now.
function Test-Routing {
    try {
        $r = Resolve-DnsName -Name 'status.aegis.invalid' -Type TXT -DnsOnly -QuickTimeout -ErrorAction Stop
        if ((@($r | ForEach-Object { $_.Strings }) -join '') -match 'app=Aegis') { return 'ok' }
    } catch { }
    $direct = $null
    $viaWindows = $null
    try { $direct = (Resolve-DnsName -Name 'googleads.g.doubleclick.net' -Type A -Server 127.0.0.1 -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress } catch { }
    if ($direct -ne '0.0.0.0') { return 'unverified' }      # paused, or that host is allowed: can't tell this way
    try { $viaWindows = (Resolve-DnsName -Name 'googleads.g.doubleclick.net' -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress } catch { }
    if ($viaWindows -eq '0.0.0.0') { return 'ok' }
    return "an ad server resolved to '$viaWindows' through Windows"
}

# Up adapters must use exactly 127.0.0.1 (and ::1 where they have IPv6). Returns what's wrong, or $null.
function Test-AdapterOnAegis($Adapter) {
    if ($Adapter.Status -ne 'Up') { return $null }          # not connected: nothing in use to check (its stored settings are)
    $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
    if (($v4 -join ',') -ne '127.0.0.1') { return "IPv4 DNS in use is '$($v4 -join ', ')'" }
    if ((Get-RegistryDns $Adapter.InterfaceGuid).Has6) {
        $v6 = @((Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv6 -ErrorAction Stop).ServerAddresses)
        if (($v6 -join ',') -ne '::1') { return "IPv6 DNS in use is '$($v6 -join ', ')'" }
    }
    return $null
}

# The DNS server Windows uses now on the internet adapter (normally the router), for local names.
function Get-RouterDns {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if (-not $route) { return $null }
    $dns = @((Get-DnsClientServerAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
        Where-Object { $_ -and $_ -ne '127.0.0.1' }) | Select-Object -First 1
    if ($dns) { return $dns }
    return $route.NextHop
}

# A backup is only trusted when every adapter entry carries a proper adapter ID.
function Test-Backup($Backup) {
    if (-not $Backup -or -not $Backup.adapters) { return $false }
    foreach ($a in @($Backup.adapters)) { if ("$($a.guid)" -notmatch $GuidPattern) { return $false } }
    return $true
}

# state\install.json, or its last good copy if it's damaged.
function Read-Backup {
    foreach ($p in @($BackupPath, $BackupPrev)) {
        if (-not (Test-Path $p)) { continue }
        try {
            $b = Get-Content $p -Raw | ConvertFrom-Json
            if (Test-Backup $b) { return $b }
        } catch { }
    }
    return $null
}

# Written to a temporary file, read back and checked, then swapped in; the previous good copy stays as .bak.
function Write-Backup($Object) {
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $json = $Object | ConvertTo-Json -Depth 4
    $tmp = "$BackupPath.tmp"
    Set-Content -Path $tmp -Value $json -Encoding UTF8
    if (-not (Test-Backup (Get-Content $tmp -Raw | ConvertFrom-Json))) { throw 'the new backup of your DNS settings did not read back correctly' }
    if (Test-Path $BackupPath) {
        try { if (Test-Backup (Get-Content $BackupPath -Raw | ConvertFrom-Json)) { Copy-Item $BackupPath $BackupPrev -Force } } catch { }
    }
    Move-Item -Path $tmp -Destination $BackupPath -Force
}

# After a successful uninstall the backup has done its job: renamed, so a later uninstall can't replay it.
function Retire-Backup {
    foreach ($p in @($BackupPath, $BackupPrev)) {
        if (Test-Path $p) { Move-Item -Path $p -Destination ($p -replace '\.json', '.restored.json') -Force }
    }
}

# For an adapter that isn't present right now: its stored settings, so it comes back working.
function Set-RegistryDns([string]$Guid, [string]$V4, [string]$V6) {
    $k4 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
    $k6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    if (Test-Path $k4) { Set-ItemProperty -Path $k4 -Name NameServer -Value $V4 -ErrorAction Stop }
    if (Test-Path $k6) { Set-ItemProperty -Path $k6 -Name NameServer -Value $V6 -ErrorAction Stop }
}

# Puts each saved adapter back on its own (one failure doesn't stop the rest) and checks the result.
# Returns the problems.
function Restore-Dns($Saved) {
    $problems = @()
    foreach ($b in @($Saved)) {
        if (-not $b) { continue }
        if ("$($b.guid)" -notmatch $GuidPattern) { $problems += ('a backup entry ({0}) has no valid adapter ID' -f $b.alias); continue }
        try {
            $v4 = @(Split-Servers $b.static_v4 | Where-Object { $_ -ne '127.0.0.1' })
            $v6 = @(Split-Servers $b.static_v6 | Where-Object { $_ -ne '::1' })
            $a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid -eq $b.guid } | Select-Object -First 1
            if ($a) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
                    if ($v4.Count -gt 0 -or $v6.Count -gt 0) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ($v4 + $v6) }
                }
                catch { Set-RegistryDns $b.guid ($v4 -join ',') ($v6 -join ',') }
                if (Test-PointsAtAegis $a) { throw 'it still points at this PC' }
            }
            else {
                # not present right now (unplugged or disabled): fix its stored settings so it comes back working
                Set-RegistryDns $b.guid ($v4 -join ',') ($v6 -join ',')
                if (Test-StaticAegis (Get-RegistryDns $b.guid)) { throw 'its stored settings still point at this PC' }
            }
        }
        catch { $problems += ('{0}: {1}' -f $b.alias, $_.Exception.Message) }
    }
    try { Clear-DnsClientCache } catch { }
    return , $problems
}

# Running copies of an Aegis program from this folder ('Aegis' or 'AegisEngine'), including copies that
# build.ps1 renamed aside while they ran (<name>.<time>.old.exe). The engine is only visible with admin rights.
function Get-AegisProcess([string]$BaseName) {
    $pattern = Join-Path (Split-Path -Parent $Engine) ($BaseName + '*.exe')
    @(Get-Process -Name ($BaseName + '*') -ErrorAction SilentlyContinue | Where-Object {
        ($_.ProcessName -eq $BaseName -or $_.ProcessName -like ($BaseName + '.*.old')) -and $_.Path -and $_.Path -like $pattern })
}

# Removes both tasks and stops the engine. Returns the problems (a task that wouldn't go away).
function Remove-AegisTasks {
    $problems = @()
    foreach ($t in @($SafetyName, $TaskName)) {
        if (-not (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue)) { continue }
        try {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction Stop
        }
        catch { $problems += ('{0}: {1}' -f $t, $_.Exception.Message) }
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { $problems += ('task "{0}" is still registered' -f $t) }
    }
    Get-AegisProcess 'AegisEngine' | Stop-Process -Force -ErrorAction SilentlyContinue
    return , $problems
}

# A task trigger that fires every N minutes from N minutes from now, for good.
function New-RepeatTrigger([int]$Minutes) {
    $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Minutes) -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
    $t.Repetition.StopAtDurationEnd = $false
    $t
}

# Only one install or uninstall at a time, across processes.
function Enter-SetupLock {
    $m = New-Object System.Threading.Mutex($false, 'Global\AegisSetup')
    $owned = $false
    try { $owned = $m.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
    if ($owned) { return $m }
    $m.Dispose()
    return $null
}

function Exit-SetupLock($Lock) {
    if (-not $Lock) { return }
    try { $Lock.ReleaseMutex() } catch { }
    $Lock.Dispose()
}

# The tray icon always runs with your normal rights, even when this script is elevated.
function Start-TrayUnelevated {
    if (Test-Admin) { Start-Process -FilePath explorer.exe -ArgumentList ('"{0}"' -f $Tray) }
    else { Start-Process -FilePath $Tray }
}

# What Windows logs when none of its DNS servers answered a lookup (DNS Client event 1014): the safety
# switch starts on it, so a dead engine is noticed as soon as lookups fail, not at the next timed check.
$DnsFailureQuery = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name=''Microsoft-Windows-DNS-Client''] and EventID=1014]]</Select></Query></QueryList>'

# The safety switch's code. It runs as SYSTEM, so it reads nothing from this (user-writable) folder:
# the adapters it may touch are written into it at install time (__MANAGED__), and all it ever does is
# set those adapters back to automatic DNS once Aegis has been silent for 90 seconds in a row (time for
# its every-minute restart to try), and never in the first 4 minutes after boot, while it may still be
# starting. Each run watches for at least a minute, so a burst of failure events starts just one copy.
$SafetyTemplate = @'
$ErrorActionPreference = 'SilentlyContinue'
$managed = @(__MANAGED__)
function Get-Pointing {
    @(Get-NetAdapter | Where-Object { $managed -contains $_.InterfaceGuid } | Where-Object {
        $s = @(Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex | ForEach-Object { $_.ServerAddresses })
        $s -contains '127.0.0.1' -or $s -contains '::1' })
}
function Test-Aegis { [bool](Resolve-DnsName -Name status.aegis.invalid -Type TXT -Server 127.0.0.1 -DnsOnly -QuickTimeout) }
if ((Get-Pointing).Count -eq 0) { exit 0 }
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$watchUntil = (Get-Date).AddSeconds(60)
$silentSince = $null
while ($true) {
    if (Test-Aegis) {
        $silentSince = $null
        if ((Get-Date) -ge $watchUntil) { exit 0 }
    }
    else {
        if (-not $silentSince) { $silentSince = Get-Date }
        $deadline = $silentSince.AddSeconds(90)
        if ($boot -and $boot.AddMinutes(4) -gt $deadline) { $deadline = $boot.AddMinutes(4) }
        if ((Get-Date) -ge $deadline) { break }
    }
    Start-Sleep -Seconds 15
}
$reset = @(Get-Pointing)
if ($reset.Count -eq 0) { exit 0 }
foreach ($a in $reset) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
Clear-DnsClientCache
Write-EventLog -LogName Application -Source Aegis -EventId 1001 -EntryType Warning -Message ('Aegis stopped answering DNS for 90 seconds, so its safety switch set DNS back to automatic on: ' + (($reset | ForEach-Object { $_.Name }) -join ', ') + '. Run install.cmd in the Aegis folder to turn Aegis on again.')
exit 1
'@
