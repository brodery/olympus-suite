<#
  olympus-setup.ps1 - shared by install.ps1 and uninstall.ps1 (dot-sourced).
#>
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Here 'bin'
$Dest = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Olympus'
$Data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Olympus'
$TaskPath = '\Olympus\'
$Apps = @('Olympus', 'Argus', 'Sibyl', 'Janus', 'Arachne', 'Athena', 'Cerberus', 'Ark', 'Ares', 'Atlas')
$Roles = @{ Olympus = 'app hub'; Argus = 'hijack watcher'; Sibyl = 'link and scam checker'; Janus = 'download inspector'; Arachne = 'infostealer tripwire'
            Athena = 'security report card'; Cerberus = 'outbound firewall'; Ark = 'versioned backups'; Ares = 'game-mode autopilot'; Atlas = 'disk space map' }
# Programs your session runs in the background (the hub keeps them going), and the signal that stops each.
$Watchers = @{ Janus = 'janus.stop'; Ares = 'ares.stop'; Atlas = 'atlas.stop' }
$DnsLog = 'Microsoft-Windows-DNS-Client/Operational'
$FirewallGroup = 'Olympus Cerberus'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Who is installing, captured before elevating (an admin prompt can run under another account).
function Get-UserInfo {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sf = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
    [ordered]@{
        Sid = $id.User.Value; Name = $id.Name; Profile = $env:USERPROFILE; Local = $env:LOCALAPPDATA; Roaming = $env:APPDATA
        Documents = [Environment]::GetFolderPath('MyDocuments'); Desktop = [Environment]::GetFolderPath('DesktopDirectory')
        Downloads = $sf.'{374DE290-123F-4565-9164-39C4925E467B}'
    }
}

function Read-UserB64([string]$B64) {
    if ($B64) { return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($B64)) | ConvertFrom-Json) }
    return [pscustomobject](Get-UserInfo)
}

function Get-OlympusReleaseFiles([switch]$IncludeConfig) {
    foreach ($name in $Apps) {
        Join-Path $Bin "$name.exe"
        Join-Path (Join-Path $Here 'assets') ($name.ToLowerInvariant() + '.ico')
    }
    Join-Path $Bin 'atlas.ini'   # Atlas's cleanup list (your own places only; it grants no admin rights)
    if ($IncludeConfig) { Join-Path $Bin 'arachne.ini' }
}

# The hub and the watchers each wait on a named signal in your session; setting it directly works
# whichever version is installed (and from an elevated script).
function Send-OlympusSignal([string]$Name) {
    try { $e = [Threading.EventWaitHandle]::OpenExisting("Local\Olympus.$Name"); [void]$e.Set(); $e.Dispose(); return $true } catch { return $false }
}

# Closes the hub first (so it can't restart the watchers), then the watchers; waits up to $Seconds.
function Stop-UserApps([int]$Seconds = 10) {
    [void](Send-OlympusSignal 'hub.exit')
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Process Olympus -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    foreach ($signal in $Watchers.Values) { [void](Send-OlympusSignal $signal) }
    while ((Get-Process @($Watchers.Keys) -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline.AddSeconds(5)) { Start-Sleep -Milliseconds 300 }
}

function Stop-Olympus {
    Stop-UserApps
    Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue | ForEach-Object { try { Stop-ScheduledTask -InputObject $_ -ErrorAction Stop } catch { } }
    Start-Sleep -Seconds 3
    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and [IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $Dest -and
        $Apps -contains [IO.Path]::GetFileNameWithoutExtension($_.ExecutablePath)
    } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch { } }
}
