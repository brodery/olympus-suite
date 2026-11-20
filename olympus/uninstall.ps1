<#
  uninstall.ps1 - removes Olympus (run uninstall.cmd; one admin prompt).

  Undoes what install.ps1 did: closes the apps, removes Arachne's audit entries and decoys and
  puts the File System audit policy back, deletes the \Olympus\ scheduled tasks, puts the
  DNS-Client log back the way it was, removes Cerberus's firewall rules (-KeepFirewallRules to
  keep them), the Run key, the shortcuts, and C:\Program Files\Olympus.

  Kept: your backups in A:\Ark (never deleted; the folder stays read-only for your account so
  ransomware still can't touch it; "icacls A:\Ark /reset /T" in an admin prompt gives it back),
  and C:\ProgramData\Olympus (logs and history) unless you add -Purge.
#>
param([string]$UserB64, [switch]$KeepFirewallRules, [switch]$Purge, [switch]$NoPause)
$ErrorActionPreference = 'Continue'
if ($OlympusVerifiedRelease -ne $PSScriptRoot -or -not (Test-Admin)) {
    throw 'Use uninstall.cmd to remove Olympus.'
}
$User = Read-UserB64 $UserB64
function Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }

Write-Host "Removing Olympus for $($User.Name)" -ForegroundColor White

Step 'Closing the apps'
Stop-Olympus

Step "Arachne's tripwire"
if (Test-Path -LiteralPath $OlympusTeardownExe -PathType Leaf) {
    Write-Host ('  ' + ((& $OlympusTeardownExe --teardown | Out-String).Trim()))
    if ($LASTEXITCODE -ne 0) { throw 'Arachne could not complete the tripwire teardown.' }
} else { Write-Host '  No Arachne audit setup to remove' }

Step 'Scheduled tasks'
Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue | ForEach-Object {
    Unregister-ScheduledTask -InputObject $_ -Confirm:$false
    Write-Host "  removed $($_.TaskName)"
}
try { $svc = New-Object -ComObject Schedule.Service; $svc.Connect(); $svc.GetFolder('\').DeleteFolder('Olympus', 0) } catch { }

Step "Windows' DNS-Client log"
$statePath = Join-Path $Data 'install-state.json'
$state = if (Test-Path $statePath) { Get-Content $statePath -Raw | ConvertFrom-Json } else { $null }
if ($state -and -not $state.DnsLogWasEnabled) { & wevtutil sl $DnsLog /e:false | Out-Null; Write-Host '  switched back off (it was off before Olympus)' }
else { Write-Host '  left on (it was on before Olympus)' }

Step "Cerberus's firewall rules"
$rules = @(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) { Write-Host '  none' }
elseif ($KeepFirewallRules) { Write-Host "  kept $($rules.Count) (those programs stay blocked)" }
else { $rules | Remove-NetFirewallRule; Write-Host "  removed $($rules.Count) (those programs can go online again)" }

Step 'Run key and shortcuts'
Remove-ItemProperty -Path "Registry::HKEY_USERS\$($User.Sid)\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'Olympus' -ErrorAction SilentlyContinue
Remove-Item (Join-Path $User.Roaming 'Microsoft\Windows\Start Menu\Programs\Olympus') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $User.Desktop 'Olympus.lnk') -Force -ErrorAction SilentlyContinue
Write-Host '  removed'

Step "Program files"
Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
Write-Host $(if (Test-Path $Dest) { "  some files in $Dest were in use; delete the folder after a restart" } else { "  removed $Dest" })

Step 'Data'
if ($Purge) { Remove-Item $Data -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "  removed $Data" }
else { Write-Host "  kept $Data (logs and history; run uninstall.cmd -Purge to remove it)" }
Write-Host '  kept your backups in A:\Ark'

Write-Host ''
Write-Host 'Olympus is removed. Aegis is a separate app and is untouched.' -ForegroundColor Green
if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
