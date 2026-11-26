<#
  install.ps1 - installs Olympus (run install.cmd; one admin prompt). Safe to run again to update.

  What it does:
    1. Copies the apps from bin\ to C:\Program Files\Olympus (admin-only, so the SYSTEM tasks
       never run files your account could swap).
    2. Creates C:\ProgramData\Olympus (you can read it, only admins can change it) and records who
       you are in install.json, so the SYSTEM engines know whose files to look after.
    3. Protects A:\Ark: your account can read and restore backups but not change or delete them
       (ransomware running as you can't wipe them).
    4. Scheduled tasks in \Olympus\, running as SYSTEM:
         Argus     every 5 minutes      hijack scan
         Ark       every hour           backups (folders that are due)
         Athena    daily 4:00 + boot    admin-only facts for the report card
         Cerberus  at boot (watchdog)   outbound connections engine
         Arachne   at boot (watchdog)   infostealer tripwire engine
       Your account may start Argus, Ark and Athena on demand (Scan now, Back up now).
    5. Turns on Windows' DNS-Client log (Cerberus names sites from it).
    6. Sets up Arachne's tripwire: turns on "File System" audit for successful reads, audits the
       files listed in arachne.ini, places hidden decoy files.
    7. Starts Olympus at sign-in (your Run key), adds Start menu and desktop shortcuts, starts it now.
  Undo it all with uninstall.cmd. A transcript goes to C:\ProgramData\Olympus\install.log.

  -DryRun shows what would happen without changing anything.
#>
param([string]$UserB64, [switch]$DryRun, [switch]$NoPause)
$ErrorActionPreference = 'Stop'
if ($OlympusVerifiedRelease -ne $PSScriptRoot) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $DryRun -or $admin) { throw 'Use install.cmd to install a reviewed release.' }
    . (Join-Path $PSScriptRoot 'olympus-setup.ps1')
}
if (-not $DryRun -and -not (Test-Admin)) { throw 'Installation requires administrator rights.' }
$User = Read-UserB64 $UserB64

function Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
# (the block's variables are looked up by name in the caller, so this helper's own parameter
# names must not collide with anything a block uses: hence $OlympusWork, not $Action)
function Do-It([string]$OlympusWhat, [scriptblock]$OlympusWork) {
    if ($DryRun) { Write-Host "  (dry run) $OlympusWhat"; return }
    Write-Host "  $OlympusWhat"
    & $OlympusWork
}

# Readable by your account, changeable only by admins and SYSTEM: set on the folder itself, and
# everything inside inherits it (granting folder-style rights file by file breaks files' access).
function Protect-Folder([string]$Path) {
    New-Item -ItemType Directory -Force $Path | Out-Null
    & icacls $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Couldn't protect $Path." }
    if (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Select-Object -First 1) {
        & icacls (Join-Path $Path '*') /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Couldn't verify inherited access for all items in $Path." }
    }
}

if (-not $DryRun) {
    Protect-Folder $Data
    Start-Transcript -Path (Join-Path $Data 'install.log') -Append | Out-Null
}
$failed = $false
try {
    Write-Host "Installing Olympus for $($User.Name)" -ForegroundColor White

    Step 'Checking the build'
    $missing = @($Apps | Where-Object { -not (Test-Path (Join-Path $Bin "$_.exe")) })
    if (-not (Test-Path (Join-Path $Bin 'arachne.ini'))) { $missing += 'arachne.ini' }
    if ($missing.Count -gt 0) { throw "Missing from bin\: $($missing -join ', '). Run build.ps1 first." }
    Write-Host "  all $($Apps.Count) apps present"

    Step 'Stopping anything already running'
    Do-It 'closing the hub and watchers, stopping the engines' { Stop-Olympus }

    Step "Copying the apps to $Dest"
    Do-It 'copying' {
        New-Item -ItemType Directory -Force $Dest | Out-Null
        foreach ($file in (Get-OlympusReleaseFiles -IncludeConfig)) {
            Copy-Item -LiteralPath $file -Destination $Dest -Force
        }
    }

    Step "Creating $Data"
    Do-It 'folder with read-only access for your account' {
        $info = [ordered]@{
            Version = (Get-Item (Join-Path $Dest 'Olympus.exe')).VersionInfo.ProductVersion; InstalledAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            BinDir = $Dest; ArkTarget = 'A:\Ark'
            User = [ordered]@{ Sid = $User.Sid; Name = $User.Name; Profile = $User.Profile; Local = $User.Local; Roaming = $User.Roaming; Documents = $User.Documents; Desktop = $User.Desktop; Downloads = $User.Downloads }
        }
        [IO.File]::WriteAllText((Join-Path $Data 'install.json'), ($info | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
        # carry over the backup settings and history from before installing
        $userArk = Join-Path $User.Local 'Olympus\ark'
        $dataArk = Join-Path $Data 'ark'
        New-Item -ItemType Directory -Force $dataArk | Out-Null
        foreach ($f in 'ark.ini', 'ark-state.json') {
            if ((Test-Path (Join-Path $userArk $f)) -and -not (Test-Path (Join-Path $dataArk $f))) { Copy-Item (Join-Path $userArk $f) $dataArk }
        }
    }

    Step 'Protecting the backups on A:\Ark'
    $arkDrive = [IO.DriveInfo]::new('A')
    if (-not $arkDrive.IsReady) {
        Write-Warning 'A: is not connected. Ark will report it and back up once it is available, or you can change the target in ark.ini.'
    } elseif ($arkDrive.DriveFormat -ne 'NTFS') {
        Write-Warning 'A: needs NTFS for the default protected backup location. Ark will pause backups until an NTFS drive is available or you change the target in ark.ini.'
    } else {
        Do-It 'your account can read and restore, but not change or delete' {
            Protect-Folder 'A:\Ark'
            & icacls 'A:\Ark' /setowner '*S-1-5-32-544' /T /C /Q | Out-Null   # an owner could change the permissions back
        }
    }

    Step 'Scheduled tasks (\Olympus\, as SYSTEM)'
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    function Add-OlympusTask([string]$Name, [string]$Arguments, $Triggers, [TimeSpan]$Limit, [int]$Priority) {
        $taskAction = New-ScheduledTaskAction -Execute (Join-Path $Dest "$Name.exe") -Argument $Arguments -WorkingDirectory $Dest
        $taskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit $Limit -Priority $Priority -StartWhenAvailable `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Do-It "$Name ($Arguments)" { Register-ScheduledTask -TaskName $Name -TaskPath $TaskPath -Action $taskAction -Trigger $Triggers -Principal $principal -Settings $taskSettings -Force | Out-Null }
    }
    function Boot([int]$DelayMinutes) { $t = New-ScheduledTaskTrigger -AtStartup; if ($DelayMinutes -gt 0) { $t.Delay = 'PT' + $DelayMinutes + 'M' }; $t }
    function Every([int]$Minutes, [int]$StartIn) { New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($StartIn) -RepetitionInterval (New-TimeSpan -Minutes $Minutes) }
    Add-OlympusTask 'Argus' '--scan' @((Boot 2), (Every 5 1)) (New-TimeSpan -Minutes 15) 7
    Add-OlympusTask 'Ark' '--backup' @((Boot 10), (Every 60 10)) (New-TimeSpan -Hours 6) 7
    Add-OlympusTask 'Athena' '--collect' @((Boot 5), (New-ScheduledTaskTrigger -Daily -At '04:00')) (New-TimeSpan -Minutes 30) 7
    Add-OlympusTask 'Cerberus' '--engine' @((Boot 1), (Every 5 1)) ([TimeSpan]::Zero) 6
    Add-OlympusTask 'Arachne' '--engine' @((Boot 1), (Every 5 1)) ([TimeSpan]::Zero) 6
    Do-It 'letting your account start Argus, Ark and Athena on demand' {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $folder = $svc.GetFolder('\Olympus')
        foreach ($n in 'Argus', 'Ark', 'Athena') {
            $t = $folder.GetTask($n)
            $sd = $t.GetSecurityDescriptor(4)
            if ($sd -notmatch [regex]::Escape($User.Sid)) { $t.SetSecurityDescriptor($sd + "(A;;GRGX;;;$($User.Sid))", 0) }
        }
    }

    Step "Windows' DNS-Client log (site names for Cerberus)"
    $state = @{}
    $statePath = Join-Path $Data 'install-state.json'
    if (Test-Path $statePath) { $old = Get-Content $statePath -Raw | ConvertFrom-Json; foreach ($p in $old.PSObject.Properties) { $state[$p.Name] = $p.Value } }
    if (-not $state.ContainsKey('DnsLogWasEnabled')) { $state['DnsLogWasEnabled'] = [bool]((& wevtutil gl $DnsLog) -match 'enabled:\s*true') }
    Do-It 'turning it on (20 MB, rolls over)' { & wevtutil sl $DnsLog /e:true /ms:20971520 | Out-Null }

    Step "Arachne's tripwire"
    Do-It "File System audit for successful reads, audit entries on the files in arachne.ini, hidden decoys" {
        $out = & (Join-Path $Dest 'Arachne.exe') --setup | Out-String
        Write-Host ('  ' + $out.Trim())
    }
    if (-not $DryRun) { [IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json), (New-Object Text.UTF8Encoding $false)) }

    Step 'Start at sign-in, shortcuts'
    Do-It 'Run key and shortcuts' {
        $run = "Registry::HKEY_USERS\$($User.Sid)\Software\Microsoft\Windows\CurrentVersion\Run"
        New-ItemProperty -Path $run -Name 'Olympus' -Value ('"' + (Join-Path $Dest 'Olympus.exe') + '" --tray') -PropertyType String -Force | Out-Null
        $shell = New-Object -ComObject WScript.Shell
        $menu = Join-Path $User.Roaming 'Microsoft\Windows\Start Menu\Programs\Olympus'
        New-Item -ItemType Directory -Force $menu | Out-Null
        foreach ($a in $Apps) {
            $lnk = $shell.CreateShortcut((Join-Path $menu "$a.lnk"))
            $lnk.TargetPath = Join-Path $Dest "$a.exe"; $lnk.WorkingDirectory = $Dest; $lnk.IconLocation = (Join-Path $Dest "$a.exe") + ',0'
            $lnk.Description = "$a $($Roles[$a])"
            $lnk.Save()
        }
        $lnk = $shell.CreateShortcut((Join-Path $User.Desktop 'Olympus.lnk'))
        $lnk.TargetPath = Join-Path $Dest 'Olympus.exe'; $lnk.WorkingDirectory = $Dest; $lnk.IconLocation = (Join-Path $Dest 'Olympus.exe') + ',0'; $lnk.Description = 'Olympus app hub'
        $lnk.Save()
    }

    Step 'Starting the engines'
    Do-It 'Argus (first full scan), Cerberus, Arachne, Athena' {
        foreach ($n in 'Argus', 'Cerberus', 'Arachne', 'Athena') { Start-ScheduledTask -TaskPath $TaskPath -TaskName $n }
    }
    Do-It 'the Olympus hub (as you, not as admin)' { Start-Process explorer.exe -ArgumentList ('"' + (Join-Path $Dest 'Olympus.exe') + '"') }

    if (-not $DryRun) {
        Step 'Checking'
        Start-Sleep -Seconds 20
        foreach ($n in 'Argus', 'Ark', 'Athena', 'Cerberus', 'Arachne') {
            $t = Get-ScheduledTask -TaskPath $TaskPath -TaskName $n
            $info = $t | Get-ScheduledTaskInfo
            $statusFile = Join-Path $Data ($n.ToLower() + '\status.json')
            $summary = if (Test-Path $statusFile) { (Get-Content $statusFile -Raw | ConvertFrom-Json).Summary } else { '(no report yet)' }
            '  {0,-9} task {1,-8} last result {2,-10} {3}' -f $n, $t.State, ('0x{0:X}' -f $info.LastTaskResult), $summary
        }
        $test = Start-Process (Join-Path $Dest 'Arachne.exe') -ArgumentList '--test' -Wait -PassThru
        Write-Host ('  Arachne tripwire test: ' + $(if ($test.ExitCode -eq 0) { 'caught the test read' } else { 'no answer yet (check again in a few minutes from Arachne''s window)' }))
        Write-Host ''
        Write-Host 'Olympus is installed. Its icon is in the notification area; the dashboard is open.' -ForegroundColor Green
        Write-Host 'To undo everything: uninstall.cmd in this folder.'
    }
}
catch {
    $failed = $true
    Write-Host ''
    Write-Host "Install stopped: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Nothing after that step was changed. Fix the problem and run install.cmd again, or run uninstall.cmd to remove what was set up.'
}
finally {
    if (-not $DryRun) { try { Stop-Transcript | Out-Null } catch { } }
    if (-not $NoPause -and -not $DryRun) { Read-Host 'Press Enter to close' | Out-Null }
}
if ($failed) { exit 1 }
