<#
  update.ps1 - puts a new build in place (run update.cmd; one admin prompt).

  Only replaces Olympus's program files in C:\Program Files\Olympus with the ones in bin\ that
  changed, and restarts whatever runs them (the hub, the watchers, the Cerberus and Arachne
  engines). It changes no settings: no scheduled-task definitions, permissions, audit policy,
  logs or tripwire files. A file that's in use (say, Ark mid-backup) is renamed aside and the
  new one takes over at its next run. Changes to arachne.ini need install.cmd instead.
  A transcript goes to C:\ProgramData\Olympus\update.log.
#>
param([switch]$NoPause)
$ErrorActionPreference = 'Stop'
if ($OlympusVerifiedRelease -ne $PSScriptRoot -or -not (Test-Admin)) {
    throw 'Use update.cmd to install a reviewed release.'
}

$code = 0
Start-Transcript -Path (Join-Path $Data 'update.log') -Append | Out-Null
try {
    if (-not (Test-Path (Join-Path $Dest 'Olympus.exe'))) { throw "Olympus isn't installed yet; run install.cmd." }
    foreach ($old in @(Get-ChildItem $Dest -Filter '*.old' -File -ErrorAction SilentlyContinue)) { try { Remove-Item -LiteralPath $old.FullName -Force -ErrorAction Stop } catch { } }

    $sources = Get-OlympusReleaseFiles | ForEach-Object { Get-Item -LiteralPath $_ }
    $changed = @($sources | Where-Object {
        $t = Join-Path $Dest $_.Name
        -not (Test-Path $t) -or (Get-FileHash $_.FullName).Hash -ne (Get-FileHash $t).Hash })
    $ini = Join-Path $Bin 'arachne.ini'
    $installedIni = Join-Path $Dest 'arachne.ini'
    if ((Test-Path -LiteralPath $ini -PathType Leaf) -and
        ((-not (Test-Path -LiteralPath $installedIni -PathType Leaf)) -or
         (Get-FileHash -LiteralPath $ini).Hash -ne (Get-FileHash -LiteralPath $installedIni).Hash)) {
        Write-Warning "The installed arachne.ini is missing or differs from the build. Run install.cmd to apply the tripwire list."
    }
    if ($changed.Count -eq 0) { Write-Host 'Already up to date.' -ForegroundColor Green; return }
    $names = @($changed | Where-Object { $_.Extension -eq '.exe' } | ForEach-Object { $_.BaseName })
    Write-Host ('Updating: ' + (($changed | ForEach-Object { $_.Name }) -join ', '))

    # stop what runs the changed programs: the hub first (it would restart the watchers), then the
    # watchers, then the engines; our own apps still running after that are closed by force
    $userApps = @(@('Olympus') + @($Watchers.Keys)) | Where-Object { $names -contains $_ }
    $restartHub = $false
    if ($userApps.Count -gt 0) { $restartHub = [bool](Get-Process Olympus -ErrorAction SilentlyContinue) -or ($names -contains 'Olympus'); Stop-UserApps 10 }
    foreach ($e in 'Cerberus', 'Arachne') { if ($names -contains $e) { try { Stop-ScheduledTask -TaskPath $TaskPath -TaskName $e -ErrorAction Stop } catch { } } }
    Start-Sleep -Seconds 1
    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Dest + '\', [StringComparison]::OrdinalIgnoreCase) -and
        (@('Olympus', 'Cerberus', 'Arachne') + @($Watchers.Keys)) -contains [IO.Path]::GetFileNameWithoutExtension($_.ExecutablePath) -and
        $names -contains [IO.Path]::GetFileNameWithoutExtension($_.ExecutablePath) } |
        ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Host "  ($($_.Name) didn't close by itself; ended it)" } catch { } }

    # put the new files in place (one still in use is renamed aside first)
    foreach ($f in $changed) {
        $t = Join-Path $Dest $f.Name
        try { Copy-Item -LiteralPath $f.FullName -Destination $t -Force -ErrorAction Stop }
        catch {
            Rename-Item -LiteralPath $t -NewName ('{0}.{1}.old' -f $f.Name, (Get-Date -Format 'yyyyMMddHHmmss'))
            Copy-Item -LiteralPath $f.FullName -Destination $t
            Write-Host "  ($($f.Name) was in use: the new copy takes over at its next start)"
        }
        Write-Host "  updated $($f.Name)"
    }

    # a Start menu entry for an app that's new since install (install.cmd made the others)
    $info = Get-Content -LiteralPath (Join-Path $Data 'install.json') -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    if ($info -and $info.User -and $info.User.Roaming) {
        $menu = Join-Path $info.User.Roaming 'Microsoft\Windows\Start Menu\Programs\Olympus'
        if (Test-Path -LiteralPath $menu) {
            $shell = New-Object -ComObject WScript.Shell
            foreach ($a in $Apps) {
                $link = Join-Path $menu "$a.lnk"
                if ((Test-Path -LiteralPath $link) -or -not (Test-Path -LiteralPath (Join-Path $Dest "$a.exe"))) { continue }
                $lnk = $shell.CreateShortcut($link)
                $lnk.TargetPath = Join-Path $Dest "$a.exe"; $lnk.WorkingDirectory = $Dest; $lnk.IconLocation = (Join-Path $Dest "$a.exe") + ',0'
                $lnk.Description = "$a $($Roles[$a])"
                $lnk.Save()
                Write-Host "  added $a to the Start menu"
            }
        }
    }

    # start them again
    # (an engine you switched off in Olympus stays off)
    foreach ($e in 'Cerberus', 'Arachne') {
        if ($names -notcontains $e) { continue }
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $e -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') { Start-ScheduledTask -TaskPath $TaskPath -TaskName $e }
        else { Write-Host "  ($e is switched off in Olympus; left off)" }
    }
    if ($restartHub) { Start-Process explorer.exe -ArgumentList ('"' + (Join-Path $Dest 'Olympus.exe') + '"') }   # as you, not as admin; it restarts the watchers
    Write-Host 'Olympus is up to date.' -ForegroundColor Green
}
catch { $code = 1; Write-Host "Update stopped: $($_.Exception.Message)" -ForegroundColor Red }
finally {
    try { Stop-Transcript | Out-Null } catch { }
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
}
exit $code
