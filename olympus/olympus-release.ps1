# Runs a reviewed Olympus release from its administrator-controlled location.
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Update','Uninstall')][string]$Operation,
    [string]$UserB64,
    [switch]$DryRun, [switch]$NoPause, [switch]$Wait,
    [switch]$KeepFirewallRules, [switch]$Purge
)
$ErrorActionPreference = 'Stop'

function Assert-OlympusReleaseItem([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular release item at $Path."
    }

    $sidType = [Security.Principal.SecurityIdentifier]
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner($sidType).Value -notin $trusted) { throw "The owner of $Path must be an administrator or Windows." }
    $rules = $acl.GetAccessRules($true, $true, $sidType)
    $writes = [Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $writeMask = [int]$writes -bor 0x50000000
    if ($rules.Count -eq 0) { throw "Missing access rules for $Path." }
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq 'Allow' -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ([int]$rule.FileSystemRights -band $writeMask) -and
            $rule.IdentityReference.Value -notin $trusted) {
            throw "A non-administrator has write access to $Path."
        }
    }
}

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$release = Join-Path $programFiles 'Olympus Release'
if ($PSScriptRoot -ne $release) { throw "Run the reviewed copy of Olympus from $release." }
Assert-OlympusReleaseItem $programFiles $true
Assert-OlympusReleaseItem $release $true
Assert-OlympusReleaseItem $PSCommandPath $false
$setup = Join-Path $release 'olympus-setup.ps1'
$operationScript = Join-Path $release ($Operation.ToLowerInvariant() + '.ps1')
Assert-OlympusReleaseItem $setup $false
Assert-OlympusReleaseItem $operationScript $false
. $setup

if ($DryRun -and $Operation -ne 'Install') { throw 'DryRun is available for install only.' }
if (Get-Item -LiteralPath $Data -Force -ErrorAction SilentlyContinue) {
    Assert-OlympusReleaseItem $Data $true
}
if (Test-Path -LiteralPath $Dest) {
    Assert-OlympusReleaseItem $Dest $true
    if ($Operation -ne 'Uninstall') {
        foreach ($name in $Apps) {
            foreach ($leaf in "$name.exe", "$name.ico") {
                $existing = Join-Path $Dest $leaf
                if (Test-Path -LiteralPath $existing) { Assert-OlympusReleaseItem $existing $false }
            }
        }
        $existing = Join-Path $Dest 'arachne.ini'
        if (Test-Path -LiteralPath $existing) { Assert-OlympusReleaseItem $existing $false }
    }
}

if ($Operation -ne 'Uninstall') {
    $signingHelper = Join-Path $release 'release-signing.ps1'
    Assert-OlympusReleaseItem $signingHelper $false
    . $signingHelper
    $signingPin = Get-OlympusSigningPin
    Assert-OlympusReleaseItem $Bin $true
    Assert-OlympusReleaseItem (Join-Path $Here 'assets') $true
    foreach ($file in (Get-OlympusReleaseFiles -IncludeConfig)) {
        Assert-OlympusReleaseItem $file $false
        if ($signingPin -and [IO.Path]::GetExtension($file) -eq '.exe') {
            Assert-OlympusArtifactSignature $file $signingPin
        }
    }
} else {
    $OlympusTeardownExe = Join-Path $Dest 'Arachne.exe'
    if (-not (Test-Path -LiteralPath $OlympusTeardownExe)) {
        $OlympusTeardownExe = Join-Path $Bin 'Arachne.exe'
        if (Test-Path -LiteralPath $OlympusTeardownExe) { Assert-OlympusReleaseItem $Bin $true }
    }
    if (Test-Path -LiteralPath $OlympusTeardownExe) {
        Assert-OlympusReleaseItem $OlympusTeardownExe $false
    } elseif (Test-Path -LiteralPath (Join-Path $Data 'arachne\setup.json')) {
        throw 'Arachne still has an audit setup. Stage a reviewed Arachne.exe before uninstalling.'
    }
}

if (-not (Test-Admin) -and -not $DryRun) {
    $u = (Get-UserInfo | ConvertTo-Json -Compress)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($u))
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-Operation', $Operation, '-UserB64', $b64)
    foreach ($flag in 'NoPause', 'KeepFirewallRules', 'Purge') {
        if ($PSBoundParameters.ContainsKey($flag) -and $PSBoundParameters[$flag]) { $argList += "-$flag" }
    }
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    try {
        $process = Start-Process $powershell -Verb RunAs -ArgumentList $argList -PassThru -Wait:$Wait
        if ($Wait) { exit $process.ExitCode }
    } catch {
        Write-Error "Olympus could not start as administrator. $($_.Exception.Message)" -ErrorAction Continue
        exit 1
    }
    return
}

$OlympusVerifiedRelease = $release
$forward = @{ NoPause = $NoPause }
if ($Operation -ne 'Update' -and $UserB64) { $forward.UserB64 = $UserB64 }
if ($Operation -eq 'Install') { $forward.DryRun = $DryRun }
if ($Operation -eq 'Uninstall') {
    $forward.KeepFirewallRules = $KeepFirewallRules
    $forward.Purge = $Purge
}
& $operationScript @forward
if (-not $?) { exit 1 }
