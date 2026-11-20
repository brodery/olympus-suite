# Requires Windows PowerShell 5.1 and the 64-bit .NET Framework C# compiler.
[CmdletBinding()]
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'dist' }
$zipName = 'Olympus-Windows-x64.zip'
$tempRoot = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).ProviderPath
$work = Join-Path $tempRoot ('OlympusRelease-' + [Guid]::NewGuid().ToString('N'))
$originalTemp = $env:TEMP
$originalTmp = $env:TMP

$olympusScripts = @('install.ps1', 'install.cmd', 'update.ps1', 'update.cmd', 'uninstall.ps1',
    'uninstall.cmd', 'olympus-setup.ps1', 'olympus-release.ps1', 'release-signing.ps1')
$aegisFiles = @('install.ps1', 'install.cmd', 'uninstall.ps1', 'uninstall.cmd',
    'aegis-setup.ps1', 'release-signing.ps1', 'aegis.ini')

function Copy-ReleaseFile([string]$Source, [string]$Destination) {
    $item = Get-Item -LiteralPath $Source -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular file at $Source."
    }
    Copy-Item -LiteralPath $Source -Destination $Destination
}

# Build from a separate source copy so the component builders cannot use old output.
function Copy-BuildSource([string]$Name, [string[]]$Files) {
    $source = Join-Path $PSScriptRoot $Name
    $destination = Join-Path $work $Name
    New-Item -ItemType Directory -Path $destination | Out-Null
    Copy-Item -LiteralPath (Join-Path $source 'src') -Destination $destination -Recurse
    foreach ($file in @('build.ps1') + $Files) {
        Copy-ReleaseFile (Join-Path $source $file) $destination
    }
    return $destination
}

function New-ReleaseArchive([string]$Directory, [string]$Zip) {
    $archive = [IO.Compression.ZipFile]::Open($Zip, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in Get-ChildItem -LiteralPath $Directory -File -Recurse) {
            $name = $file.FullName.Substring($Directory.Length + 1).Replace('\', '/')
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $name,
                [IO.Compression.CompressionLevel]::Optimal)
        }
    }
    finally { $archive.Dispose() }
}

try {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    New-Item -ItemType Directory -Path $work | Out-Null
    $scratch = Join-Path $work 'scratch'
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $env:TEMP = $scratch
    $env:TMP = $scratch

    $olympusSource = Copy-BuildSource 'olympus' $olympusScripts
    $aegisSource = Copy-BuildSource 'aegis' $aegisFiles
    & (Join-Path $olympusSource 'build.ps1')
    & (Join-Path $aegisSource 'build.ps1') -NoDeploy

    $payload = Join-Path $work 'payload'
    $olympusPayload = Join-Path $payload 'Olympus'
    $aegisPayload = Join-Path $payload 'Aegis'
    $outer = Join-Path $work 'package'
    New-Item -ItemType Directory -Path $payload, $olympusPayload, $aegisPayload, $outer | Out-Null
    foreach ($file in $olympusScripts) { Copy-ReleaseFile (Join-Path $olympusSource $file) $olympusPayload }
    foreach ($file in $aegisFiles + @('aegis.ico')) { Copy-ReleaseFile (Join-Path $aegisSource $file) $aegisPayload }
    foreach ($file in @('Aegis.exe', 'AegisEngine.exe')) {
        Copy-ReleaseFile (Join-Path $aegisSource "build\$file") $aegisPayload
    }

    $olympusReleaseFiles = & {
        . (Join-Path $olympusSource 'olympus-setup.ps1')
        Get-OlympusReleaseFiles -IncludeConfig
    }
    $sourcePrefix = $olympusSource + [IO.Path]::DirectorySeparatorChar
    New-Item -ItemType Directory -Path (Join-Path $olympusPayload 'bin'), (Join-Path $olympusPayload 'assets') | Out-Null
    foreach ($file in $olympusReleaseFiles) {
        if (-not $file.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unexpected Olympus release path: $file"
        }
        Copy-ReleaseFile $file (Join-Path $olympusPayload $file.Substring($sourcePrefix.Length))
    }

    $payloadZip = Join-Path $work 'payload.zip'
    New-ReleaseArchive $payload $payloadZip
    $payloadHash = (Get-FileHash -LiteralPath $payloadZip -Algorithm SHA256).Hash
    $metadata = Join-Path $work 'BundleMetadata.cs'
    $metadataSource = '[assembly: System.Reflection.AssemblyMetadata("BundleSha256", "{0}")]' -f $payloadHash
    Set-Content -LiteralPath $metadata -Encoding ASCII -Value $metadataSource

    $installerSource = Join-Path $PSScriptRoot 'installer'
    $setupExe = Join-Path $outer 'Setup.exe'
    $compiler = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $compilerArgs = @('/nologo', '/langversion:5', '/codepage:65001', '/optimize+', '/target:winexe', '/platform:x64',
        '/r:System.Core.dll', '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
        "/out:$setupExe", "/resource:$payloadZip,Olympus.Payload.zip", "/win32manifest:$(Join-Path $installerSource 'Setup.manifest')",
        "/win32icon:$(Join-Path $olympusPayload 'assets\olympus.ico')",
        (Join-Path $installerSource 'Setup.cs'), $metadata)
    & $compiler @compilerArgs
    if ($LASTEXITCODE -ne 0) { throw "Building Setup.exe failed ($LASTEXITCODE)." }

    . (Join-Path $olympusSource 'release-signing.ps1')
    $signingPin = Get-OlympusBuildSigningPin
    if ($signingPin) { Set-OlympusArtifactSignature $setupExe (Get-OlympusBuildSigner $signingPin) $signingPin }

    $verificationLog = Join-Path $work 'verify-error.txt'
    $verification = Start-Process -FilePath $setupExe -ArgumentList '--verify-only' -WindowStyle Hidden `
        -RedirectStandardError $verificationLog -Wait -PassThru
    if ($verification.ExitCode -ne 0) {
        $details = (Get-Content -LiteralPath $verificationLog -Raw)
        throw "The installer failed its package verification ($($verification.ExitCode)). $details"
    }

    @'
Olympus for 64-bit Windows

1. Extract this ZIP to a folder using Extract All.
2. Open Setup.exe and follow the prompts. Setup needs administrator access.
3. Select Aegis if you want it to set up DNS filtering on this PC.
4. After setup, open Olympus from the Start menu.

Setup.exe contains the complete app bundle, including Atlas and Aegis.
Packages built on GitHub use the project defaults. Your settings and backups
are separate from this installer.

GitHub-built packages are unsigned. If you previously enabled local Olympus
signing on this PC, build a package from source with your local certificate.

The .zip.sha256 file on the release page gives the SHA-256 checksum for this ZIP.
To compare it before extracting, open PowerShell in the download folder and run:
Get-FileHash .\Olympus-Windows-x64.zip -Algorithm SHA256
'@ | Set-Content -LiteralPath (Join-Path $outer 'Read me.txt') -Encoding ASCII

    $archive = Join-Path $work $zipName
    New-ReleaseArchive $outer $archive
    $checksum = Join-Path $work "$zipName.sha256"
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($checksum, "$hash  $zipName`n", [Text.Encoding]::ASCII)

    $destination = (New-Item -ItemType Directory -Path $OutputDirectory -Force).FullName
    Copy-Item -LiteralPath $archive, $checksum -Destination $destination -Force
    Write-Host "Created $(Join-Path $destination $zipName) and its SHA-256 checksum."
}
finally {
    $env:TEMP = $originalTemp
    $env:TMP = $originalTmp
    $item = Get-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue
    if ($item -and $item.FullName -eq $work -and $item.Parent.FullName -eq $tempRoot.TrimEnd('\') -and
        $item.Name -match '\AOlympusRelease-[0-9a-f]{32}\z' -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        [IO.Directory]::Delete($item.FullName, $true)
    }
}
