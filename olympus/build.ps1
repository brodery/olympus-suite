<#
  build.ps1 - compiles the Olympus suite with the C# compiler that ships with Windows
  (.NET Framework 4.8), like Aegis. No admin rights needed.

    assets\   the icons, drawn in code (one .ico per app) and icons-preview.png
    bin\      Olympus.exe, Argus.exe, ... (run them from here to test; install.ps1 copies
              them to C:\Program Files\Olympus, which is what the scheduled tasks run)
    obj\      build helpers and OlympusTests.exe

  -Only Argus,Ark   builds just those apps      -NoTests   skips the unit tests
  -TestsOnly        builds and runs just the unit tests; bin\ stays byte-for-byte as it is
                    (csc builds aren't reproducible, so a full build always differs from an
                    installed release even when nothing changed)
#>
param([string[]]$Only, [switch]$NoTests, [switch]$TestsOnly)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'release-signing.ps1')
if (-not $TestsOnly) {
    $signingPin = Get-OlympusBuildSigningPin
    if ($signingPin) { $buildSigner = Get-OlympusBuildSigner $signingPin }
}
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "C# compiler not found at $csc" }
$src = Join-Path $here 'src'
$bin = Join-Path $here 'bin'
$obj = Join-Path $here 'obj'
$assets = Join-Path $here 'assets'
New-Item -ItemType Directory -Force $bin, $obj, $assets | Out-Null

$common = @(Get-ChildItem (Join-Path $src 'Common') -Filter *.cs | ForEach-Object { $_.FullName })
$refs = @('System.dll', 'System.Core.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Web.Extensions.dll',
          'System.Management.dll', 'System.Security.dll', 'System.IO.Compression.dll', 'System.IO.Compression.FileSystem.dll',
          'Microsoft.VisualBasic.dll', 'System.Xml.dll', 'System.Xml.Linq.dll', 'System.ServiceProcess.dll', 'System.Web.dll') | ForEach-Object { "/r:$_" }
$apps = @('Olympus', 'Ark', 'Argus', 'Sibyl', 'Janus', 'Ares', 'Athena', 'Cerberus', 'Arachne', 'Atlas')

function Invoke-Csc([string[]]$CscArgs) {
    $all = @('/nologo', '/langversion:5', '/optimize+', '/platform:anycpu', '/warn:4') + $refs + $CscArgs
    $out = & $csc @all
    $code = $LASTEXITCODE
    $out | Where-Object { $_ -and $_ -notmatch 'only supports language versions up to C# 5|For more information|go.microsoft.com' } | ForEach-Object { "  $_" }
    if ($code -ne 0) { throw "csc failed ($code)" }
}

# A running program's file can't be overwritten, but it can be renamed: set it aside, then copy.
function Install-Build([string]$From, [string]$To) {
    try { Copy-Item -LiteralPath $From -Destination $To -Force; return }
    catch { if (-not (Test-Path -LiteralPath $To)) { throw } }
    $asideName = '{0}.{1}.old' -f (Split-Path -Leaf $To), (Get-Date -Format 'yyyyMMddHHmmssfff')
    Rename-Item -LiteralPath $To -NewName $asideName
    Copy-Item -LiteralPath $From -Destination $To
    Write-Host "  ($(Split-Path -Leaf $To) was running: the old copy was set aside)"
}
foreach ($old in @(Get-ChildItem $bin -Filter '*.old' -File -ErrorAction SilentlyContinue)) {
    try { Remove-Item -LiteralPath $old.FullName -Force -ErrorAction Stop } catch { }
}

if (-not $TestsOnly) {
    Write-Host 'Drawing the icons...'
    $maker = Join-Path $obj 'IconMaker.exe'
    Invoke-Csc (@('/target:exe', "/out:$maker") + $common + @((Join-Path $src 'Tools\IconMaker.cs')))
    & $maker $assets
    if ($LASTEXITCODE -ne 0) { throw 'drawing the icons failed' }
}

foreach ($app in $apps) {
    if ($TestsOnly -or ($Only -and ($Only -notcontains $app))) { continue }
    $dir = Join-Path $src $app
    if (-not (Test-Path $dir)) { continue }
    Write-Host "Building $app.exe..."
    $files = @(Get-ChildItem $dir -Filter *.cs | ForEach-Object { $_.FullName })
    $out = Join-Path $obj "$app.exe"
    $ico = Join-Path $assets ($app.ToLowerInvariant() + '.ico')
    Invoke-Csc (@('/target:winexe', "/out:$out", "/win32icon:$ico") + $common + $files)
    if ($signingPin) { Set-OlympusArtifactSignature $out $buildSigner $signingPin }
    Install-Build $out (Join-Path $bin "$app.exe")
    foreach ($data in @(Get-ChildItem $dir -Filter *.ini -File)) { Copy-Item -LiteralPath $data.FullName -Destination (Join-Path $bin $data.Name) -Force }
}

$testDir = Join-Path $src 'Tests'
if ((Test-Path $testDir) -and -not $Only) {
    Write-Host 'Building the tests...'
    # Keep unfinished or unregistered apps out of the suite's test executable.
    $testSources = @($testDir) + @($apps | ForEach-Object { Join-Path $src $_ })
    $files = @($testSources | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | ForEach-Object {
        Get-ChildItem -LiteralPath $_ -Filter *.cs -File -Recurse
    } | Where-Object { $_.Name -ne 'AssemblyInfo.cs' } | ForEach-Object { $_.FullName })
    $tests = Join-Path $obj 'OlympusTests.exe'
    Invoke-Csc (@('/target:exe', "/out:$tests", '/define:TESTS', '/main:Olympus.Tests.TestMain') + $common + $files)
    if (-not $NoTests) {
        & $tests
        if ($LASTEXITCODE -ne 0) { throw 'unit tests failed' }
    }
}
Write-Host 'Done.'
