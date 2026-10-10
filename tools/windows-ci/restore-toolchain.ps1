<#
.SYNOPSIS
Restores the hash-pinned Windows CI compiler and reference assemblies.
.DESCRIPTION
Extracts build dependencies into a new private directory without installing tools.
Checks their hashes against all three packaged helpers before returning paths.
.PARAMETER DestinationDirectory
A new directory owned by this CI run or local caller.
.PARAMETER PackageDirectory
Optional offline directory containing the two pinned archives. No download fallback.
.OUTPUTS
An object with CompilerPath, ReferenceAssemblyPath and PackageDirectory.
.EXAMPLE
.\tools\windows-ci\restore-toolchain.ps1 -DestinationDirectory "$env:RUNNER_TEMP\native-toolchain"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DestinationDirectory,
    [string]$PackageDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required for the CI native toolchain.' }
$DestinationDirectory = [IO.Path]::GetFullPath($DestinationDirectory)
if (Test-Path -LiteralPath $DestinationDirectory) { throw 'Toolchain destination must not already exist.' }
if ($DestinationDirectory -match '[\r\n]') { throw 'Invalid toolchain destination.' }
$null = New-Item -ItemType Directory -Path $DestinationDirectory
$downloadPackages = -not $PackageDirectory
if ($downloadPackages) {
    $PackageDirectory = Join-Path $DestinationDirectory 'packages'
    $null = New-Item -ItemType Directory -Path $PackageDirectory
}
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path

function Assert-Digest {
    param([string]$Path, [string]$Expected)
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "SHA256 mismatch for ${Path}: expected $Expected; actual $actual."
    }
}

$packages = @(
    @{
        Name = 'microsoft.net.compilers.toolset.5.9.0.nupkg'
        Url = 'https://api.nuget.org/v3-flatcontainer/microsoft.net.compilers.toolset/5.9.0/microsoft.net.compilers.toolset.5.9.0.nupkg'
        Sha256 = 'b0227910320c5af14d80ec32b5e1a759c1e3cc2ec12e7d9cc8862cf826bd9551'
    },
    @{
        Name = 'net462-4.6.1590.5.cab'
        Url = 'https://download.visualstudio.microsoft.com/download/pr/3e04be02-cc29-4ce0-aea5-2ad7c040b6f9/4d4e304503ea6b2067bc916aded7bd1244e8608c57056afcd6f8e79c99448915/cab1.cab'
        Sha256 = '4d4e304503ea6b2067bc916aded7bd1244e8608c57056afcd6f8e79c99448915'
    }
)
foreach ($package in $packages) {
    $path = Join-Path $PackageDirectory $package.Name
    if ($downloadPackages) {
        Invoke-WebRequest -Uri $package.Url -OutFile $path -TimeoutSec 180
    }
    Assert-Digest -Path $path -Expected $package.Sha256
}

$compilerDirectory = Join-Path $DestinationDirectory 'compiler'
$archive = [IO.Compression.ZipFile]::OpenRead((Join-Path $PackageDirectory $packages[0].Name))
try {
    foreach ($entry in $archive.Entries) {
        if (-not $entry.FullName.StartsWith('tasks/net472/', [StringComparison]::Ordinal)) { continue }
        $relative = $entry.FullName.Substring('tasks/net472/'.Length)
        if (-not $relative) { continue }
        $unsafePath = $relative -match '[:\\]' -or
            $relative -match '(^|/)\.\.?(/|$)' -or
            $relative.StartsWith('/')
        if ($unsafePath) { throw 'Unsafe compiler archive path.' }
        $target = [IO.Path]::GetFullPath((Join-Path $compilerDirectory $relative))
        if (-not $target.StartsWith("$compilerDirectory\", [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Compiler archive path leaves its destination.'
        }
        if ($entry.FullName.EndsWith('/')) {
            $null = [IO.Directory]::CreateDirectory($target)
        } else {
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)
        }
    }
} finally {
    $archive.Dispose()
}

$references = Join-Path $DestinationDirectory 'references'
$null = New-Item -ItemType Directory -Path (Join-Path $references 'RedistList')
# File keys come from the File table in the matching netfx_462mtpack.msi.
$referenceFiles = [ordered]@{
    filE47B05BE2151E8C50A1A7C5E0C02ED99 = 'mscorlib.dll'
    filB899BC76A5AB12F2698B12146A8780A9 = 'System.dll'
    fil49D1E6F7DB166567CAAB18A0FF744ABB = 'System.Core.dll'
    fil5DF50AF908ADAA1A25697FEE88E5A880 = 'System.Management.dll'
    fil5C8EA3D4B207247EBE33C34E9A3A7D45 = 'System.Web.Extensions.dll'
    'frameworklist.xml' = 'RedistList\FrameworkList.xml'
}
foreach ($entry in $referenceFiles.GetEnumerator()) {
    $output = & "$env:SystemRoot\System32\expand.exe" (Join-Path $PackageDirectory $packages[1].Name) "-F:$($entry.Key)" $references
    if ($LASTEXITCODE -ne 0) { throw "Reference extraction failed for $($entry.Value): $output" }
    Move-Item -LiteralPath (Join-Path $references $entry.Key) -Destination (Join-Path $references $entry.Value)
}

$compiler = Join-Path $compilerDirectory 'csc.exe'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$metadataFiles = @(
    'bin\windows-lifetime\ProcessLifetimeHelper.build.json',
    'bin\windows-legacy\LegacyProcessBroker.build.json',
    'bin\windows-task-channel\TaskChannelGuard.build.json'
)
$metadata = foreach ($file in $metadataFiles) {
    Get-Content -LiteralPath (Join-Path $root $file) -Raw | ConvertFrom-Json
}
foreach ($helper in $metadata) {
    Assert-Digest -Path $compiler -Expected $helper.inputs.compilerSha256
    foreach ($reference in $helper.inputs.referenceSha256.PSObject.Properties) {
        Assert-Digest -Path (Join-Path $references $reference.Name) -Expected $reference.Value
    }
}
$version = (& $compiler /version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Pinned compiler version probe failed.' }
foreach ($helper in $metadata) {
    if ($version -cne $helper.inputs.compilerVersion) {
        throw "Compiler version mismatch for $($helper.binary): expected $($helper.inputs.compilerVersion); actual $version."
    }
}
[pscustomobject]@{
    CompilerPath = $compiler
    ReferenceAssemblyPath = $references
    PackageDirectory = $PackageDirectory
}
