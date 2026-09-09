<#
.SYNOPSIS
Builds or verifies the packaged Windows security helper.
.DESCRIPTION
Uses installed Visual Studio Roslyn and .NET Framework 4.6.2 reference assemblies.
Builds twice in temporary directories and requires identical bytes. No tools are downloaded.
.PARAMETER Verify
Checks source, build script, toolchain, references, and rebuilt bytes against packaged metadata.
Does not replace packaged files.
.PARAMETER CompilerPath
Optional installed Roslyn csc.exe path. Otherwise discovers the newest Visual Studio with MSBuild.
.PARAMETER ReferenceAssemblyPath
Optional directory containing the .NET Framework 4.6.2 reference assemblies.
.OUTPUTS
Build or verification status and the executable SHA256.
.EXAMPLE
.\tools\windows-security-helper\build.ps1
.EXAMPLE
.\tools\windows-security-helper\build.ps1 -Verify
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [string]$CompilerPath,
    [string]$ReferenceAssemblyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SourceHash {
    param([Parameter(Mandatory)][string]$Path)

    $text = [System.IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        return [System.BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hash.Dispose()
    }
}

function Get-BinaryHash {
    param([Parameter(Mandatory)][string]$Path)

    $hash = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        return [System.BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        if ($stream) {
            $stream.Dispose()
        }

        $hash.Dispose()
    }
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Build on Windows with installed Visual Studio Roslyn and the .NET Framework 4.6.2 targeting pack.'
}

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$binaryDirectory = Join-Path $root 'bin\windows'
$sourceDirectory = Join-Path $binaryDirectory 'src'
$binaryName = 'PoolingSecurityHelper.exe'
$binaryPath = Join-Path $binaryDirectory $binaryName
$metadataPath = Join-Path $binaryDirectory 'PoolingSecurityHelper.build.json'
$sourceNames = @('AssemblyInfo.cs', 'PoolingSecurityReader.cs', 'PoolingSecurityHelper.cs')
$referenceNames = @('mscorlib.dll', 'System.dll')

if (-not $CompilerPath) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -ne 0) {
            throw 'vswhere failed. Specify -CompilerPath with an installed Visual Studio Roslyn csc.exe.'
        }

        if ($installation) {
            $CompilerPath = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
        }
    }

    if (-not $CompilerPath) {
        $CompilerPath = Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe'
    }
}

if (-not (Test-Path -LiteralPath $CompilerPath -PathType Leaf)) {
    throw 'Roslyn csc.exe was not found. Install Visual Studio/Build Tools with MSBuild, or specify -CompilerPath. The Windows Framework csc.exe is too old.'
}

$CompilerPath = (Resolve-Path -LiteralPath $CompilerPath).Path
$compilerVersion = (& $CompilerPath /version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Roslyn csc.exe /version failed.'
}

$compilerHelp = @(& $CompilerPath /help)
$hasDeterministic = @($compilerHelp | Where-Object { $_.Trim().StartsWith('-deterministic ') }).Length -gt 0
$hasPathMap = @($compilerHelp | Where-Object { $_.Trim().StartsWith('-pathmap:') }).Length -gt 0
if ($LASTEXITCODE -ne 0 -or
    -not $hasDeterministic -or
    -not $hasPathMap) {
    throw 'The installed compiler must support /deterministic and /pathmap.'
}

if (-not $ReferenceAssemblyPath) {
    $ReferenceAssemblyPath = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}

foreach ($name in $referenceNames) {
    if (-not (Test-Path -LiteralPath (Join-Path $ReferenceAssemblyPath $name) -PathType Leaf)) {
        throw "Missing .NET Framework 4.6.2 reference assembly: $name. Install its targeting pack, or specify -ReferenceAssemblyPath."
    }
}

$ReferenceAssemblyPath = (Resolve-Path -LiteralPath $ReferenceAssemblyPath).Path
$frameworkListPath = Join-Path $ReferenceAssemblyPath 'RedistList\FrameworkList.xml'
if (-not (Test-Path -LiteralPath $frameworkListPath -PathType Leaf)) {
    throw 'The reference directory must contain the .NET Framework 4.6.2 targeting pack, including RedistList\FrameworkList.xml.'
}

$frameworkList = [xml](Get-Content -LiteralPath $frameworkListPath -Raw)
if ($frameworkList.FileList.Name -cne '.NET Framework 4.6.2') {
    throw 'The reference directory is not the .NET Framework 4.6.2 targeting pack.'
}

$compilerArguments = @(
    '/nologo',
    '/noconfig',
    '/nostdlib+',
    '/target:exe',
    '/platform:anycpu',
    '/langversion:7.3',
    '/optimize+',
    '/debug-',
    '/deterministic+',
    '/checked-',
    '/unsafe-',
    '/warn:4',
    '/warnaserror+',
    '/utf8output'
)
$sourceHashes = [ordered]@{}
foreach ($name in $sourceNames) {
    $sourceHashes[$name] = Get-SourceHash -Path (Join-Path $sourceDirectory $name)
}

$referenceHashes = [ordered]@{}
foreach ($name in $referenceNames) {
    $referenceHashes[$name] = Get-BinaryHash -Path (Join-Path $ReferenceAssemblyPath $name)
}

$inputs = [ordered]@{
    targetFramework = '.NETFramework,Version=v4.6.2'
    platform = 'AnyCPU'
    compilerVersion = $compilerVersion
    compilerSha256 = Get-BinaryHash -Path $CompilerPath
    compilerArguments = $compilerArguments
    pathMap = '/_/mcp-pacemaker/windows-security-helper'
    sourceEncoding = 'UTF-8 without BOM, LF line endings'
    sourceSha256 = $sourceHashes
    buildScriptSha256 = Get-SourceHash -Path $PSCommandPath
    referenceSha256 = $referenceHashes
}
$inputsJson = $inputs | ConvertTo-Json -Depth 5 -Compress
$expectedMetadata = $null
if ($Verify) {
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw 'Packaged helper metadata is missing. Build and review the helper before verification.'
    }

    $expectedMetadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ($expectedMetadata.schemaVersion -ne 1 -or
        $expectedMetadata.binary -cne $binaryName) {
        throw 'The packaged helper metadata schema or executable name is invalid.'
    }

    $expectedInputsJson = $expectedMetadata.inputs | ConvertTo-Json -Depth 5 -Compress
    if ($inputsJson -cne $expectedInputsJson) {
        throw "Source/build inputs differ from metadata. Expected Roslyn $($expectedMetadata.inputs.compilerVersion) and the recorded compiler/reference hashes. Current Roslyn: $compilerVersion. Use the recorded toolchain, or explicitly rebuild and review changed assets."
    }

    if ((Get-BinaryHash -Path $binaryPath) -cne $expectedMetadata.binarySha256) {
        throw 'The packaged helper SHA256 does not match its metadata.'
    }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mcp-security-build-' + [Guid]::NewGuid().ToString('N'))
$createdFiles = [System.Collections.Generic.List[string]]::new()
$createdDirectories = [System.Collections.Generic.List[string]]::new()
$outputs = [System.Collections.Generic.List[string]]::new()
try {
    [System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    $createdDirectories.Add($temporaryRoot)
    foreach ($pass in @('first', 'second')) {
        $passDirectory = Join-Path $temporaryRoot $pass
        [System.IO.Directory]::CreateDirectory($passDirectory) | Out-Null
        $createdDirectories.Add($passDirectory)
        $sourcePaths = foreach ($name in $sourceNames) {
            $sourcePath = Join-Path $passDirectory $name
            $text = [System.IO.File]::ReadAllText((Join-Path $sourceDirectory $name)).Replace("`r`n", "`n")
            $createdFiles.Add($sourcePath)
            [System.IO.File]::WriteAllText($sourcePath, $text, [System.Text.UTF8Encoding]::new($false))
            $sourcePath
        }

        $output = Join-Path $passDirectory $binaryName
        $createdFiles.Add($output)
        $arguments = $compilerArguments + @("/out:$output", "/pathmap:$passDirectory=$($inputs.pathMap)")
        foreach ($name in $referenceNames) {
            $arguments += '/reference:' + (Join-Path $ReferenceAssemblyPath $name)
        }

        & $CompilerPath @arguments @sourcePaths
        if ($LASTEXITCODE -ne 0) {
            throw "Windows security helper compilation failed on pass $pass."
        }

        $outputs.Add($output)
    }

    $binaryHash = Get-BinaryHash -Path $outputs[0]
    if ($binaryHash -cne (Get-BinaryHash -Path $outputs[1])) {
        throw 'Two builds produced different bytes. No packaged files were updated.'
    }

    if ($Verify) {
        if ($binaryHash -cne $expectedMetadata.binarySha256) {
            throw 'The deterministic rebuild does not match the packaged helper. No packaged files were updated.'
        }

        Write-Output "Verified source, toolchain and byte-for-byte rebuild: SHA256 $binaryHash"
    }
    else {
        $metadata = [ordered]@{
            schemaVersion = 1
            binary = $binaryName
            binarySha256 = $binaryHash
            inputs = $inputs
        }
        $metadataJson = ($metadata | ConvertTo-Json -Depth 6).Replace("`r`n", "`n") + "`n"
        [System.IO.File]::Copy($outputs[0], $binaryPath, $true)
        [System.IO.File]::WriteAllText($metadataPath, $metadataJson, [System.Text.UTF8Encoding]::new($false))
        Write-Output "Built two matching executables with Roslyn ${compilerVersion}: SHA256 $binaryHash"
    }
}
finally {
    foreach ($path in $createdFiles) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }

    for ($index = $createdDirectories.Count - 1; $index -ge 0; $index--) {
        [System.IO.Directory]::Delete($createdDirectories[$index])
    }
}
