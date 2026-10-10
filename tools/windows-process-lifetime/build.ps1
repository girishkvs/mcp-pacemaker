<#
.SYNOPSIS
Builds or verifies the separate Windows process lifetime helper.
.DESCRIPTION
Uses installed Visual Studio Roslyn and .NET Framework 4.6.2 reference assemblies.
Compiles twice under different paths, records every input, and downloads nothing.
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [string]$CompilerPath,
    [string]$ReferenceAssemblyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Digest([string]$Path, [switch]$Text) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($Text) {
        $bytes = [Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText($Path).Replace("`r`n", "`n"))
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

if ($env:OS -ne 'Windows_NT') { throw 'Build on Windows with installed Roslyn and .NET Framework 4.6.2 references.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$directory = Join-Path $root 'bin\windows-lifetime'
$binary = 'ProcessLifetimeHelper.exe'
$metadataPath = Join-Path $directory 'ProcessLifetimeHelper.build.json'
$sources = @('AssemblyInfo.cs', 'ProcessLifetimeHelper.cs')
$references = @('mscorlib.dll', 'System.dll')
if (-not $CompilerPath) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Specify an installed Roslyn -CompilerPath; no tools are installed.' }
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    if ($LASTEXITCODE -ne 0 -or
        -not $installation) { throw 'No installed Visual Studio MSBuild compiler found.' }
    $CompilerPath = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
if (-not $ReferenceAssemblyPath) {
    $ReferenceAssemblyPath = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$CompilerPath = (Resolve-Path -LiteralPath $CompilerPath).Path
$ReferenceAssemblyPath = (Resolve-Path -LiteralPath $ReferenceAssemblyPath).Path
$framework = [xml][IO.File]::ReadAllText((Join-Path $ReferenceAssemblyPath 'RedistList\FrameworkList.xml'))
if ($framework.FileList.Name -cne '.NET Framework 4.6.2') { throw 'Wrong reference assembly targeting pack.' }
$version = (& $CompilerPath /version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Roslyn version probe failed.' }
$options = @('/nologo', '/noconfig', '/nostdlib+', '/target:exe', '/platform:anycpu',
    '/langversion:7.3', '/optimize+', '/debug-', '/deterministic+', '/checked-',
    '/unsafe-', '/warn:4', '/warnaserror+', '/utf8output')
$sourceHashes = [ordered]@{}
foreach ($name in $sources) { $sourceHashes[$name] = Get-Digest (Join-Path $directory "src\$name") -Text }
$referenceHashes = [ordered]@{}
foreach ($name in $references) { $referenceHashes[$name] = Get-Digest (Join-Path $ReferenceAssemblyPath $name) }
$inputs = [ordered]@{
    targetFramework = '.NETFramework,Version=v4.6.2'
    platform = 'AnyCPU'
    compilerVersion = $version
    compilerSha256 = Get-Digest $CompilerPath
    compilerArguments = $options
    pathMap = '/_/mcp-pacemaker/windows-process-lifetime'
    sourceEncoding = 'UTF-8 without BOM, LF line endings'
    sourceSha256 = $sourceHashes
    buildScriptSha256 = Get-Digest $PSCommandPath -Text
    referenceSha256 = $referenceHashes
}
$expected = $null
if ($Verify) {
    $expected = [IO.File]::ReadAllText($metadataPath) | ConvertFrom-Json
    if ($expected.schemaVersion -ne 1 -or
        $expected.binary -cne $binary -or
        (ConvertTo-Json $inputs -Depth 6 -Compress) -cne (ConvertTo-Json $expected.inputs -Depth 6 -Compress) -or
        (Get-Digest (Join-Path $directory $binary)) -cne $expected.binarySha256) {
        throw 'Packaged lifetime helper inputs/toolchain/bytes do not match metadata. Verification changes nothing.'
    }
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mcp-lifetime-build-' + [Guid]::NewGuid().ToString('N'))
$files = [Collections.Generic.List[string]]::new()
$directories = [Collections.Generic.List[string]]::new()
$outputs = [Collections.Generic.List[string]]::new()
try {
    $null = [IO.Directory]::CreateDirectory($temporary)
    $directories.Add($temporary)
    foreach ($pass in @('first', 'second')) {
        $scratch = Join-Path $temporary $pass
        $null = [IO.Directory]::CreateDirectory($scratch)
        $directories.Add($scratch)
        $paths = foreach ($name in $sources) {
            $path = Join-Path $scratch $name
            $files.Add($path)
            $text = [IO.File]::ReadAllText((Join-Path $directory "src\$name")).Replace("`r`n", "`n")
            [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
            $path
        }
        $output = Join-Path $scratch $binary
        $files.Add($output)
        $arguments = $options + @("/out:$output", "/pathmap:$scratch=$($inputs.pathMap)")
        foreach ($name in $references) { $arguments += '/reference:' + (Join-Path $ReferenceAssemblyPath $name) }
        & $CompilerPath @arguments @paths
        if ($LASTEXITCODE -ne 0) { throw "Lifetime helper compile failed: $pass" }
        $outputs.Add($output)
    }
    $digest = Get-Digest $outputs[0]
    if ($digest -cne (Get-Digest $outputs[1])) { throw 'Two builds differ; no package assets changed.' }
    if ($Verify) {
        if ($digest -cne $expected.binarySha256) { throw 'Rebuilt bytes differ; no package assets changed.' }
        Write-Output "Verified lifetime helper source, toolchain and byte-for-byte rebuild: SHA256 $digest"
    } else {
        $metadata = [ordered]@{ schemaVersion = 1; binary = $binary; binarySha256 = $digest; inputs = $inputs }
        [IO.File]::Copy($outputs[0], (Join-Path $directory $binary), $true)
        [IO.File]::WriteAllText($metadataPath,
            (ConvertTo-Json $metadata -Depth 8).Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
        Write-Output "Built two matching lifetime helpers with Roslyn ${version}: SHA256 $digest"
    }
} finally {
    foreach ($path in $files) { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
    for ($index = $directories.Count - 1; $index -ge 0; $index--) { [IO.Directory]::Delete($directories[$index]) }
}
