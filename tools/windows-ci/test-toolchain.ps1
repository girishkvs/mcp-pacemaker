<#
.SYNOPSIS
Tests isolated native toolchain restore and fail-closed verification.
.DESCRIPTION
Uses already downloaded archives, hides installed tools, verifies all three helpers,
and compiles the native test fixtures. Keeps results in the caller's private directory.
.PARAMETER PackageDirectory
Directory containing the two pinned archives; this test never downloads packages.
.PARAMETER TestDirectory
A new private directory for extracted tools, invalid inputs and fixture outputs.
.OUTPUTS
Verification and test results.
.EXAMPLE
.\tools\windows-ci\test-toolchain.ps1 -PackageDirectory C:\private\packages -TestDirectory C:\private\checks
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [Parameter(Mandatory)][string]$TestDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $TestDirectory) { throw 'Test directory must not already exist.' }
$null = New-Item -ItemType Directory -Path $TestDirectory
$TestDirectory = (Resolve-Path -LiteralPath $TestDirectory).Path
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))

function Assert-Rejected {
    param([scriptblock]$Operation, [string]$Message)
    $failure = $null
    try { & $Operation } catch { $failure = $_ }
    if (-not $failure -or
        $failure.Exception.Message -notlike "*$Message*") {
        throw "Expected rejection containing '$Message'; actual: $failure"
    }
}

$oldProgramFiles = ${env:ProgramFiles(x86)}
$oldCompiler = $env:MCP_NATIVE_COMPILER
$oldReferences = $env:MCP_NATIVE_REFERENCES
try {
    ${env:ProgramFiles(x86)} = Join-Path $TestDirectory 'no-installed-toolchain'
    $toolchain = & "$PSScriptRoot\restore-toolchain.ps1" -PackageDirectory $PackageDirectory `
        -DestinationDirectory (Join-Path $TestDirectory 'isolated')
    $env:MCP_NATIVE_COMPILER = $toolchain.CompilerPath
    $env:MCP_NATIVE_REFERENCES = $toolchain.ReferenceAssemblyPath

    $helpers = @('windows-process-lifetime', 'windows-legacy', 'windows-task-channel')
    foreach ($helper in $helpers) {
        $build = Join-Path $root "tools\$helper\build.ps1"
        Assert-Rejected -Operation { & $build -Verify } -Message 'CompilerPath'
        & $build -Verify -CompilerPath $toolchain.CompilerPath -ReferenceAssemblyPath $toolchain.ReferenceAssemblyPath
    }
    Write-Output 'PASS: all three pinned rebuilds work without an installed toolchain; default lookup fails closed.'

    $reference = Join-Path $toolchain.ReferenceAssemblyPath 'mscorlib.dll'
    $original = [IO.File]::ReadAllBytes($reference)
    try {
        [IO.File]::WriteAllBytes($reference, $original + [byte]0)
        foreach ($helper in $helpers) {
            $build = Join-Path $root "tools\$helper\build.ps1"
            Assert-Rejected -Operation {
                & $build -Verify -CompilerPath $toolchain.CompilerPath -ReferenceAssemblyPath $toolchain.ReferenceAssemblyPath
            } -Message 'changes nothing'
        }
    } finally {
        [IO.File]::WriteAllBytes($reference, $original)
    }
    Write-Output 'PASS: all three verifiers reject changed references.'

    $packageNames = @('microsoft.net.compilers.toolset.5.9.0.nupkg', 'net462-4.6.1590.5.cab')
    foreach ($badPackage in $packageNames) {
        $badInputs = Join-Path $TestDirectory "invalid-$badPackage"
        $null = New-Item -ItemType Directory -Path $badInputs
        foreach ($name in $packageNames) {
            $target = Join-Path $badInputs $name
            if ($name -eq $badPackage) {
                [IO.File]::WriteAllText($target, 'untrusted package bytes')
            } else {
                Copy-Item -LiteralPath (Join-Path $PackageDirectory $name) -Destination $target
            }
        }
        $destination = Join-Path $badInputs 'restore'
        Assert-Rejected -Operation {
            & "$PSScriptRoot\restore-toolchain.ps1" -PackageDirectory $badInputs -DestinationDirectory $destination
        } -Message "SHA256 mismatch for $(Join-Path $badInputs $badPackage)"
        if (Get-ChildItem -LiteralPath $destination -Force) { throw 'An invalid archive was extracted.' }
    }
    Write-Output 'PASS: both archive integrity failures stop before extraction.'

    $fixtures = @(
        'windows-process-lifetime\build-failure.ps1',
        'windows-legacy\build-bounds-model.ps1',
        'windows-legacy\build-cached-edge.ps1',
        'windows-legacy\build-failure-model.ps1',
        'windows-legacy\build-variant.ps1'
    )
    foreach ($fixture in $fixtures) {
        $output = Join-Path $TestDirectory ([IO.Path]::GetFileNameWithoutExtension($fixture))
        $null = New-Item -ItemType Directory -Path $output
        & (Join-Path $root "test\fixtures\$fixture") -OutputDirectory $output
    }
    & "$root\test\fixtures\windows-task-channel\build-thread-lifecycle.ps1" `
        -Destination (Join-Path $TestDirectory 'ThreadLifecycleHost.exe')
    & "$root\test\fixtures\windows-task-channel\build-context-variant.ps1" -SourceRoot $root `
        -Destination (Join-Path $TestDirectory 'context-variant') -Variant denied
    & "$root\test\fixtures\windows-task-channel\build-auth-barrier.ps1" -SourceRoot $root `
        -Destination (Join-Path $TestDirectory 'auth-barrier')
    & "$root\test\fixtures\windows-task-channel\build-blocked-query.ps1" -SourceRoot $root `
        -Destination (Join-Path $TestDirectory 'blocked-query')
    Write-Output 'PASS: all nine native fixture builders use the pinned paths without installed tools.'
} finally {
    ${env:ProgramFiles(x86)} = $oldProgramFiles
    $env:MCP_NATIVE_COMPILER = $oldCompiler
    $env:MCP_NATIVE_REFERENCES = $oldReferences
}
