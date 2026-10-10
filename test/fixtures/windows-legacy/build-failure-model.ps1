param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$metadata = Get-Content -LiteralPath (Join-Path $root 'bin\windows-legacy\LegacyProcessBroker.build.json') -Raw | ConvertFrom-Json
$compiler = $env:MCP_NATIVE_COMPILER
if (-not $compiler) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    if ($LASTEXITCODE -ne 0 -or
        -not $installation) { throw 'Installed recorded compiler required' }
    $compiler = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
if ((Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant() -cne $metadata.inputs.compilerSha256) {
    throw 'Recorded compiler required'
}
$references = $env:MCP_NATIVE_REFERENCES
if (-not $references) {
    $references = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$arguments = @($metadata.inputs.compilerArguments) + @('/main:FailureDiagnosticsModel', "/out:$OutputDirectory\failure-model.exe")
foreach ($entry in $metadata.inputs.referenceSha256.PSObject.Properties) {
    $path = Join-Path $references $entry.Name
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value) { throw 'Recorded references required' }
    $arguments += "/reference:$path"
}
$sources = @((Join-Path $root 'bin\windows-legacy\src\LegacyNative.cs'),
    (Join-Path $root 'bin\windows-legacy\src\LegacyProcessBroker.cs'),
    (Join-Path $PSScriptRoot 'failure-diagnostics-model.cs'))
& $compiler @arguments @sources
if ($LASTEXITCODE -ne 0) { throw 'Failure diagnostic model build failed' }
