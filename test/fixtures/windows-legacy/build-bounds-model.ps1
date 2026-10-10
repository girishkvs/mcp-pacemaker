param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$metadata = Get-Content -LiteralPath (Join-Path $root 'bin\windows-legacy\LegacyProcessBroker.build.json') -Raw | ConvertFrom-Json
$compiler = $env:MCP_NATIVE_COMPILER
if (-not $compiler) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    $compiler = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
if ((Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant() -cne $metadata.inputs.compilerSha256) {
    throw 'Installed compiler differs from the recorded compiler.'
}
$references = $env:MCP_NATIVE_REFERENCES
if (-not $references) {
    $references = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$arguments = @($metadata.inputs.compilerArguments) + @('/main:BoundsModel', "/out:$OutputDirectory\bounds-model.exe")
foreach ($entry in $metadata.inputs.referenceSha256.PSObject.Properties) {
    $reference = Join-Path $references $entry.Name
    if ((Get-FileHash -LiteralPath $reference -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value) {
        throw 'Reference assembly differs from the recorded input.'
    }
    $arguments += "/reference:$reference"
}
$sources = @((Join-Path $PSScriptRoot 'bounds-model.cs'))
foreach ($name in @('LegacyNative.cs','LegacyProcessBroker.cs')) {
    $sources += Join-Path $root "bin\windows-legacy\src\$name"
}
& $compiler @arguments @sources
if ($LASTEXITCODE -ne 0) { throw 'Owned bounds model build failed.' }
