param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Destination) { throw 'New owned executable path required.' }
$compiler = $env:MCP_NATIVE_COMPILER
if (-not $compiler) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    if (-not $installation) { throw 'Installed compiler required; no downloads.' }
    $compiler = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
$refs = $env:MCP_NATIVE_REFERENCES
if (-not $refs) {
    $refs = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$options = @('/nologo','/noconfig','/nostdlib+','/target:exe','/platform:anycpu','/langversion:7.3',
    '/optimize+','/debug-','/deterministic+','/warnaserror+',"/out:$Destination")
foreach ($name in @('mscorlib.dll','System.dll','System.Core.dll','System.Web.Extensions.dll')) {
    $options += '/reference:' + (Join-Path $refs $name)
}
& $compiler @options (Join-Path $PSScriptRoot 'ThreadLifecycleHost.cs')
if ($LASTEXITCODE -ne 0) { throw 'Owned thread lifecycle fixture build failed.' }
Get-FileHash -LiteralPath $Destination | Select-Object Hash
