param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$SourceRoot
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if (-not $SourceRoot) { $SourceRoot = $repo }
$metadata = Get-Content -LiteralPath (Join-Path $SourceRoot 'bin\windows-legacy\LegacyProcessBroker.build.json') -Raw | ConvertFrom-Json
$compiler = $env:MCP_NATIVE_COMPILER
if (-not $compiler) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    $compiler = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
if ((Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant() -cne $metadata.inputs.compilerSha256) { throw 'Recorded compiler required' }
$references = $env:MCP_NATIVE_REFERENCES
if (-not $references) {
    $references = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$arguments = @($metadata.inputs.compilerArguments) + @('/main:CachedEdgeCases', "/out:$OutputDirectory\cached-edge.exe")
foreach ($entry in $metadata.inputs.referenceSha256.PSObject.Properties) {
    $path = Join-Path $references $entry.Name
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value) { throw 'Recorded references required' }
    $arguments += "/reference:$path"
}
$sources = @()
foreach ($name in @('LegacyNative.cs','LegacyProcessBroker.cs')) {
    $text = [IO.File]::ReadAllText((Join-Path $SourceRoot "bin\windows-legacy\src\$name")).Replace("`r`n","`n")
    if ($name -eq 'LegacyNative.cs') {
        $needle = "internal int Parent(SafeProcess process)`n    {"
        $replacement = $needle + "`n        var modeled = CachedEdgeCases.Current.Parent(process);`n        if (modeled.HasValue) return modeled.GetValueOrDefault();"
    } else {
        $needle = "private List<int> Children(int parentId)`n    {"
        $replacement = $needle + "`n        var modeled = CachedEdgeCases.Current.Children(parentId);`n        if (modeled != null) return modeled;"
    }
    if ($text.Split(@($needle),[StringSplitOptions]::None).Length -ne 2) { throw 'Owned metadata injection point changed' }
    $destination = Join-Path $OutputDirectory $name
    [IO.File]::WriteAllText($destination, $text.Replace($needle,$replacement))
    $sources += $destination
}
$sources += Join-Path $PSScriptRoot 'cached-edge-cases.cs'
& $compiler @arguments @sources
if ($LASTEXITCODE -ne 0) { throw 'Owned cached-edge variant build failed' }
