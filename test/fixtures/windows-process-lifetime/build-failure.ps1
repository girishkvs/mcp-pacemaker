# TEST-SETUP: compile a real failing native call only into the caller's owned temp root.
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateSet('assignment-failure', 'zero-exit', 'protocol')][string]$Variant = 'assignment-failure'
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$metadata = [IO.File]::ReadAllText((Join-Path $root 'bin\windows-lifetime\ProcessLifetimeHelper.build.json')) | ConvertFrom-Json
$compiler = $env:MCP_NATIVE_COMPILER
if (-not $compiler) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    if ($LASTEXITCODE -ne 0 -or
        -not $installation) { throw 'Installed recorded Roslyn compiler required for native failure test' }
    $compiler = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
if ((Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.inputs.compilerSha256) {
    throw 'Native failure fixture requires the recorded trusted compiler'
}
$references = $env:MCP_NATIVE_REFERENCES
if (-not $references) {
    $references = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$arguments = @($metadata.inputs.compilerArguments)
foreach ($name in @('mscorlib.dll', 'System.dll')) {
    $path = Join-Path $references $name
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.inputs.referenceSha256.$name) {
        throw 'Native failure fixture reference mismatch'
    }
    $arguments += "/reference:$path"
}
if ($Variant -eq 'zero-exit') {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'TerminateOwned.cs'))
} else {
    $source = [IO.File]::ReadAllText((Join-Path $root 'bin\windows-lifetime\src\ProcessLifetimeHelper.cs'))
    $needle = 'Require(Native.AssignProcessToJobObject(job, parent));'
    if ($source.Split(@($needle), [StringSplitOptions]::None).Length -ne 2) { throw 'Failure injection point changed' }
    if ($Variant -eq 'protocol') {
        $source = $source.Replace($needle, '// TEST ONLY: no assignment, no workload is started.')
        $membership = 'Require(Native.IsProcessInJob(parent, job, out member));'
        if (-not $source.Contains($membership)) { throw 'Membership test injection point changed' }
        $source = $source.Replace($membership, 'member = true;')
        $observer = 'return helper.ObserveOwner(args);'
        if (-not $source.Contains($observer)) { throw 'Observer test injection point changed' }
        $source = $source.Replace($observer,
            'Console.Out.WriteLine("MCP_JOB_OBSERVER_READY"); Console.Out.WriteLine("MCP_JOB_DRAINED"); return 0;')
    } else {
        $source = $source.Replace($needle, 'Require(Native.AssignProcessToJobObject(new SafeNativeHandle(), parent));')
    }
}
$sourcePath = Join-Path $OutputDirectory "$Variant.cs"
$binary = Join-Path $OutputDirectory "$Variant.exe"
[IO.File]::WriteAllText($sourcePath, $source)
$arguments += "/out:$binary"
& $compiler @arguments $sourcePath
if ($LASTEXITCODE -ne 0) { throw 'Native failure fixture compilation failed' }
Write-Output $binary
