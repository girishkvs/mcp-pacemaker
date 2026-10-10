param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$Destination, [switch]$DisableMonitor)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Destination) { throw 'Exclusive owned destination required.' }
$sourceDirectory = Join-Path $Destination 'bin\windows-task-channel\src'
$toolsDirectory = Join-Path $Destination 'tools\windows-task-channel'
[IO.Directory]::CreateDirectory($sourceDirectory) | Out-Null
[IO.Directory]::CreateDirectory($toolsDirectory) | Out-Null
foreach ($source in Get-ChildItem -LiteralPath (Join-Path $SourceRoot 'bin\windows-task-channel\src') -File) {
    [IO.File]::Copy($source.FullName, (Join-Path $sourceDirectory $source.Name), $false)
}
[IO.File]::Copy((Join-Path $SourceRoot 'bin\windows-task-channel.mjs'),
    (Join-Path $Destination 'bin\windows-task-channel.mjs'), $false)
[IO.File]::Copy((Join-Path $SourceRoot 'tools\windows-task-channel\build.ps1'),
    (Join-Path $toolsDirectory 'build.ps1'), $false)
$path = Join-Path $sourceDirectory 'ChannelFiles.cs'
$text = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
$needle = '        int directories = 0, files = 0;'
if ($text.Split($needle).Count -ne 2) { throw 'Expected one test-only injection point.' }
$injection = @'
        int ownedPid = System.Diagnostics.Process.GetCurrentProcess().Id;
        using (var ownedProcess = native.Open(ownedPid))
            File.WriteAllText(Path.Combine(root, "owned-query-entered.json"),
                new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(native.Identity(ownedPid, ownedProcess)));
        System.Threading.Thread.Sleep(30000);
'@
$text = $text.Replace($needle, $injection + "`n" + $needle)
[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
if ($DisableMonitor) {
    $guard = Join-Path $sourceDirectory 'TaskChannelGuard.cs'
    $text = [IO.File]::ReadAllText($guard).Replace("`r`n", "`n")
    $needle = '        monitor.Start();'
    if ($text.Split($needle).Count -ne 2) { throw 'Expected one test-only watchdog failure injection point.' }
    $text = $text.Replace($needle, '        // Owned test-only watchdog failure; not a shipped option.')
    [IO.File]::WriteAllText($guard, $text, [Text.UTF8Encoding]::new($false))
}
$buildParameters = @{}
if ($env:MCP_NATIVE_COMPILER) { $buildParameters.CompilerPath = $env:MCP_NATIVE_COMPILER }
if ($env:MCP_NATIVE_REFERENCES) { $buildParameters.ReferenceAssemblyPath = $env:MCP_NATIVE_REFERENCES }
& (Join-Path $toolsDirectory 'build.ps1') @buildParameters
if (-not $?) { throw 'Owned blocked-query build failed.' }
