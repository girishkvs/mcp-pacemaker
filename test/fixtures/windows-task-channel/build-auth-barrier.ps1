param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Destination) { throw 'Exclusive owned destination required.' }
$sourceDirectory = Join-Path $Destination 'bin\windows-task-channel\src'
$toolsDirectory = Join-Path $Destination 'tools\windows-task-channel'
[IO.Directory]::CreateDirectory($sourceDirectory) | Out-Null
[IO.Directory]::CreateDirectory($toolsDirectory) | Out-Null
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $SourceRoot 'bin\windows-task-channel\src') -File) {
    [IO.File]::Copy($file.FullName, (Join-Path $sourceDirectory $file.Name), $false)
}
foreach($path in @('bin/windows-task-channel.mjs','tools/windows-task-channel/build.ps1')) {
    [IO.File]::Copy((Join-Path $SourceRoot $path), (Join-Path $Destination $path), $false)
}
$path = Join-Path $sourceDirectory 'TaskChannelGuard.cs'
$text = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
$field = '    private SessionFact targetSession;'
if ($text.Split($field).Count -ne 2) { throw 'Expected one barrier field insertion point.' }
$text = $text.Replace($field, $field + "`n    private string ownedBarrierDirectory;`n    private Task ownedPeerRead;")
$set = '        Validate(request);'
if ($text.Split($set).Count -ne 2) { throw 'Expected one owned operation binding point.' }
$text = $text.Replace($set, $set + "`n        ownedBarrierDirectory = request.manifestParent;")
if ($text.Contains('var incoming = Task.Run(() => Read(pipe, 16384, true));')) {
    $needle = 'var incoming = Task.Run(() => Read(pipe, 16384, true));'
    $text = $text.Replace($needle, $needle + "`n                    ownedPeerRead = incoming;")
    $needle = 'incoming = Task.Run(() => Read(pipe, 16384, true));'
    # Assign on subsequent reads, without replacing the just-injected declaration again.
    $text = $text.Replace("                            $needle",
        "                            $needle`n                            ownedPeerRead = incoming;")
} else {
    $needle = '        peerRead = Task.Run(ReadPeerFrame);'
    if (-not $text.Contains($needle)) { throw 'Expected fixed typed peer-read assignment.' }
    $text = $text.Replace($needle, $needle + "`n        ownedPeerRead = peerRead;")
}
$needle = "    private void Authorize(int id, bool cross)`n    {"
if ($text.Split($needle).Count -ne 2) { throw 'Expected one authorization barrier insertion point.' }
$barrier = @'
        var entered = Path.Combine(ownedBarrierDirectory, "auth-entered.json");
        File.WriteAllText(entered, new JavaScriptSerializer().Serialize(guardIdentity));
        var release = Path.Combine(ownedBarrierDirectory, "auth-release");
        var state = Path.Combine(ownedBarrierDirectory, "peer-read-state.json");
        var bound = Stopwatch.StartNew();
        while (!File.Exists(release) && bound.ElapsedMilliseconds < 10000)
        {
            if (ownedPeerRead != null && ownedPeerRead.IsCompleted && !File.Exists(state))
                File.WriteAllText(state, new JavaScriptSerializer().Serialize(new {
                    completed = true, faulted = ownedPeerRead.IsFaulted,
                    status = ownedPeerRead.Status.ToString()
                }));
            Thread.Sleep(10);
        }
        if (!File.Exists(release)) throw new InvalidOperationException("OWNED_BARRIER_EXPIRED");
'@
$text = $text.Replace($needle, $needle + "`n" + $barrier)
[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
$buildParameters = @{}
if ($env:MCP_NATIVE_COMPILER) { $buildParameters.CompilerPath = $env:MCP_NATIVE_COMPILER }
if ($env:MCP_NATIVE_REFERENCES) { $buildParameters.ReferenceAssemblyPath = $env:MCP_NATIVE_REFERENCES }
& (Join-Path $toolsDirectory 'build.ps1') @buildParameters
if (-not $?) { throw 'Owned authorization-barrier build failed.' }
