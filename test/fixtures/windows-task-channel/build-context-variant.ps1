param(
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][ValidateSet('denied','token','churn','layout','binding','query-denied',
        'reuse','no-info','walk','marker-free','snapshot-free','duplicate','empty','count','access-ledger',
        'owner','birth','exit-zero','exit-future','missing-flag','unknown-flags','changed-exit',
        'classification','thread-denied','no-live','end-after-snapshot')][string]$Variant,
    [ValidateSet('cli','facts')][string]$Scope = 'cli',
    [string]$LedgerPath
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Destination) { throw 'Exclusive owned destination required.' }
$src = Join-Path $Destination 'bin\windows-task-channel\src'
$tools = Join-Path $Destination 'tools\windows-task-channel'
[IO.Directory]::CreateDirectory($src) | Out-Null
[IO.Directory]::CreateDirectory($tools) | Out-Null
foreach($file in Get-ChildItem -LiteralPath (Join-Path $SourceRoot 'bin\windows-task-channel\src') -File) {
    [IO.File]::Copy($file.FullName, (Join-Path $src $file.Name), $false)
}
[IO.File]::Copy((Join-Path $SourceRoot 'bin\windows-task-channel.mjs'), (Join-Path $Destination 'bin\windows-task-channel.mjs'), $false)
[IO.File]::Copy((Join-Path $SourceRoot 'tools\windows-task-channel\build.ps1'), (Join-Path $tools 'build.ps1'), $false)
$source = if ($Variant -in @('binding','query-denied','access-ledger')) { 'ChannelCliContext.cs' } else { 'ChannelNative.cs' }
$path = Join-Path $src $source
$text = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
switch ($Variant) {
    'denied' {
        $from = 'uint status = ContextApi.PssCaptureSnapshot(parent, 0x80, 0, out snapshot);'
        $to = 'snapshot = IntPtr.Zero; uint status = 5;'
    }
    'token' {
        $from = 'impersonating |= HasThreadToken(thread);'
        $to = $from + ' impersonating = true;'
    }
    'churn' {
        $from = 'if (!before.Select(entry => entry.threadId).SequenceEqual(after.Select(entry => entry.threadId)) ||'
        $to = 'after.RemoveAt(0); ' + $from
    }
    'layout' {
        $from = 'int entrySize = Marshal.SizeOf(typeof(ContextApi.ThreadEntry));'
        $to = 'int entrySize = Marshal.SizeOf(typeof(ContextApi.ThreadEntry)) + 1;'
    }
    'binding' {
        $from = 'information.parentReserved.ToInt64() == pipeOwner'
        $to = 'information.parentReserved.ToInt64() != pipeOwner'
    }
    'query-denied' {
        $from = 'var handle = ChannelApi.OpenProcess(0x101400, false, pid);'
        $to = 'var handle = new ProcessHandle();'
    }
    'reuse' {
        $from = 'if (!SameThread(before[index], after[index]))'
        $to = 'var changed = after[index]; changed.creation.low++; after[index] = changed; ' + $from
    }
    'no-info' {
        $from = 'status = ContextApi.PssQuerySnapshot(snapshot, 5, out information, (uint)Marshal.SizeOf(information));'
        $to = $from + ' status = 5;'
    }
    'walk' {
        $from = 'status = ContextApi.PssWalkSnapshot(snapshot, 3, marker, out entry, (uint)entrySize);'
        $to = $from + ' status = 5;'
    }
    'marker-free' {
        $from = 'finally { RequireSnapshotStatus(ContextApi.PssWalkMarkerFree(marker)); }'
        $to = 'finally { RequireSnapshotStatus(ContextApi.PssWalkMarkerFree(marker)); RequireSnapshotStatus(5); }'
    }
    'snapshot-free' {
        $from = 'finally { RequireSnapshotStatus(ContextApi.PssFreeSnapshot(ContextApi.GetCurrentProcess(), snapshot)); }'
        $to = 'finally { RequireSnapshotStatus(ContextApi.PssFreeSnapshot(ContextApi.GetCurrentProcess(), snapshot)); RequireSnapshotStatus(5); }'
    }
    'duplicate' {
        $from = 'entries.Any(previous => previous.threadId == entry.threadId) ||'
        $to = 'entries.Count > 0 ||'
    }
    'empty' {
        $from = 'if (information.count < 1 ||'
        $to = 'information.count = 0; ' + $from
    }
    'count' {
        $from = 'if (entries.Count != information.count)'
        $to = 'information.count++; ' + $from
    }
    'owner' {
        $from = 'entries.Add(entry);'
        $to = 'entry.processId++; ' + $from
    }
    'birth' {
        $from = 'entries.Add(entry);'
        $to = 'entry.creation.low++; ' + $from
    }
    'exit-zero' {
        $from = 'entries.Add(entry);'
        $to = 'entry.flags = 1; entry.exit = new ContextApi.FileTime(); ' + $from
    }
    'exit-future' {
        $from = 'entries.Add(entry);'
        $to = 'entry.flags = 1; entry.exit.low = uint.MaxValue; entry.exit.high = int.MaxValue; ' + $from
    }
    'missing-flag' {
        $from = 'entries.Add(entry);'
        $to = 'entry.flags = 0; entry.exit = entry.creation; ' + $from
    }
    'unknown-flags' {
        $from = 'entries.Add(entry);'
        $to = 'entry.flags |= 2; ' + $from
    }
    'changed-exit' {
        $from = 'if (!SameThread(before[index], after[index]))'
        $to = 'var changed = after[index]; changed.exit.low++; after[index] = changed; ' + $from
    }
    'classification' {
        $from = 'if (!SameThread(before[index], after[index]))'
        $to = 'var changed = after[index]; changed.flags ^= 1; after[index] = changed; ' + $from
    }
    'thread-denied' {
        $from = 'var thread = ContextApi.OpenThread(0x100040, false, entry.threadId);'
        $to = 'var thread = new ProcessHandle();'
    }
    'no-live' {
        $from = 'if (liveCount == 0)'
        $to = 'liveCount = 0; ' + $from
    }
    'end-after-snapshot' {
        if (-not $LedgerPath) { throw 'Owned lifecycle barrier path required.' }
        $literal = $LedgerPath.Replace('"', '""')
        $from = 'var before = CaptureThreads(process, checkpoint, out began);'
        $to = $from + @"

        System.IO.File.WriteAllText(@"$literal.entered", "first-capture-complete");
        var barrier = System.Diagnostics.Stopwatch.StartNew();
        while (!System.IO.File.Exists(@"$literal.ended") && barrier.ElapsedMilliseconds < 5000)
            System.Threading.Thread.Sleep(10);
        if (!System.IO.File.Exists(@"$literal.ended")) throw new InvalidOperationException("OWNED_LIFECYCLE_BARRIER_EXPIRED");
"@
    }
    'access-ledger' {
        if (-not $LedgerPath -or
            (Test-Path -LiteralPath $LedgerPath)) { throw 'New owned ledger prefix required.' }
        $literal = $LedgerPath.Replace('"', '""')
        $record = 'System.IO.File.AppendAllText(@"' + $literal + '" + "." + System.Diagnostics.Process.GetCurrentProcess().Id, '
        $from = 'var handle = ChannelApi.OpenProcess(0x101400, false, pid);'
        $to = $record + '"capture|" + pid + "|0x101400\n"); ' + $from
        $nativePath = Join-Path $src 'ChannelNative.cs'
        $nativeText = [IO.File]::ReadAllText($nativePath).Replace("`r`n", "`n")
        $open = 'var handle = ChannelApi.OpenProcess(0x101000, false, pid);'
        $capture = 'uint status = ContextApi.PssCaptureSnapshot(parent, 0x80, 0, out snapshot);'
        if (-not $nativeText.Contains($open) -or
            -not $nativeText.Contains($capture)) { throw 'Missing native access ledger anchors.' }
        $nativeText = $nativeText.Replace($open, $record + '"limited|" + pid + "|0x101000\n"); ' + $open)
        $nativeText = $nativeText.Replace($capture,
            $record + '"snapshot|" + ChannelApi.GetProcessId(parent) + "|0x80\n"); ' + $capture)
        [IO.File]::WriteAllText($nativePath, $nativeText, [Text.UTF8Encoding]::new($false))
    }
}
if (-not $text.Contains($from)) { throw 'Missing explicit test-only injection point.' }
$text = $text.Replace($from, $to)
[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
$buildParameters = @{}
if ($env:MCP_NATIVE_COMPILER) { $buildParameters.CompilerPath = $env:MCP_NATIVE_COMPILER }
if ($env:MCP_NATIVE_REFERENCES) { $buildParameters.ReferenceAssemblyPath = $env:MCP_NATIVE_REFERENCES }
& (Join-Path $tools 'build.ps1') @buildParameters
if (-not $?) { throw 'Owned context variant build failed.' }
