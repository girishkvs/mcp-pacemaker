param(
    [Parameter(Mandatory)][int]$ProcessId,
    [int]$ParentId,
    [string]$CreationTicks,
    [switch]$StopOwned
)
$ErrorActionPreference = 'Stop'
$process = $null
try {
    try { $process = [Diagnostics.Process]::GetProcessById($ProcessId) }
    catch [ArgumentException] { '{"gone":true}'; return }
    $null = $process.Handle
    if ($process.HasExited) { '{"gone":true}'; return }
    try {
        $created = $process.StartTime.ToUniversalTime()
    } catch {
        if ($process.HasExited) { '{"gone":true}'; return }
        throw
    }
    if ($CreationTicks -and
        $created.Ticks.ToString() -ne $CreationTicks) {
        '{"gone":true,"differentIdentityNotTouched":true}'
        return
    }
    if ($ParentId) {
        $row = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -Property ParentProcessId
        if ($row.ParentProcessId -ne $ParentId) { throw 'Owned parent identity mismatch' }
    }
    if ($StopOwned) {
        if (-not $CreationTicks) { throw 'Refusing termination without captured creation identity' }
        if (-not $process.HasExited) { $process.Kill() }
        if (-not $process.WaitForExit(3000)) { throw 'Owned process did not exit within bounded cleanup' }
    }
    @{ pid = $ProcessId; creationTicks = $created.Ticks.ToString(); creationUtc = $created.ToString('o')
        creationFileTime = $created.ToFileTimeUtc().ToString()
        gone = $process.HasExited } | ConvertTo-Json -Compress
} finally {
    if ($process) { $process.Dispose() }
}
