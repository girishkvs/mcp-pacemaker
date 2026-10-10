<#
.SYNOPSIS
Launches the CI worker through the existing Windows desktop broker.
.DESCRIPTION
Uses the desktop open verb without changing tokens or machine policy. The worker
starts the explicit Node executable with only the supplied non-secret environment.
.PARAMETER InputDirectory
New private run directory created by ordinary-run.mjs.
.PARAMETER Worker
Internal desktop-child role; the native Node caller check still applies.
.OUTPUTS
The desktop child writes a bounded bootstrap exit receipt in InputDirectory.
.EXAMPLE
.\tools\windows-ci\ordinary-desktop.ps1 -InputDirectory C:\private\ordinary-run
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputDirectory,
    [switch]$Worker
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputPath = Join-Path $InputDirectory 'input.json'
$inputRecord = Get-Content -LiteralPath $inputPath -Raw | ConvertFrom-Json
if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $inputRecord.startDeadline) {
    throw 'Ordinary desktop startup deadline expired.'
}
if (($InputDirectory + $PSCommandPath + $inputRecord.node) -match '["\r\n]') {
    throw 'Unsupported ordinary-launch path.'
}
if (-not $Worker) {
    $shell = New-Object -ComObject Shell.Application
    $location = 0
    $locationRoot = 0
    $windowHandle = 0
    $desktop = $shell.Windows().FindWindowSW([ref]$location, [ref]$locationRoot, 8, [ref]$windowHandle, 1)
    if ($null -eq $desktop) { throw 'Existing desktop broker unavailable; no administrator fallback.' }
    if ($null -eq $desktop.Document.Application) { throw 'Existing desktop broker unavailable; no administrator fallback.' }
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = "-NoProfile -NonInteractive -File `"$PSCommandPath`" -InputDirectory `"$InputDirectory`" -Worker"
    $desktop.Document.Application.ShellExecute($powershell, $arguments, $inputRecord.cwd, 'open', 0)
    return
}

$allowed = @('PATH', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'OS', 'ProgramFiles',
    'ProgramFiles(x86)', 'ProgramData', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA',
    'TEMP', 'TMP', 'CI', 'MCP_NATIVE_COMPILER', 'MCP_NATIVE_REFERENCES', 'MCP_POOLING_TRACE_RUN_FAULTS')
$process = [Diagnostics.Process]::new()
$stdout = $null
$stderr = $null
$started = $false
$receipt = [ordered]@{ runId = $inputRecord.runId; exitCode = $null; error = $null }
try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $inputRecord.node
    $start.Arguments = "`"$(Join-Path $PSScriptRoot 'ordinary-run.mjs')`" --worker `"$InputDirectory`""
    $start.WorkingDirectory = $inputRecord.cwd
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables.Clear()
    foreach ($entry in $inputRecord.environment.PSObject.Properties) {
        if ($entry.Name -cnotin $allowed) { throw 'Unexpected environment key in ordinary launch input.' }
        $start.EnvironmentVariables[$entry.Name] = [string]$entry.Value
    }
    $process.StartInfo = $start
    $stdout = [IO.File]::Open((Join-Path $InputDirectory 'bootstrap.stdout'), [IO.FileMode]::CreateNew)
    $stderr = [IO.File]::Open((Join-Path $InputDirectory 'bootstrap.stderr'), [IO.FileMode]::CreateNew)
    if (-not $process.Start()) { throw 'Ordinary Node process did not start.' }
    $started = $true
    $copyOut = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $copyErr = $process.StandardError.BaseStream.CopyToAsync($stderr)
    $remaining = $inputRecord.deadline - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 15000
    $wait = [int][Math]::Max(1, [Math]::Min($remaining, 3615000))
    if (-not $process.WaitForExit($wait)) {
        $process.Kill()
        if (-not $process.WaitForExit(10000)) { throw 'Owned Node process did not exit after bootstrap timeout.' }
        throw 'Ordinary Node bootstrap completion deadline exceeded.'
    }
    if (-not [Threading.Tasks.Task]::WaitAll(@($copyOut, $copyErr), 10000)) {
        throw 'Ordinary bootstrap output did not close.'
    }
    $receipt.exitCode = $process.ExitCode
} catch {
    $receipt.error = $_.Exception.Message
    if ($started -and
        -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(10000)) { $receipt.error += '; owned Node exit is unverified.' }
    }
} finally {
    if ($null -ne $stdout) { $stdout.Dispose() }
    if ($null -ne $stderr) { $stderr.Dispose() }
    $process.Dispose()
    $temporary = Join-Path $InputDirectory 'bootstrap.json.tmp'
    [IO.File]::WriteAllText($temporary, ($receipt | ConvertTo-Json -Compress))
    Move-Item -LiteralPath $temporary -Destination (Join-Path $InputDirectory 'bootstrap.json')
}
