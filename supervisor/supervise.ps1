<#
.SYNOPSIS  Supervisor for the mcp-pacemaker bridge (Windows). Keeps it alive across crashes.
.DESCRIPTION
  Runs bin/mcp-bridge.mjs and restarts it if it exits. Exit code 3 means another bridge is
  already listening on the port, so this supervisor stops (no thrash). Runs until closed.
.PARAMETER Port  Port the bridge listens on (default 8791). Must match your client config.
#>
[CmdletBinding()]
param([int]$Port = 8791)

$ErrorActionPreference = 'Stop'
$bridge = Resolve-Path (Join-Path $PSScriptRoot '..\bin\mcp-bridge.mjs')

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "node is not on PATH. Install Node.js (>=18) and retry."
}

$proc = $null
try {
  while ($true) {
    $proc = Start-Process -FilePath 'node' -ArgumentList @("`"$bridge`"", '--port', $Port) -NoNewWindow -PassThru
    while (-not $proc.WaitForExit(1000)) { }
    if ($proc.ExitCode -eq 3) { break }   # another bridge already running on this port
    Start-Sleep -Seconds 2                # backoff so a crash-loop doesn't spin
  }
}
finally {
  if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
