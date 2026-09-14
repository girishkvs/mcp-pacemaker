<#
.SYNOPSIS  Supervisor for the mcp-pacemaker bridge (Windows). Keeps it alive across crashes.
.DESCRIPTION
  Runs the managed supervisor. A targeted CLI stop holds automatic restarts until an
  explicit CLI start. Node.js 20 or newer must be on PATH.
.PARAMETER Port  Port the bridge listens on (default 8791). Must match your client config.
.OUTPUTS
  Supervisor diagnostics.
.EXAMPLE
  .\supervise.ps1 -Port 8791
#>
[CmdletBinding()]
param([ValidateRange(1, 65535)][int]$Port = 8791)

$ErrorActionPreference = 'Stop'
$supervisor = Join-Path -Path $PSScriptRoot -ChildPath 'supervise.mjs'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "node is not on PATH. Install Node.js (>=20) and retry."
}

& node $supervisor --port $Port
exit $LASTEXITCODE
