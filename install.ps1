# mcp-pacemaker bootstrap (Windows). Imports your client servers, wires the client, starts the bridge.
# Usage: .\install.ps1 [-Client vscode|cursor|claude] [-Port 8791]
[CmdletBinding()]
param([string]$Client = 'vscode', [int]$Port = 8791)

$ErrorActionPreference = 'Stop'
$cli = Join-Path $PSScriptRoot 'bin\cli.mjs'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'node is not on PATH. Install Node.js (>=18).' }

node "$cli" import  --from $Client
node "$cli" install --client $Client --port $Port
node "$cli" status
