# mcp-pacemaker bootstrap (Windows). Imports your client servers, wires the client, starts the bridge.
# Usage: .\install.ps1 [-Client vscode|cursor|claude] [-Port 8791]
[CmdletBinding()]
param([string]$Client = 'vscode', [int]$Port = 8791)

$ErrorActionPreference = 'Stop'
$cli = Join-Path $PSScriptRoot 'bin\cli.mjs'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'node is not on PATH. Install Node.js (>=20).' }
& node -e "if (Number(process.versions.node.split('.')[0]) < 20) process.exit(1)"
if ($LASTEXITCODE -ne 0) { throw 'Node.js >=20 is required.' }

node "$cli" import  --from $Client
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node "$cli" install --client $Client --port $Port
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node "$cli" status
exit $LASTEXITCODE
