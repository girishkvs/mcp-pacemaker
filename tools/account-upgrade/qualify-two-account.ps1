<#
.SYNOPSIS
Runs an explicitly authorized two-account Windows upgrade qualification.
.DESCRIPTION
Requires an existing elevated controller, existing logged-on target account and
existing target task. Does not create accounts, request elevation, change ACLs or
install toolchains. Without Execute it runs only the product's read-only plan.
.PARAMETER TrustedRoot
Existing protected, target-readable controller package directory.
.PARAMETER NodePath
Existing trusted Node executable.
.PARAMETER TargetSid
Canonical SID of the different existing target account.
.PARAMETER TaskPath
Exact existing per-user task.
.PARAMETER Version
Exact target version approved for this qualification.
.PARAMETER ControllerRoot
Existing protected operation-store parent, readable/traversable by the target.
.PARAMETER Registry
Explicit approved registry; use an owned registry for fixture qualification.
.PARAMETER Execute
Runs the interactive product transaction after its read-only plan succeeds.
.OUTPUTS
Product plan and operation results. This script does not attest readiness by itself.
.EXAMPLE
.\qualify-two-account.ps1 -TrustedRoot C:\ExistingProtectedTools\Pacemaker -NodePath C:\ExistingNode\node.exe -TargetSid S-1-5-21-1-2-3-1001 -TaskPath \OwnedPacemakerTask -Version 2.1.0 -ControllerRoot C:\ExistingProtectedOperations -Registry https://approved.example.test/npm/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TrustedRoot,
    [Parameter(Mandatory)][string]$NodePath,
    [Parameter(Mandatory)][string]$TargetSid,
    [Parameter(Mandatory)][string]$TaskPath,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$ControllerRoot,
    [Parameter(Mandatory)][string]$Registry,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows qualification only.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($identity.User.Value -ceq $TargetSid -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use an already-elevated different controller account. This script never elevates.'
}
foreach ($path in @($TrustedRoot, $ControllerRoot)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw 'Required existing protected directory is absent.' }
}
if (-not (Test-Path -LiteralPath $NodePath -PathType Leaf)) { throw 'Required existing Node executable is absent.' }
$cli = Join-Path $TrustedRoot 'bin\cli.mjs'
$arguments = @(
    $cli, '--user', $TargetSid, '--task', $TaskPath, 'upgrade', '--to', $Version,
    '--controller-root', $ControllerRoot, '--registry', $Registry
)
& $NodePath @arguments --plan
if ($LASTEXITCODE -ne 0) { throw 'Read-only account/task/path/session eligibility did not pass.' }
if (-not $Execute) {
    Write-Output 'Plan only. Actual two-account task mutation, original-account runtime and rollback remain NOT RUN.'
    return
}
if ([Console]::IsInputRedirected) { throw 'Interactive confirmation is required; no unattended approval fallback.' }
& $NodePath @arguments
if ($LASTEXITCODE -ne 0) { throw 'Operation did not complete. Preserve both journals; do not force cleanup or replay calls.' }
Write-Output 'Inspect recorded worker/backend SID, session, version, task full-SD continuity, protected state and cleanup receipts before accepting qualification.'
