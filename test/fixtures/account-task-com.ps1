<#
.SYNOPSIS
Runs the production account-task adapter against a private in-memory COM boundary.
.PARAMETER Adapter
Exact production script.
.PARAMETER Case
Operation or refusal control to exercise without real task changes.
.OUTPUTS
Sanitized mutation and security evidence.
.EXAMPLE
.\account-task-com.ps1 -Adapter C:\owned\account-task.ps1 -Case bootstrap
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Adapter,
    [ValidateSet('bootstrap', 'hold', 'repoint', 'release', 'restore', 'launch', 'acl-drift', 'owner-drift', 'disabled', 'no-demand', 'wrong-principal')]
    [string]$Case
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'legacy-task-com.ps1') -Adapter $Adapter -TaskOwner builtin-administrators -ModelOnly
$selectedTaskPath = '\McpPacemaker-32190'
$targetSid = $global:LegacyMock.CurrentSid
$global:LegacyMock.RunCalls = 0
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptMethod -Name RunEx -Value {
    param($Parameters, $Flags, $SessionId, $User)
    if ($Flags -ne 12 -or
        $SessionId -ne 2 -or
        $User -cne $global:LegacyMock.CurrentSid) { throw 'RunEx account/session flags changed.' }
    $global:LegacyMock.RunCalls++
    return [pscustomobject]@{ InstanceGuid = 'owned-correlation-only' }
}
function Get-CimInstance {
    param($ClassName, $Filter, $Property, $OperationTimeoutSec)
    if ($ClassName -ne 'Win32_UserProfile') { throw 'Unexpected live query.' }
    return [pscustomobject]@{ SID = $global:LegacyMock.CurrentSid; LocalPath = $env:TEMP; Loaded = $true }
}
function Invoke-OwnedAdapter {
    param([string]$Action, $Body)
    $previous = [Console]::In
    $reader = [IO.StringReader]::new(($Body | ConvertTo-Json -Depth 16 -Compress))
    try {
        [Console]::SetIn($reader)
        return & $Adapter -Action $Action | ConvertFrom-Json
    }
    finally { [Console]::SetIn($previous); $reader.Dispose() }
}
$base = @{ targetSid = $targetSid; taskPath = $selectedTaskPath }
if ($Case -eq 'disabled') { $global:LegacyMock.Definition.Settings.Enabled = $false }
if ($Case -eq 'no-demand') { $global:LegacyMock.Definition.Settings.AllowDemandStart = $false }
$original = (Invoke-OwnedAdapter -Action inspect -Body $base).record
$current = $original
$bootstrap = @{ nodePath = 'C:\trusted\node.exe'; arguments = '"C:\trusted\worker.mjs" --manifest "C:\owned\manifest.json"'; cwd = 'C:\trusted' }
if ($Case -in @('repoint', 'release', 'restore')) {
    $current = Invoke-OwnedAdapter -Action bootstrap -Body ($base + @{ expected = $current; original = $original; bootstrap = $bootstrap })
}
if ($Case -eq 'acl-drift') { $global:LegacyMock.Security = New-Security -Change acl }
if ($Case -eq 'owner-drift') { $global:LegacyMock.Security = New-Security -Change owner-current }
if ($Case -eq 'wrong-principal') { $global:LegacyMock.Definition.Principal.UserId = 'S-1-5-21-1-2-3-1001' }
$before = $global:LegacyMock.Mutations
$beforeSecurity = $global:LegacyMock.Security
$action = switch ($Case) {
    { $_ -in @('disabled', 'no-demand') } { 'launch' }
    { $_ -in @('acl-drift', 'owner-drift', 'wrong-principal') } { 'hold' }
    default { $Case }
}
$ok = $false
$errorText = ''
$result = $null
try {
    $result = Invoke-OwnedAdapter -Action $action -Body ($base + @{
        expected = $current; original = $original; bootstrap = $bootstrap; launcher = 'C:\owned\launcher.vbs'; sessionId = 2
    })
    $ok = $true
}
catch { $errorText = 'Production account adapter refused the owned control.' }
@{
    succeeded = $ok
    error = $errorText
    mutationDelta = $global:LegacyMock.Mutations - $before
    securityUnchanged = $global:LegacyMock.Security -ceq $beforeSecurity
    ownerPreserved = ([Security.AccessControl.RawSecurityDescriptor]::new($global:LegacyMock.Security).Owner.Value -ceq 'S-1-5-32-544')
    runCalls = $global:LegacyMock.RunCalls
    launchNotReadiness = ($null -ne $result -and $result.readinessProven -eq $false)
    principalPreserved = $global:LegacyMock.Definition.Principal.UserId -ceq $targetSid
    xmlRestored = $global:LegacyMock.Definition.XmlText -ceq $original.xml
    flags = $global:LegacyMock.RegistrationFlags
    securitySetterCalled = $global:LegacyMock.SecuritySetterCalled
} | ConvertTo-Json -Depth 5 -Compress
