<#
.SYNOPSIS
Exercises legacy-access.ps1 functions against owned descriptors and the in-memory task model.
.DESCRIPTION
Reads one JSON request from standard input. No real task, file owner or ACL is changed.
Descriptors use {U} for the current user SID; outputs replace that SID with {U} again.
.PARAMETER Mode
rights evaluates allowed rights; grant runs the task access change on a modeled task;
report builds an access report through the modeled Schedule.Service.
.OUTPUTS
Sanitized JSON evidence.
.EXAMPLE
'{"cases":{"x":"O:BAG:BAD:(A;;FA;;;{U})"}}' | .\legacy-access-functions.ps1 -Mode rights
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('rights', 'grant', 'report')]
    [string]$Mode
)
$ErrorActionPreference = 'Stop'
$fixtureMode = $Mode
$fixtureRequest = [Console]::In.ReadToEnd() | ConvertFrom-Json
$fixtureUser = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$accessScript = Join-Path $PSScriptRoot '..\..\autostart\windows\legacy-access.ps1'

function Expand-Sddl([string]$Value) { return $Value.Replace('{U}', $fixtureUser) }

if ($fixtureMode -eq 'rights') {
    . $accessScript -Operation inspect -Port 1 -CliPath 'C:\unused\bin\cli.mjs' -FunctionsOnly
    $results = [ordered]@{}
    foreach ($case in $fixtureRequest.cases.PSObject.Properties) {
        $results[$case.Name] = (Get-AllowedRights -Sddl (Expand-Sddl $case.Value)).Allowed
    }
    $results | ConvertTo-Json -Compress
    return
}

if ($fixtureMode -eq 'grant') {
    . $accessScript -Operation inspect -Port 1 -CliPath 'C:\unused\bin\cli.mjs' -FunctionsOnly
    $initial = Expand-Sddl $fixtureRequest.initial
    $task = [pscustomobject]@{ Sddl = $initial; Flags = $null; Reads = [Collections.Generic.List[int]]::new() }
    Add-Member -InputObject $task -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {
        param([int]$Information)
        $this.Reads.Add($Information)
        return $this.Sddl
    }
    Add-Member -InputObject $task -MemberType ScriptMethod -Name SetSecurityDescriptor -Value {
        param([string]$Sddl, [int]$Flags)
        $this.Sddl = $Sddl
        $this.Flags = $Flags
    }
    Grant-TaskWrite -Task $task -RuntimeSid $fixtureUser
    $checks = [ordered]@{}
    foreach ($candidate in @(@{ Name = 'actual'; Sddl = $task.Sddl }) + @($fixtureRequest.drifts.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Sddl = Expand-Sddl $_.Value } })) {
        try {
            Assert-TaskAccessChange -Before $initial -After $candidate.Sddl -RuntimeSid $fixtureUser
            $checks[$candidate.Name] = 'accepted'
        }
        catch { $checks[$candidate.Name] = $_.Exception.Message }
    }
    [ordered]@{
        after = $task.Sddl.Replace($fixtureUser, '{U}')
        flags = $task.Flags
        reads = @($task.Reads)
        checks = $checks
    } | ConvertTo-Json -Depth 4 -Compress
    return
}

. (Join-Path $PSScriptRoot 'legacy-task-com.ps1') -Adapter (Join-Path $PSScriptRoot '..\..\autostart\windows\legacy-task.ps1') -ModelOnly
$global:LegacyMock.Definition.Actions[0].Arguments = '"' + $fixtureRequest.launcher + '" 32190'
$global:LegacyMock.Security = Expand-Sddl $fixtureRequest.taskSddl
. $accessScript -Operation inspect -Port 32190 -CliPath $fixtureRequest.cli -FunctionsOnly
try {
    $report = Get-AccessReport -Task $global:LegacyMock.Task -Path $fixtureRequest.cli
    [ordered]@{
        missing = @($report.missing)
        fixable = @($report.fixable)
        runtimeSidMatches = $report.runtimeSidMatches
        taskPath = $report.task.path
        boundToTask = $report.expected.xmlSha256 -ceq (Get-TaskRecord -Task $global:LegacyMock.Task).xmlSha256
        mutations = $global:LegacyMock.Mutations
    } | ConvertTo-Json -Compress
}
catch { [ordered]@{ error = $_.Exception.Message; mutations = $global:LegacyMock.Mutations } | ConvertTo-Json -Compress }
