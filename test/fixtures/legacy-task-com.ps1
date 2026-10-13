<#
.SYNOPSIS
Exercises the production task adapter against an owned in-memory COM model.
.DESCRIPTION
Replaces only Schedule.Service construction. XML, run-as identity and resource
security are independent. No real task or access-control operation is performed.
.PARAMETER Adapter
Production adapter script.
.PARAMETER Scenario
Owned model change before the second adapter invocation.
.PARAMETER Operation
Scoped adapter operation.
.PARAMETER Launcher
Owned file used for repoint tests.
.PARAMETER TaskOwner
Synthetic task resource owner, independent of the run-as principal.
.PARAMETER RunAs
Synthetic run-as principal.
.PARAMETER ModelOnly
Initializes the in-memory COM model without invoking an adapter operation.
.PARAMETER UnrelatedArguments
Adds an unrelated executable task with absent or empty arguments.
.PARAMETER NullWorkingDirectory
Returns an absent working directory through the modeled COM action.
.PARAMETER StoredDefaultsElided
Omits a default-valued field in stored XML while the definition parser materializes it.
.PARAMETER PostWriteDrift
Injects a meaningful definition change after the requested modeled mutation.
.PARAMETER EchoResourceSecurity
Models registration copying the full resource descriptor into registration XML.
.PARAMETER PostWriteSecurityDrift
Changes actual resource security after the modeled write, independently of its XML echo.
.PARAMETER StaleXmlRevision
Supplies a stale raw XML hash before mutation.
.OUTPUTS
Sanitized assertion evidence without XML, SDDL or account identifiers.
.EXAMPLE
.\legacy-task-com.ps1 -Adapter C:\owned\legacy-task.ps1 -Scenario acl -Operation hold
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Adapter,
    [ValidateSet('none', 'acl', 'owner', 'owner-current', 'audit', 'integrity', 'audit-denied', 'missing')][string]$Scenario = 'none',
    [ValidateSet('hold', 'enable', 'repoint', 'restore', 'start')][string]$Operation = 'hold',
    [string]$Launcher,
    [ValidateSet('current-user', 'builtin-administrators', 'unrelated-user', 'misleading-label')][string]$TaskOwner = 'current-user',
    [ValidateSet('current-user', 'unrelated-user')][string]$RunAs = 'current-user',
    [ValidateSet('none', 'null', 'empty')][string]$UnrelatedArguments = 'none',
    [switch]$NullWorkingDirectory,
    [switch]$StoredDefaultsElided,
    [ValidateSet('none','action','principal','enabled','trigger','settings','embedded-security')][string]$PostWriteDrift = 'none',
    [switch]$EchoResourceSecurity,
    [ValidateSet('none','owner','group','acl','audit','integrity')][string]$PostWriteSecurityDrift = 'none',
    [switch]$StaleXmlRevision,
    [switch]$ModelOnly
)
$ErrorActionPreference = 'Stop'
$global:LegacyMock = @{
    CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Mutations = 0
    SecurityReads = [Collections.Generic.List[int]]::new()
    RegistrationFlags = 0
    DescriptorPreservedByUpdate = $false
    SecuritySetterCalled = $false
    DenyAudit = $false
    MissingSecurity = $false
    WorkingDirectory = if ($NullWorkingDirectory) { $null } else { '' }
    StoredDefaultsElided = [bool]$StoredDefaultsElided
    PostWriteDrift = $PostWriteDrift
    EchoResourceSecurity = [bool]$EchoResourceSecurity
    PostWriteSecurityDrift = $PostWriteSecurityDrift
}
$global:LegacyMock.OwnerSid = switch ($TaskOwner) {
    'builtin-administrators' { 'S-1-5-32-544' }
    { $_ -in @('unrelated-user', 'misleading-label') } { 'S-1-5-21-1-2-3-1001' }
    default { $global:LegacyMock.CurrentSid }
}
$global:LegacyMock.RunAsSid = if ($RunAs -eq 'current-user') { $global:LegacyMock.CurrentSid } else { 'S-1-5-21-1-2-3-1001' }

function New-Definition {
    $action = [pscustomobject]@{ Type = 0; Path = 'wscript.exe'; Arguments = '"C:\owned\launcher.vbs" 32190'; WorkingDirectory = $global:LegacyMock.WorkingDirectory }
    $actions = [Collections.ArrayList]::new()
    $null = $actions.Add($action)
    Add-Member -InputObject $actions -MemberType ScriptMethod -Name Item -Force -Value {
        param([int]$Index)
        return $this[$Index - 1]
    }
    $triggers = [Collections.ArrayList]::new()
    $null = $triggers.Add([pscustomobject]@{ Type = 9; UserId = $global:LegacyMock.CurrentSid; Enabled = $true })
    $null = $triggers.Add([pscustomobject]@{ Type = 11; UserId = $global:LegacyMock.CurrentSid; Enabled = $true; StateChange = 8 })
    Add-Member -InputObject $triggers -MemberType ScriptMethod -Name Item -Force -Value {
        param([int]$Index)
        return $this[$Index - 1]
    }
    $definition = [pscustomobject]@{
        RegistrationInfo = [pscustomobject]@{ SecurityDescriptor = $null }
        Principal = [pscustomobject]@{ UserId = $global:LegacyMock.RunAsSid; LogonType = 3; RunLevel = 0 }
        Actions = $actions
        Triggers = $triggers
        Settings = [pscustomobject]@{
            Enabled = $true; AllowDemandStart = $true; MultipleInstances = 2; RestartCount = 3; RestartInterval = 'PT1M'
            ExecutionTimeLimit = 'PT0S'; StartWhenAvailable = $true
            DisallowStartIfOnBatteries = $false; StopIfGoingOnBatteries = $false
        }
    }
    Add-Member -InputObject $definition -MemberType ScriptProperty -Name XmlText -Value {
        [ordered]@{
            enabled = $this.Settings.Enabled
            arguments = $this.Actions[0].Arguments
            actionPath = $this.Actions[0].Path
            cwd = $this.Actions[0].WorkingDirectory
            principal = $this.Principal.UserId
            triggers = @($this.Triggers | ForEach-Object { $_.Enabled })
            restartCount = $this.Settings.RestartCount
            allowDemandStart = $this.Settings.AllowDemandStart
            registrationSecurity = $this.RegistrationInfo.SecurityDescriptor
        } | ConvertTo-Json -Compress
    } -SecondValue {
        param([string]$Value)
        $parsed = $Value | ConvertFrom-Json
        $this.Settings.Enabled = $parsed.enabled
        $this.Actions[0].Arguments = $parsed.arguments
        $this.Actions[0].Path = $parsed.actionPath
        $this.Actions[0].WorkingDirectory = $parsed.cwd
        $this.Principal.UserId = $parsed.principal
        for ($index = 0; $index -lt $this.Triggers.Count; $index++) { $this.Triggers[$index].Enabled = $parsed.triggers[$index] }
        $this.Settings.RestartCount = $parsed.restartCount
        $this.Settings.AllowDemandStart = if ($null -eq $parsed.allowDemandStart) { $true } else { $parsed.allowDemandStart }
        $this.RegistrationInfo.SecurityDescriptor = $parsed.registrationSecurity
    }
    return $definition
}

function New-Security {
    param([string]$Change = 'none')
    $owner = switch ($Change) {
        'owner' { 'SY' }
        'owner-current' { $global:LegacyMock.CurrentSid }
        default { $global:LegacyMock.OwnerSid }
    }
    $right = if ($Change -eq 'acl') { 'FR' } else { 'FA' }
    $group = if ($Change -eq 'group') { 'BA' } else { $global:LegacyMock.CurrentSid }
    $label = if ($Change -eq 'integrity') { 'HI' } else { 'ME' }
    $audit = if ($Change -eq 'audit') { "(AU;SA;FW;;;$($global:LegacyMock.CurrentSid))" } else { '' }
    $inherited = if ($global:LegacyMock.EchoResourceSecurity) { 'AI' } else { '' }
    return "O:${owner}G:${group}D:P${inherited}(A;;$right;;;$($global:LegacyMock.CurrentSid))S:${inherited}${audit}(ML;;NW;;;$label)"
}

function Invoke-PostWriteDrift {
    $definition = $global:LegacyMock.Definition
    switch ($global:LegacyMock.PostWriteDrift) {
        'action' { $definition.Actions[0].Arguments += ' --unrequested' }
        'principal' { $definition.Principal.UserId = 'S-1-5-21-1-2-3-1001' }
        'enabled' { $definition.Settings.Enabled = -not $definition.Settings.Enabled }
        'trigger' { $definition.Triggers[0].Enabled = -not $definition.Triggers[0].Enabled }
        'settings' { $definition.Settings.RestartCount++ }
        'embedded-security' { $definition.RegistrationInfo.SecurityDescriptor = 'unexpected-embedded-descriptor' }
    }
    if ($global:LegacyMock.PostWriteSecurityDrift -ne 'none') {
        $global:LegacyMock.Security = New-Security -Change $global:LegacyMock.PostWriteSecurityDrift
    }
}

$global:LegacyMock.Definition = New-Definition
$global:LegacyMock.Security = New-Security
$global:LegacyMock.Definition.RegistrationInfo.SecurityDescriptor = $global:LegacyMock.Security
if ($global:LegacyMock.EchoResourceSecurity) {
    $global:LegacyMock.Definition.RegistrationInfo.SecurityDescriptor =
        $global:LegacyMock.Security.Replace('D:PAI', 'D:P').Replace('S:AI', 'S:')
}
$global:LegacyMock.Task = [pscustomobject]@{
    Name = 'McpPacemaker-32190'
    Path = '\McpPacemaker-32190'
    OwnerLabel = if ($TaskOwner -eq 'misleading-label') { 'Administrator' } else { '' }
}
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptProperty -Name Definition -Value {
    $copy = New-Definition
    $copy.XmlText = $global:LegacyMock.Definition.XmlText
    return $copy
}
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptProperty -Name Xml -Value {
    $text = $global:LegacyMock.Definition.XmlText
    if ($global:LegacyMock.StoredDefaultsElided -and
        $global:LegacyMock.Definition.Settings.AllowDemandStart) {
        $stored = $text | ConvertFrom-Json
        $stored.PSObject.Properties.Remove('allowDemandStart')
        return $stored | ConvertTo-Json -Compress
    }
    return $text
}
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptProperty -Name Enabled -Value {
    $global:LegacyMock.Definition.Settings.Enabled
} -SecondValue {
    param([bool]$Value)
    $global:LegacyMock.Mutations++
    $global:LegacyMock.Definition.Settings.Enabled = $Value
    Invoke-PostWriteDrift
}
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {
    param([int]$Information)
    $global:LegacyMock.SecurityReads.Add($Information)
    if ($global:LegacyMock.DenyAudit -and
        ($Information -band 8)) { throw [UnauthorizedAccessException]::new('Owned audit read denied.') }
    if ($global:LegacyMock.MissingSecurity) { return '' }
    return $global:LegacyMock.Security
}
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptMethod -Name SetSecurityDescriptor -Value {
    $global:LegacyMock.SecuritySetterCalled = $true
    throw 'The adapter must not repair or relax ACLs.'
}
Add-Member -InputObject $global:LegacyMock.Task -MemberType ScriptMethod -Name Run -Value {
    param($Parameters)
    $global:LegacyMock.Mutations++
    Invoke-PostWriteDrift
}
$global:LegacyMock.Folder = [pscustomobject]@{}
$global:LegacyMock.OtherTasks = @()
if ($UnrelatedArguments -ne 'none') {
    $global:LegacyMock.OtherTasks = @([pscustomobject]@{
        Name = 'UnrelatedTask'
        Definition = [pscustomobject]@{
            Actions = @([pscustomobject]@{
                Type = 0
                Arguments = if ($UnrelatedArguments -eq 'null') { $null } else { '' }
            })
        }
    })
}
Add-Member -InputObject $global:LegacyMock.Folder -MemberType ScriptMethod -Name GetTasks -Value {
    param($Flags)
    return @($global:LegacyMock.OtherTasks) + @($global:LegacyMock.Task)
}
Add-Member -InputObject $global:LegacyMock.Folder -MemberType ScriptMethod -Name GetFolders -Value { param($Flags) return @() }
Add-Member -InputObject $global:LegacyMock.Folder -MemberType ScriptMethod -Name GetTask -Value { param($Name) return $global:LegacyMock.Task }
Add-Member -InputObject $global:LegacyMock.Folder -MemberType ScriptMethod -Name RegisterTaskDefinition -Value {
    param($Name, $Definition, $Flags, $User, $Password, $LogonType, $Sddl)
    $global:LegacyMock.Mutations++
    $global:LegacyMock.RegistrationFlags = $Flags
    $global:LegacyMock.DescriptorPreservedByUpdate = $null -eq $Sddl -or
        $Sddl -ceq $global:LegacyMock.Security
    $global:LegacyMock.SddlArgumentWasNull = $null -eq $Sddl
    $global:LegacyMock.CandidateDescriptorCleared = $Definition.RegistrationInfo.SecurityDescriptor -ceq ''
    if (-not $global:LegacyMock.DescriptorPreservedByUpdate) { $global:LegacyMock.Security = New-Security -Change acl }
    $global:LegacyMock.Definition.XmlText = $Definition.XmlText
    if ($null -ne $Sddl) { $global:LegacyMock.Definition.RegistrationInfo.SecurityDescriptor = $Sddl }
    Invoke-PostWriteDrift
    return $global:LegacyMock.Task
}
$global:LegacyMock.Service = [pscustomobject]@{}
Add-Member -InputObject $global:LegacyMock.Service -MemberType ScriptMethod -Name Connect -Value {}
Add-Member -InputObject $global:LegacyMock.Service -MemberType ScriptMethod -Name GetFolder -Value { param($Name) return $global:LegacyMock.Folder }
Add-Member -InputObject $global:LegacyMock.Service -MemberType ScriptMethod -Name NewTask -Value { param($Flags) return New-Definition }
function New-Object {
    param([string]$ComObject)
    if ($ComObject -ne 'Schedule.Service') { throw 'Unexpected COM construction.' }
    return $global:LegacyMock.Service
}

if ($ModelOnly) { return }
if ($Operation -in @('repoint', 'restore', 'enable')) { $global:LegacyMock.Definition.Settings.Enabled = $false }
$original = @(& $Adapter -Operation inspect -Port 32190 | ConvertFrom-Json)[0]
$beforeXml = $global:LegacyMock.Task.Xml
$beforePrincipal = $global:LegacyMock.Definition.Principal.UserId
if ($Scenario -eq 'audit-denied') { $global:LegacyMock.DenyAudit = $true }
elseif ($Scenario -eq 'missing') { $global:LegacyMock.MissingSecurity = $true }
elseif ($Scenario -ne 'none') { $global:LegacyMock.Security = New-Security -Change $Scenario }
$changedSecurity = $global:LegacyMock.Security
if ($StaleXmlRevision) { $original.xmlSha256 = '0' * 64 }
$originalInput = [Console]::In
$inputJson = @{ expected = $original; original = $original; launcher = $Launcher } | ConvertTo-Json -Depth 12 -Compress
$reader = [IO.StringReader]::new($inputJson)
$succeeded = $false
$errorText = ''
try {
    [Console]::SetIn($reader)
    $null = & $Adapter -Operation $Operation -Port 32190
    $succeeded = $true
}
catch {
    $errorText = $_.Exception.Message
    if ($errorText.Contains($global:LegacyMock.CurrentSid) -or
        $errorText.Contains('D:P(')) { $errorText = 'Adapter leaked security data in its error.' }
}
finally {
    [Console]::SetIn($originalInput)
    $reader.Dispose()
}
[ordered]@{
    succeeded = $succeeded
    error = $errorText
    mutations = $global:LegacyMock.Mutations
    securityReads = @($global:LegacyMock.SecurityReads)
    securityUnchanged = $global:LegacyMock.Security -ceq $changedSecurity
    xmlUnchanged = $global:LegacyMock.Task.Xml -ceq $beforeXml
    principalUnchanged = $global:LegacyMock.Definition.Principal.UserId -ceq $beforePrincipal
    descriptorPreservedByUpdate = $global:LegacyMock.DescriptorPreservedByUpdate
    registrationFlags = $global:LegacyMock.RegistrationFlags
    securitySetterCalled = $global:LegacyMock.SecuritySetterCalled
    ownerIsBuiltinAdministrators = ([Security.AccessControl.RawSecurityDescriptor]::new($global:LegacyMock.Security).Owner.Value -ceq 'S-1-5-32-544')
    runAsIsCurrentUser = $global:LegacyMock.Definition.Principal.UserId -ceq $global:LegacyMock.CurrentSid
    inspectedWorkingDirectory = $original.actions[0].workingDirectory
    qualification = 'in-memory COM serialization/drift model, not real Task Scheduler mutation'
    storedDefaultsElided = $global:LegacyMock.StoredDefaultsElided
    postWriteDrift = $global:LegacyMock.PostWriteDrift
    postWriteSecurityDrift = $global:LegacyMock.PostWriteSecurityDrift
    echoedResourceSecurity = $global:LegacyMock.EchoResourceSecurity
    sddlArgumentWasNull = $global:LegacyMock.SddlArgumentWasNull
    candidateDescriptorCleared = $global:LegacyMock.CandidateDescriptorCleared
} | ConvertTo-Json -Depth 5 -Compress
