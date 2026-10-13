<#
.SYNOPSIS
Inspects or updates one identity-bound per-user Pacemaker registration.
.DESCRIPTION
Reads a bounded JSON request from standard input. Mutations require the exact
task XML and full owner/group/DACL/SACL/integrity descriptor. Does not enable
privileges, repair permissions or stop processes.
.PARAMETER Operation
The scoped task operation to perform.
.PARAMETER Port
The selected Pacemaker port.
.PARAMETER FunctionsOnly
Loads shared task inspection/security functions without connecting to Task Scheduler.
.OUTPUTS
JSON task identity including its XML for protected backup and scoped restoration.
.EXAMPLE
.\legacy-task.ps1 -Operation inspect -Port 8791
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('inspect', 'hold', 'repoint', 'enable', 'restore', 'start', 'compare-restored')]
    [string]$Operation,
    [Parameter(Mandatory)]
    [ValidateRange(1, 65535)]
    [int]$Port,
    [switch]$FunctionsOnly
)

$ErrorActionPreference = 'Stop'
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ownerPolicy = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\..\bin\legacy-1.3.json') | ConvertFrom-Json).taskOwnerPolicy
if ($ownerPolicy.protocol -ne 1 -or
    $ownerPolicy.allowRuntimeUser -ne $true -or
    $null -eq $ownerPolicy.allowedOwnerSids) { throw 'Unsupported task owner policy.' }

function Get-UserSid {
    param([string]$User)
    if ($User.StartsWith('S-1-', [StringComparison]::Ordinal)) { return $User }
    $account = [Security.Principal.NTAccount]::new($User)
    return $account.Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-XmlHash {
    param([string]$Xml)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Xml))).ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function ConvertTo-TaskSecurity {
    param([string]$Sddl)
    try {
        if ([string]::IsNullOrEmpty($Sddl) -or
            $Sddl.Length -gt 65536) { throw 'Unsupported descriptor length.' }
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if ($null -eq $descriptor.Owner -or
            $null -eq $descriptor.Group) { throw 'Missing resource owner/group.' }
        return @{
            protocol = 1
            information = 31
            complete = $true
            ownerSid = $descriptor.Owner.Value
            groupSid = $descriptor.Group.Value
            controlFlags = [int]$descriptor.ControlFlags
            # AccessControlSections.All omits the LABEL flag when reserializing SDDL.
            sddl = $Sddl
            sha256 = Get-XmlHash -Xml $Sddl
        }
    }
    catch { throw 'TASK_SECURITY_UNVERIFIED: Full task security descriptor could not be represented. No security fallback is allowed.' }
}

function Get-TaskSecurity {
    param($Task)
    try {
        # OWNER | GROUP | DACL | SACL | LABEL; omitted audit data is not an empty SACL.
        $sddl = $Task.GetSecurityDescriptor(31)
    }
    catch {
        throw 'TASK_SECURITY_UNVERIFIED: Owner/group/DACL/SACL/integrity inspection was denied or unsupported. Further operations are refused; this adapter does not enable security privilege or elevate.'
    }
    return ConvertTo-TaskSecurity -Sddl $sddl
}

function Assert-TaskSecurity {
    param($Actual, $Expected, [string]$RuntimeSid = $currentSid)
    $recorded = ConvertTo-TaskSecurity -Sddl $Expected.sddl
    if ($Expected.protocol -ne 1 -or
        $Expected.information -ne 31 -or
        $Expected.complete -ne $true -or
        $Expected.sha256 -cne $recorded.sha256 -or
        $Expected.ownerSid -cne $recorded.ownerSid -or
        $Expected.groupSid -cne $recorded.groupSid -or
        $Expected.controlFlags -ne $recorded.controlFlags -or
        $Actual.sha256 -cne $recorded.sha256 -or
        -not ($Actual.ownerSid -ceq $RuntimeSid -or
              $Actual.ownerSid -cin $ownerPolicy.allowedOwnerSids)) {
        throw 'TASK_SECURITY_CHANGED: Resource owner, permissions, audit or integrity no longer matches the approved task. Further operations are refused.'
    }
}

function Get-TaskRecord {
    param($Task)
    $definition = $Task.Definition
    $actions = @($definition.Actions | ForEach-Object {
        @{
            type = $_.Type
            path = $_.Path
            arguments = $_.Arguments
            workingDirectory = [string]$_.WorkingDirectory
        }
    })
    $triggers = @($definition.Triggers | ForEach-Object {
        @{
            type = $_.Type
            userSid = Get-UserSid -User $_.UserId
            enabled = $_.Enabled
            stateChange = if ($_.Type -eq 11) { $_.StateChange } else { 0 }
        }
    })
    $xml = $Task.Xml
    if ($xml.Length -gt 524288) { throw 'Selected task XML exceeds the supported bound.' }
    return @{
        name = $Task.Name
        path = $Task.Path
        enabled = $Task.Enabled
        xml = $xml
        xmlSha256 = Get-XmlHash -Xml $xml
        security = Get-TaskSecurity -Task $Task
        currentUserSid = $currentSid
        userSid = Get-UserSid -User $definition.Principal.UserId
        logonType = $definition.Principal.LogonType
        runLevel = $definition.Principal.RunLevel
        actions = $actions
        triggers = $triggers
        settings = @{
            multipleInstances = $definition.Settings.MultipleInstances
            restartCount = $definition.Settings.RestartCount
            restartInterval = $definition.Settings.RestartInterval
            executionTimeLimit = $definition.Settings.ExecutionTimeLimit
            startWhenAvailable = $definition.Settings.StartWhenAvailable
            disallowStartIfOnBatteries = $definition.Settings.DisallowStartIfOnBatteries
            stopIfGoingOnBatteries = $definition.Settings.StopIfGoingOnBatteries
        }
    }
}

function Get-RestorationXml {
    param([string]$Xml, $TaskService)
    if ([string]::IsNullOrWhiteSpace($Xml) -or
        $Xml.Length -gt 524288) { throw 'TASK_RESTORATION_XML_UNVERIFIED: Invalid XML bounds.' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 524288
    $text = [IO.StringReader]::new($Xml)
    $reader = [Xml.XmlReader]::Create($text, $settings)
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    try { $document.Load($reader) }
    finally { $reader.Dispose(); $text.Dispose() }
    $namespace = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    $root = $document.DocumentElement
    if ($root.LocalName -cne 'Task' -or
        $root.NamespaceURI -cne $namespace) { throw 'TASK_RESTORATION_XML_UNVERIFIED: Unexpected task root.' }
    $registrations = @($document.SelectNodes("//*[local-name()='RegistrationInfo']"))
    $descriptors = @($document.SelectNodes("//*[local-name()='SecurityDescriptor']"))
    if ($registrations.Count -gt 1 -or
        $descriptors.Count -gt 1) { throw 'TASK_RESTORATION_XML_UNVERIFIED: Duplicate registration metadata.' }
    foreach ($registration in $registrations) {
        if ($registration.NamespaceURI -cne $namespace -or
            $registration.ParentNode -ne $root) { throw 'TASK_RESTORATION_XML_UNVERIFIED: Unexpected registration metadata.' }
    }
    foreach ($descriptor in $descriptors) {
        if ($descriptor.NamespaceURI -cne $namespace -or
            $descriptor.ParentNode.LocalName -cne 'RegistrationInfo' -or
            $descriptor.ParentNode.NamespaceURI -cne $namespace -or
            $descriptor.ParentNode.ParentNode -ne $root) { throw 'TASK_RESTORATION_XML_UNVERIFIED: Unexpected embedded descriptor.' }
    }
    $definition = $TaskService.NewTask(0)
    $definition.XmlText = $Xml
    $definition.RegistrationInfo.SecurityDescriptor = ''
    return $definition.XmlText
}

function Get-MatchingTasks {
    param($TaskFolder, [int]$Depth)
    if ($Depth -gt 8) { throw 'Task folder depth exceeds the inspection bound.' }
    $script:folderCount++
    if ($script:folderCount -gt 512) { throw 'Task folder count exceeds the inspection bound.' }
    foreach ($candidate in $TaskFolder.GetTasks(1)) {
        $matching = $candidate.Name -in @("McpPacemaker-$Port", 'McpPacemaker')
        foreach ($action in $candidate.Definition.Actions) {
            if ($action.Type -eq 0 -and
                $null -ne $action.Arguments -and
                $action.Arguments.EndsWith("\autostart\windows\launcher.vbs`" $Port", [StringComparison]::OrdinalIgnoreCase)) {
                $matching = $true
            }
        }
        if ($matching) { $candidate }
    }
    foreach ($childFolder in $TaskFolder.GetFolders(0)) {
        Get-MatchingTasks -TaskFolder $childFolder -Depth ($Depth + 1)
    }
}
if ($FunctionsOnly) { return }
$service = New-Object -ComObject Schedule.Service
$service.Connect()
if ($Operation -eq 'compare-restored') {
    $text = [Console]::In.ReadToEnd()
    if ($text.Length -gt 1048576) { throw 'Task operation input exceeds the supported bound.' }
    $request = $text | ConvertFrom-Json
    Assert-TaskSecurity -Actual $request.actual.security -Expected $request.original.security -RuntimeSid $request.original.userSid
    $actualXml = Get-RestorationXml -Xml $request.actual.xml -TaskService $service
    $originalXml = Get-RestorationXml -Xml $request.original.xml -TaskService $service
    if ((Get-XmlHash -Xml $actualXml) -cne (Get-XmlHash -Xml $originalXml)) {
        throw 'Restored legacy registration XML differs beyond its embedded descriptor representation.'
    }
    @{ equivalent = $true } | ConvertTo-Json -Compress
    return
}
$folder = $service.GetFolder('\')
$script:folderCount = 0
$tasks = @(Get-MatchingTasks -TaskFolder $folder -Depth 0)
if ($tasks.Count -gt 16) { throw 'Too many matching Pacemaker registrations.' }
if ($Operation -eq 'inspect') {
    ConvertTo-Json -InputObject @($tasks | ForEach-Object { Get-TaskRecord -Task $_ }) -Depth 8 -Compress
    return
}

$text = [Console]::In.ReadToEnd()
if ($text.Length -gt 1048576) { throw 'Task operation input exceeds the supported bound.' }
$request = $text | ConvertFrom-Json
if ($tasks.Count -ne 1) { throw 'Exactly one selected registration is required before mutation.' }
$task = $tasks[0]
$record = Get-TaskRecord -Task $task
Assert-TaskSecurity -Actual $record.security -Expected $request.expected.security
if ($record.name -ne $request.expected.name -or
    $record.path -ne "\$($record.name)" -or
    $record.xmlSha256 -cne $request.expected.xmlSha256 -or
    $record.userSid -cne $currentSid -or
    $record.logonType -ne 3 -or
    $record.runLevel -ne 0) {
    throw 'Selected task identity changed; no operation was performed.'
}
switch ($Operation) {
    'hold' { $task.Enabled = $false }
    'enable' { $task.Enabled = $true }
    'repoint' {
        if ($task.Enabled) { throw 'Registration must be held before replacing its launcher.' }
        $launcher = [IO.Path]::GetFullPath($request.launcher)
        if ($launcher.IndexOfAny([char[]]"`"`r`n") -ge 0 -or
            -not [IO.File]::Exists($launcher)) { throw 'Invalid stable launcher path.' }
        $definition = $task.Definition
        if ($definition.Actions.Count -ne 1) { throw 'Unexpected task actions.' }
        $definition.Actions.Item(1).Arguments = "`"$launcher`""
        # Update only, do not alter principal ACEs, and suppress registration-trigger execution.
        $definition.RegistrationInfo.SecurityDescriptor = ''
        $folder.RegisterTaskDefinition($task.Name, $definition, 52, $definition.Principal.UserId, $null, 3, $null) | Out-Null
    }
    'restore' {
        if ($task.Enabled) { throw 'Registration must be held before restoration.' }
        Assert-TaskSecurity -Actual $record.security -Expected $request.original.security
        $definition = $service.NewTask(0)
        $definition.XmlText = $request.original.xml
        if ((Get-XmlHash -Xml $request.original.xml) -cne $request.original.xmlSha256 -or
            (Get-UserSid -User $definition.Principal.UserId) -cne $currentSid -or
            $definition.Principal.LogonType -ne 3 -or
            $definition.Principal.RunLevel -ne 0 -or
            $request.original.name -ne $task.Name) { throw 'Invalid original task identity.' }
        $definition.RegistrationInfo.SecurityDescriptor = ''
        $folder.RegisterTaskDefinition($task.Name, $definition, 52, $definition.Principal.UserId, $null, 3, $null) | Out-Null
    }
    'start' { $task.Run($null) | Out-Null }
}
$updated = Get-TaskRecord -Task ($folder.GetTask($task.Name))
Assert-TaskSecurity -Actual $updated.security -Expected $record.security
$expectedDefinition = $service.NewTask(0)
$expectedDefinition.XmlText = $record.xml
switch ($Operation) {
    'hold' { $expectedDefinition.Settings.Enabled = $false }
    'enable' { $expectedDefinition.Settings.Enabled = $true }
    'repoint' { $expectedDefinition.Actions.Item(1).Arguments = "`"$launcher`"" }
    'restore' { $expectedDefinition.XmlText = $request.original.xml }
}
$updatedDefinition = $service.NewTask(0)
$updatedDefinition.XmlText = $updated.xml
if ($Operation -in @('repoint', 'restore')) {
    $expectedDefinition.RegistrationInfo.SecurityDescriptor = ''
    if (-not [string]::IsNullOrEmpty($updatedDefinition.RegistrationInfo.SecurityDescriptor)) {
        throw 'Registration changed beyond the requested scoped edit; do not stop or activate a backend.'
    }
    $updatedDefinition.RegistrationInfo.SecurityDescriptor = ''
}
if ((Get-XmlHash -Xml $expectedDefinition.XmlText) -cne (Get-XmlHash -Xml $updatedDefinition.XmlText)) {
    throw 'Registration changed beyond the requested scoped edit; do not stop or activate a backend.'
}
$updated | ConvertTo-Json -Depth 8 -Compress
