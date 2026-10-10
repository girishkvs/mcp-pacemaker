<#
.SYNOPSIS
Performs fixed controller task operations while preserving the registered account.
.DESCRIPTION
Reads a bounded controller request on stdin. This adapter changes only the exact
selected registration, preserving principal, logon type, run level and full security.
It never stops processes, edits configuration, enables privileges or changes ACLs.
.PARAMETER Action
Exact task operation chosen by the trusted controller.
.OUTPUTS
Bounded JSON task/profile/session evidence. A successful launch call is not readiness.
.EXAMPLE
.\account-task.ps1 -Action inspect
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('inspect', 'session', 'bootstrap', 'hold', 'repoint', 'release', 'restore', 'launch')]
    [string]$Action
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'legacy-task.ps1') -Operation inspect -Port 1 -FunctionsOnly
$text = [Console]::In.ReadToEnd()
if ($text.Length -gt 65536) { throw 'Controller request exceeds its bound.' }
$request = $text | ConvertFrom-Json
$targetSid = $request.targetSid
if ($targetSid -cnotmatch '^S-1-[0-9]+(?:-[0-9]+)+$' -or
    ([Security.Principal.SecurityIdentifier]::new($targetSid)).Value -cne $targetSid) {
    throw 'A canonical target SID is required.'
}
$impersonated = [Security.Principal.WindowsIdentity]::GetCurrent($true)
if ($null -ne $impersonated) {
    $impersonated.Dispose()
    throw 'Impersonating task-adapter contexts are unsupported.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($targetSid -cne $currentSid -and
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The current task-adapter token is not an enabled administrator.'
}
$path = $request.taskPath
if ([string]::IsNullOrEmpty($path) -or
    $path.Length -gt 1024 -or
    -not $path.StartsWith('\') -or
    $path.Contains('/') -or
    $path.Split('\') -contains '..') { throw 'An exact task path is required.' }
$separator = $path.LastIndexOf('\')
$folderPath = if ($separator -eq 0) { '\' } else { $path.Substring(0, $separator) }
$name = $path.Substring($separator + 1)
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $service.GetFolder($folderPath)
$task = $folder.GetTask($name)
$record = Get-TaskRecord -Task $task
$record.runAsName = $task.Definition.Principal.UserId
if ($record.path -cne $path -or
    $record.userSid -cne $targetSid -or
    $record.logonType -ne 3 -or
    $record.runLevel -ne 0) { throw 'Selected task does not preserve the requested interactive account.' }
Assert-TaskSecurity -Actual $record.security -Expected $record.security -RuntimeSid $targetSid
if ($Action -eq 'inspect') {
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$targetSid'" -Property SID, LocalPath, Loaded -OperationTimeoutSec 10)
    if ($profiles.Count -ne 1 -or
        -not $profiles[0].Loaded) { throw 'The selected user profile is not loaded in an existing interactive session.' }
    @{
        record = $record
        profilePath = [IO.Path]::GetFullPath($profiles[0].LocalPath)
        allowDemandStart = $task.Definition.Settings.AllowDemandStart
    } | ConvertTo-Json -Depth 12 -Compress
    return
}
if ($record.xmlSha256 -cne $request.expected.xmlSha256 -or
    $record.userSid -cne $request.expected.userSid) { throw 'Task definition changed after the approved plan.' }
Assert-TaskSecurity -Actual $record.security -Expected $request.expected.security -RuntimeSid $targetSid
if ($Action -eq 'session') {
    $port = [int]$request.port
    if ($port -lt 1 -or $port -gt 65535) { throw 'Invalid selected port.' }
    $listeners = @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_NetTCPConnection `
        -Filter "LocalAddress='127.0.0.1' AND LocalPort=$port AND State=2" -OperationTimeoutSec 10)
    if ($listeners.Count -ne 1) { throw 'Selected listener is absent or ambiguous.' }
    $processId = [int]$listeners[0].OwningProcess
    $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$processId" -Property ProcessId, ParentProcessId, SessionId, CreationDate, CommandLine, ExecutablePath -OperationTimeoutSec 10
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
    $scriptPath = [IO.Path]::GetFullPath((Join-Path $request.root 'bin\mcp-bridge.mjs'))
    $commands = @(
        "`"$($process.ExecutablePath)`" `"$scriptPath`" --port $port",
        "$($process.ExecutablePath) `"$scriptPath`" --port $port"
    )
    if ($null -ne $request.managed) {
        $parts = @((Join-Path $request.root 'supervisor\bridge-child.mjs'), '--port', "$port", '--config', $request.managed.config, '--cwd', $request.managed.cwd)
        $arguments = ($parts | ForEach-Object {
            if ($_ -match '\s') { "`"$_`"" } else { $_ }
        }) -join ' '
        $commands = @("`"$($process.ExecutablePath)`" $arguments", "$($process.ExecutablePath) $arguments")
    }
    if ($owner.ReturnValue -ne 0 -or
        $owner.Sid -cne $targetSid -or
        $process.SessionId -le 0 -or
        $process.CommandLine -notin $commands) {
        throw 'Selected listener account/session/absolute legacy command could not be verified.'
    }
    $parentId = [int]$process.ParentProcessId
    $parent = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$parentId" -Property ProcessId, ExecutablePath, SessionId, CreationDate -OperationTimeoutSec 10
    $parentOwner = Invoke-CimMethod -InputObject $parent -MethodName GetOwnerSid -ErrorAction Stop
    if ($parentOwner.ReturnValue -ne 0 -or
        $parentOwner.Sid -cne $targetSid -or
        $parent.SessionId -ne $process.SessionId -or
        $parent.CreationDate -gt $process.CreationDate) { throw 'Selected supervisor account/session/generation is ambiguous.' }
    @{ ownerSid = $owner.Sid; sessionId = $process.SessionId; pid = $processId
        createdUtc = $process.CreationDate.ToUniversalTime().ToString('o')
        supervisorImage = @{ path = $parent.ExecutablePath; sha256 = (Get-FileHash -LiteralPath $parent.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() }
    } | ConvertTo-Json -Depth 4 -Compress
    return
}
if ($Action -eq 'launch') {
    if (-not $task.Enabled -or
        -not $task.Definition.Settings.AllowDemandStart -or
        $request.sessionId -le 0) { throw 'The selected task cannot demand-start in the requested session.' }
    $running = $task.RunEx($null, 12, [int]$request.sessionId, $targetSid)
    @{ requested = $true; instanceGuid = $running.InstanceGuid; readinessProven = $false } | ConvertTo-Json -Compress
    return
}
$definition = $task.Definition
switch ($Action) {
    'bootstrap' {
        if (-not $task.Enabled -or
            -not $definition.Settings.AllowDemandStart) { throw 'Bootstrap requires an enabled demand-start task.' }
        if ($definition.Actions.Count -ne 1) { throw 'Unsupported task actions.' }
        $definition.Actions.Item(1).Path = $request.bootstrap.nodePath
        $definition.Actions.Item(1).Arguments = $request.bootstrap.arguments
        $definition.Actions.Item(1).WorkingDirectory = $request.bootstrap.cwd
        foreach ($trigger in $definition.Triggers) { $trigger.Enabled = $false }
        $definition.Settings.RestartCount = 0
    }
    'repoint' {
        if ($definition.Actions.Count -ne 1) { throw 'Unsupported task actions.' }
        $definition.Actions.Item(1).Path = 'wscript.exe'
        $definition.Actions.Item(1).Arguments = "`"$($request.launcher)`""
        $definition.Actions.Item(1).WorkingDirectory = ''
    }
    'hold' {
        foreach ($trigger in $definition.Triggers) { $trigger.Enabled = $false }
        $definition.Settings.RestartCount = 0
    }
    'release' {
        $original = $service.NewTask(0)
        $original.XmlText = $request.original.xml
        if ($original.Triggers.Count -ne $definition.Triggers.Count) { throw 'Task trigger identity changed.' }
        for ($index = 1; $index -le $definition.Triggers.Count; $index++) {
            $definition.Triggers.Item($index).Enabled = $original.Triggers.Item($index).Enabled
        }
        $definition.Settings.RestartCount = $original.Settings.RestartCount
    }
    'restore' { $definition.XmlText = $request.original.xml }
}
Assert-TaskSecurity -Actual $record.security -Expected $request.original.security -RuntimeSid $targetSid
if ((Get-UserSid -User $definition.Principal.UserId) -cne $targetSid -or
    $definition.Principal.LogonType -ne $record.logonType -or
    $definition.Principal.RunLevel -ne $record.runLevel) { throw 'Task account semantics changed.' }
$expectedXml = $definition.XmlText
$folder.RegisterTaskDefinition($name, $definition, 52, $definition.Principal.UserId, $null, 3, $record.security.sddl) | Out-Null
$updated = Get-TaskRecord -Task ($folder.GetTask($name))
$updated.runAsName = $definition.Principal.UserId
Assert-TaskSecurity -Actual $updated.security -Expected $record.security -RuntimeSid $targetSid
if ($updated.xmlSha256 -cne (Get-XmlHash -Xml $expectedXml)) { throw 'Task update outcome differs from the exact requested definition.' }
$updated | ConvertTo-Json -Depth 12 -Compress
