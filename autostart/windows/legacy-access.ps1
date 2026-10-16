<#
.SYNOPSIS
Checks, or grants, the runtime user's access to one known legacy 1.3 registration and CLI file.
.DESCRIPTION
inspect is read-only. It reports whether the ordinary runtime user can make the task writes
and the bin\cli.mjs stage/move operations that legacy migration needs. Only allow ACEs that
apply to that user are counted, so a reported gap is certain; deny ACEs can still refuse later.
A non-elevated caller is evaluated with its own token. An elevated caller is evaluated as its
UAC-filtered ordinary context: its user SID and groups, without administrator groups.

grant requires an elevated administrator and the descriptors returned by inspect. It gives the
task's run-as user full control of that task and makes that user the owner of bin\cli.mjs,
only where inspect reports that gap. Task XML, run-as account, task owner/group, other ACEs,
audit/label data, file bytes and the file's DACL are unchanged and verified afterwards.
.PARAMETER Operation
inspect or grant.
.PARAMETER Port
The selected Pacemaker port.
.PARAMETER CliPath
The selected legacy package's bin\cli.mjs. It must belong to the selected task's launcher root.
.PARAMETER FunctionsOnly
Loads the access functions without connecting to Task Scheduler.
.OUTPUTS
JSON access report. grant reads {"expected": {...}} from standard input.
.EXAMPLE
.\legacy-access.ps1 -Operation inspect -Port 8791 -CliPath C:\src\mcp-pacemaker\bin\cli.mjs
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('inspect', 'grant')]
    [string]$Operation,
    [Parameter(Mandatory)]
    [ValidateRange(1, 65535)]
    [int]$Port,
    [Parameter(Mandatory)]
    [string]$CliPath,
    [switch]$FunctionsOnly
)

$ErrorActionPreference = 'Stop'
# legacy-task.ps1 binds its own parameters in this scope when dot-sourced.
$accessOperation = $Operation
$accessPort = $Port
$accessCliPath = $CliPath
$accessFunctionsOnly = [bool]$FunctionsOnly
. (Join-Path $PSScriptRoot 'legacy-task.ps1') -Operation inspect -Port $accessPort -FunctionsOnly

$fileReadData = 0x1
# FILE_WRITE_DATA on a file is FILE_ADD_FILE on a directory.
$fileWriteData = 0x2
$fileDeleteChild = 0x40
$deleteAccess = 0x10000
$readControl = 0x20000
$writeDac = 0x40000
$fullControl = 0x1F01FF
# PoolingSecurityHelper stage opens the source with READ_CONTROL | FILE_READ_DATA | FILE_WRITE_DATA.
$stageSource = $readControl -bor $fileReadData -bor $fileWriteData
$fixable = @('task-write', 'cli-owner')
$uacFilteredSids = @('S-1-5-32-544', 'S-1-5-32-547', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550',
    'S-1-5-32-551', 'S-1-5-32-552', 'S-1-5-32-556')
$uacFilteredDomainRids = @('-498', '-512', '-516', '-517', '-518', '-519', '-520', '-521')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))

function Test-UacFiltered {
    param([string]$Sid)
    if ($Sid -cin $uacFilteredSids) { return $true }
    if (-not $Sid.StartsWith('S-1-5-21-', [StringComparison]::Ordinal)) { return $false }
    foreach ($rid in $uacFilteredDomainRids) {
        if ($Sid.EndsWith($rid, [StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

$ordinarySids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$null = $ordinarySids.Add($identity.User.Value)
foreach ($group in $identity.Groups) {
    if (-not (Test-UacFiltered -Sid $group.Value)) { $null = $ordinarySids.Add($group.Value) }
}

function Test-CallerSid {
    param([string]$Sid)
    if ($elevated) { return $ordinarySids.Contains($Sid) }
    if ($Sid -ceq $identity.User.Value) { return $true }
    return $principal.IsInRole([Security.Principal.SecurityIdentifier]::new($Sid))
}

function ConvertTo-FileRights {
    param([int]$Mask)
    [int64]$value = [BitConverter]::ToUInt32([BitConverter]::GetBytes($Mask), 0)
    [int64]$rights = $value -band 0x01FFFFFF
    # GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE and GENERIC_ALL use the file mapping.
    if ($value -band 2147483648) { $rights = $rights -bor 0x120089 }
    if ($value -band 1073741824) { $rights = $rights -bor 0x120116 }
    if ($value -band 536870912) { $rights = $rights -bor 0x1200A0 }
    if ($value -band 268435456) { $rights = $rights -bor $fullControl }
    return $rights
}

function Get-AllowedRights {
    param([string]$Sddl)
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $ownerApplies = Test-CallerSid -Sid $descriptor.Owner.Value
    if ($null -eq $descriptor.DiscretionaryAcl) {
        return [pscustomobject]@{ Allowed = [int64]$fullControl; OwnerSid = $descriptor.Owner.Value }
    }
    [int64]$allowed = 0
    $ownerRightsAce = $false
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) { continue }
        $common = $ace -as [Security.AccessControl.CommonAce]
        if ($null -eq $common) { continue }
        $sid = $common.SecurityIdentifier.Value
        $ownerRights = $sid -ceq 'S-1-3-4'
        if ($ownerRights) { $ownerRightsAce = $true }
        $applies = if ($ownerRights) { $ownerApplies } else { Test-CallerSid -Sid $sid }
        $grants = $applies -and
            -not $common.IsCallback -and
            $common.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed
        if ($grants) { $allowed = $allowed -bor (ConvertTo-FileRights -Mask $common.AccessMask) }
    }
    # Owners implicitly hold READ_CONTROL and WRITE_DAC unless an OWNER RIGHTS ACE replaces them.
    if ($ownerApplies -and
        -not $ownerRightsAce) { $allowed = $allowed -bor $readControl -bor $writeDac }
    return [pscustomobject]@{ Allowed = $allowed; OwnerSid = $descriptor.Owner.Value }
}

function Get-AccountName {
    param([string]$Sid)
    try { return ([Security.Principal.SecurityIdentifier]::new($Sid)).Translate([Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

function Get-LegacyCliPath {
    param($Record)
    $arguments = [string]$Record.actions[0].arguments
    $suffix = "`" $accessPort"
    if (-not $arguments.StartsWith('"') -or
        -not $arguments.EndsWith($suffix)) { throw 'Unsupported legacy launcher arguments.' }
    $launcher = [IO.Path]::GetFullPath($arguments.Substring(1, $arguments.Length - 1 - $suffix.Length))
    $root = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($launcher)))
    return [IO.Path]::Combine($root, 'bin', 'cli.mjs')
}

function Get-FileSddl {
    param([IO.FileSystemInfo]$Item)
    $sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
    if ($Item -is [IO.DirectoryInfo]) {
        return [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]$Item).GetSecurityDescriptorSddlForm($sections)
    }
    return [IO.FileSystemAclExtensions]::GetAccessControl([IO.FileInfo]$Item).GetSecurityDescriptorSddlForm($sections)
}

function Get-AccessReport {
    param($Task, [string]$Path)
    $record = Get-TaskRecord -Task $Task
    $expectedCli = Get-LegacyCliPath -Record $record
    $file = [IO.FileInfo]::new($Path)
    if (-not [string]::Equals($expectedCli, $file.FullName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The CLI file does not belong to the selected legacy registration.'
    }
    # PowerShell reports LinkType HardLink when a file has more than one link.
    $linkType = if ($file.Exists) { (Get-Item -LiteralPath $file.FullName -Force).LinkType } else { $null }
    $regular = $file.Exists -and
        -not ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        [string]::IsNullOrEmpty($linkType)
    if (-not $regular) { throw 'The legacy CLI file must be one regular file without links.' }
    $cliSddl = Get-FileSddl -Item $file
    $binSddl = Get-FileSddl -Item $file.Directory
    $taskRights = Get-AllowedRights -Sddl $record.security.sddl
    $cliRights = Get-AllowedRights -Sddl $cliSddl
    $binRights = Get-AllowedRights -Sddl $binSddl
    $runtimeSid = $identity.User.Value
    # Staging keeps the owner when it is the caller's user SID or (non-elevated) default owner.
    $ownerRetained = $cliRights.OwnerSid -ceq $runtimeSid -or
        (-not $elevated -and $cliRights.OwnerSid -ceq $identity.Owner.Value)
    $canDelete = ($cliRights.Allowed -band $deleteAccess) -ne 0 -or
        ($binRights.Allowed -band $fileDeleteChild) -ne 0
    $missing = [Collections.Generic.List[string]]::new()
    if (($taskRights.Allowed -band $fileWriteData) -eq 0) { $missing.Add('task-write') }
    if (-not $ownerRetained -and
        ($cliRights.Allowed -band $writeDac) -eq 0) { $missing.Add('cli-owner') }
    if (($cliRights.Allowed -band $stageSource) -ne $stageSource) { $missing.Add('cli-write') }
    if (-not $canDelete) { $missing.Add('cli-delete') }
    if (($binRights.Allowed -band $fileWriteData) -eq 0) { $missing.Add('bin-add-file') }
    return [ordered]@{
        protocol = 1
        elevated = $elevated
        evaluated = if ($elevated) { 'ordinary-context-of-elevated-token' } else { 'current-token' }
        runtimeSidMatches = $record.userSid -ceq $runtimeSid
        task = [ordered]@{
            name = $record.name
            path = $record.path
            ownerName = Get-AccountName -Sid ([Security.AccessControl.RawSecurityDescriptor]::new($record.security.sddl).Owner.Value)
        }
        cli = [ordered]@{
            path = $file.FullName
            directory = $file.DirectoryName
            ownerName = Get-AccountName -Sid $cliRights.OwnerSid
        }
        missing = @($missing)
        fixable = @($missing | Where-Object { $_ -cin $fixable })
        expected = [ordered]@{ taskSddl = $record.security.sddl; xmlSha256 = $record.xmlSha256; cliSddl = $cliSddl }
    }
}

function Get-AceKeys {
    param([string]$Sddl, [string]$RuntimeSid)
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if ($null -eq $descriptor.DiscretionaryAcl) { return '' }
    $keys = foreach ($ace in $descriptor.DiscretionaryAcl) {
        $common = $ace -as [Security.AccessControl.CommonAce]
        $explicitRuntime = $null -ne $common -and
            ($ace.AceFlags -band [Security.AccessControl.AceFlags]::Inherited) -eq 0 -and
            $common.SecurityIdentifier.Value -ceq $RuntimeSid
        if ($explicitRuntime) { continue }
        $bytes = [byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    }
    return (@($keys) | Sort-Object) -join '|'
}

function Assert-TaskAccessChange {
    param([string]$Before, [string]$After, [string]$RuntimeSid)
    $old = [Security.AccessControl.RawSecurityDescriptor]::new($Before)
    $new = [Security.AccessControl.RawSecurityDescriptor]::new($After)
    $sections = [Security.AccessControl.AccessControlSections]::Audit
    $unchanged = $old.Owner -eq $new.Owner -and
        $old.Group -eq $new.Group -and
        $old.GetSddlForm($sections) -ceq $new.GetSddlForm($sections) -and
        (Get-AceKeys -Sddl $Before -RuntimeSid $RuntimeSid) -ceq (Get-AceKeys -Sddl $After -RuntimeSid $RuntimeSid)
    if (-not $unchanged) {
        throw 'LEGACY_ACCESS_DRIFT: Task security changed beyond the runtime user entry. Inspect it before retrying.'
    }
}

function Grant-TaskWrite {
    param($Task, [string]$RuntimeSid)
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Task.GetSecurityDescriptor(7))
    $acl = $descriptor.DiscretionaryAcl
    if ($null -eq $acl) { throw 'Task has no discretionary ACL; nothing was changed.' }
    $sid = [Security.Principal.SecurityIdentifier]::new($RuntimeSid)
    $replacement = [Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,
        [Security.AccessControl.AceQualifier]::AccessAllowed, $fullControl, $sid, $false, $null)
    $explicitEnd = $acl.Count
    for ($index = 0; $index -lt $acl.Count; $index++) {
        if ($acl[$index].AceFlags -band [Security.AccessControl.AceFlags]::Inherited) { $explicitEnd = $index; break }
    }
    # Task Scheduler can return the principal's explicit entry after inherited ones, so search them all.
    $updated = $false
    for ($index = 0; $index -lt $acl.Count; $index++) {
        $common = $acl[$index] -as [Security.AccessControl.CommonAce]
        $runtimeAllow = $null -ne $common -and
            -not $common.IsCallback -and
            $common.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            $common.AceFlags -eq [Security.AccessControl.AceFlags]::None -and
            $common.SecurityIdentifier -eq $sid
        if ($runtimeAllow) {
            $acl.RemoveAce($index)
            $acl.InsertAce($index, $replacement)
            $updated = $true
            break
        }
    }
    # A new entry goes before inherited ones; Windows keeps explicit entries first.
    if (-not $updated) { $acl.InsertAce($explicitEnd, $replacement) }
    $sddl = $descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]'Owner, Group, Access')
    # 0x10 is TASK_DONT_ADD_PRINCIPAL_ACE.
    $Task.SetSecurityDescriptor($sddl, 0x10)
}

function Set-CliOwner {
    param([string]$Path, [string]$RuntimeSid)
    # A new FileSecurity persists only the sections that were set: here, the owner.
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($RuntimeSid))
    [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $security)
}

function Get-FileDigest {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if ($accessFunctionsOnly) { return }
$script:accessChanged = [Collections.Generic.List[string]]::new()

function Invoke-LegacyAccess {
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    $folder = $service.GetFolder('\')
    $script:folderCount = 0
    $tasks = @(Get-MatchingTasks -TaskFolder $folder -Depth 0)
    if ($tasks.Count -ne 1) { throw 'Exactly one selected legacy registration is required.' }
    $task = $tasks[0]
    $report = Get-AccessReport -Task $task -Path $accessCliPath
    if ($accessOperation -eq 'inspect') { return $report }

    if (-not $elevated) { throw 'LEGACY_ACCESS_NOT_ELEVATED: Run --fix-legacy-access from an administrator terminal. Nothing was changed.' }
    $text = [Console]::In.ReadToEnd()
    if ($text.Length -gt 1048576) { throw 'Access request exceeds the supported bound.' }
    $request = $text | ConvertFrom-Json
    $record = Get-TaskRecord -Task $task
    $planned = $report.expected.taskSddl -ceq $request.expected.taskSddl -and
        $report.expected.xmlSha256 -ceq $request.expected.xmlSha256 -and
        $report.expected.cliSddl -ceq $request.expected.cliSddl
    if (-not $planned) { throw 'LEGACY_ACCESS_CHANGED: The task or CLI file changed after the plan was shown. Nothing was changed.' }
    $selected = $report.runtimeSidMatches -and
        $record.logonType -eq 3 -and
        $record.runLevel -eq 0
    if (-not $selected) { throw 'Selected task is not a non-elevated InteractiveToken task for this account. Nothing was changed.' }
    $manual = @($report.missing | Where-Object { $_ -cnotin $fixable })
    if ($manual.Count) { throw "LEGACY_ACCESS_MANUAL: These need a manual permission change: $($manual -join ', '). Nothing was changed." }
    $runtimeSid = $identity.User.Value
    $cliDigest = Get-FileDigest -Path $accessCliPath
    if ($report.missing -ccontains 'task-write') {
        Grant-TaskWrite -Task $task -RuntimeSid $runtimeSid
        $script:accessChanged.Add('task-write')
    }
    if ($report.missing -ccontains 'cli-owner') {
        Set-CliOwner -Path $accessCliPath -RuntimeSid $runtimeSid
        $script:accessChanged.Add('cli-owner')
    }
    $updatedTask = $folder.GetTask($task.Name)
    $after = Get-AccessReport -Task $updatedTask -Path $accessCliPath
    $updatedRecord = Get-TaskRecord -Task $updatedTask
    Assert-TaskAccessChange -Before $report.expected.taskSddl -After $after.expected.taskSddl -RuntimeSid $runtimeSid
    $beforeCli = [Security.AccessControl.RawSecurityDescriptor]::new($report.expected.cliSddl)
    $afterCli = [Security.AccessControl.RawSecurityDescriptor]::new($after.expected.cliSddl)
    $accessSection = [Security.AccessControl.AccessControlSections]::Access
    $verified = $updatedRecord.xmlSha256 -ceq $record.xmlSha256 -and
        $updatedRecord.enabled -eq $record.enabled -and
        $updatedRecord.userSid -ceq $record.userSid -and
        $beforeCli.Group -eq $afterCli.Group -and
        $beforeCli.GetSddlForm($accessSection) -ceq $afterCli.GetSddlForm($accessSection) -and
        (Get-FileDigest -Path $accessCliPath) -ceq $cliDigest -and
        -not ($after.missing | Where-Object { $_ -cin $fixable })
    if (-not $verified) { throw 'LEGACY_ACCESS_UNVERIFIED: The access change could not be verified. Inspect the task and CLI file.' }
    return [ordered]@{
        protocol = 1
        changed = @($script:accessChanged)
        before = $report.expected
        after = $after.expected
        missing = $after.missing
    }
}

try {
    Invoke-LegacyAccess | ConvertTo-Json -Depth 6 -Compress
}
catch {
    # Callers read one JSON document; changed lists any write that completed before the failure.
    [ordered]@{ protocol = 1; error = $_.Exception.Message; changed = @($script:accessChanged) } | ConvertTo-Json -Compress
    exit 1
}
