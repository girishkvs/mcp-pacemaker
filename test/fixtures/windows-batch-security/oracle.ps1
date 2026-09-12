<#
.SYNOPSIS
Creates isolated security fixtures and verifies native operations under Explorer's ordinary token.
.DESCRIPTION
TEST-SETUP only. Requires a full audit-reading oracle token and an existing Explorer window.
All policy changes and child output are confined to the supplied empty fixture directory.
.PARAMETER Root
Empty mcp-batch-audit-oracle-* directory owned by the calling test.
.PARAMETER Helper
Packaged production helper executable to run and load for native descriptor inspection.
.PARAMETER Node
Exact Node executable used by the calling test.
.OUTPUTS
One JSON report, or an explicit unavailable reason when the oracle prerequisites are absent.
.EXAMPLE
.\oracle.ps1 -Root C:\Temp\mcp-batch-audit-oracle-example -Helper C:\package\bin\windows\PoolingSecurityHelper.exe -Node C:\node\node.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Helper,
    [Parameter(Mandatory)][string]$Node
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath($Root)
if (-not [IO.Path]::GetFileName($Root).StartsWith('mcp-batch-audit-oracle-') -or
    @(Get-ChildItem -LiteralPath $Root -Force).Count -ne 0) {
    throw 'TEST_SETUP_REQUIRES_EMPTY_OWNED_ROOT'
}

$User = [Security.Principal.WindowsIdentity]::GetCurrent().User
$AuditSection = [Security.AccessControl.AccessControlSections]::Audit
$AccessSections = [Security.AccessControl.AccessControlSections]'Access, Owner, Group'
try {
    $RootAudit = [IO.Directory]::GetAccessControl($Root, $AuditSection)
}
catch [Security.AccessControl.PrivilegeNotHeldException] {
    '{"unavailable":"TEST-SETUP full audit oracle token unavailable"}'
    exit 0
}
catch [UnauthorizedAccessException] {
    '{"unavailable":"TEST-SETUP full audit oracle access unavailable"}'
    exit 0
}

$Shell = New-Object -ComObject Shell.Application
$Explorer = @($Shell.Windows()) |
    Where-Object { $_.FullName -and [IO.Path]::GetFileName($_.FullName) -ieq 'explorer.exe' } |
    Select-Object -First 1
if ($null -eq $Explorer) {
    '{"unavailable":"TEST-SETUP existing ordinary Explorer context unavailable"}'
    exit 0
}

[Reflection.Assembly]::LoadFrom($Helper) | Out-Null
$Reader = New-Object PoolingSecurityReader
Add-Type -Path (Join-Path $PSScriptRoot 'FixturePolicy.cs')
$Policy = New-Object FixturePolicy
$Utf8 = [Text.UTF8Encoding]::new($false)
$Names = @(
    'inherited', 'protected', 'audit', 'low', 'medium', 'creator-allowed', 'deny-other',
    'high', 'readonly', 'creator-refused', 'owner-rights', 'creator-special', 'callback',
    'inheritance-mismatch', 'audit-protected', 'label-mask3', 'label-mask5', 'label-mask7',
    'resource-policy'
)
$Successful = @(
    'inherited', 'protected', 'audit', 'low', 'medium', 'creator-allowed', 'deny-other',
    'audit-protected', 'label-mask3', 'label-mask5', 'label-mask7'
)

function Get-Hash {
    param([byte[]]$Bytes)
    $Hash = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($Hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $Hash.Dispose()
    }
}

function Get-AclHash {
    param([Security.AccessControl.RawAcl]$Acl)
    if ($null -eq $Acl) {
        return 'null'
    }

    $Bytes = New-Object byte[] $Acl.BinaryLength
    $Acl.GetBinaryForm($Bytes, 0)
    return Get-Hash -Bytes $Bytes
}

function Get-Snapshot {
    param([string]$Path)
    $Raw = [Security.AccessControl.RawSecurityDescriptor]::new($Reader.ReadControlDescriptor($Path), 0)
    $Audit = [IO.File]::GetAccessControl($Path, $AuditSection)
    $Rules = @($Audit.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $Bytes = [IO.File]::ReadAllBytes($Path)
    return [ordered]@{
        owner = $Raw.Owner.Value
        group = $Raw.Group.Value
        dacl = Get-AclHash -Acl $Raw.DiscretionaryAcl
        protected = [bool]($Raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
        control = [int]$Raw.ControlFlags
        labels = Get-AclHash -Acl $Raw.SystemAcl
        attributes = [int][IO.File]::GetAttributes($Path)
        revision = Get-Hash -Bytes $Bytes
        size = $Bytes.Length
        audit = Get-Hash -Bytes $Audit.GetSecurityDescriptorBinaryForm()
        auditProtected = $Audit.AreAuditRulesProtected
        explicit = @($Rules | Where-Object { -not $_.IsInherited }).Count
        inherited = @($Rules | Where-Object IsInherited).Count
    }
}

function Set-PrivateDirectory {
    param([string]$Path, [bool]$BroaderRead = $false)
    $Security = [Security.AccessControl.DirectorySecurity]::new()
    $Security.SetOwner($User)
    $Security.SetGroup($User)
    $Security.SetAccessRuleProtection($true, $false)
    $Inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $Security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $User, 'FullControl', $Inheritance, 'None', 'Allow'))
    if ($BroaderRead) {
        $Security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
            'ReadAndExecute', $Inheritance, 'None', 'Allow'))
    }

    if ([IO.Directory]::Exists($Path)) {
        [IO.Directory]::SetAccessControl($Path, $Security)
    }
    else {
        [IO.Directory]::CreateDirectory($Path, $Security) | Out-Null
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Context)
    if (($Actual | ConvertTo-Json -Depth 8 -Compress) -cne
        ($Expected | ConvertTo-Json -Depth 8 -Compress)) {
        throw "TEST_ORACLE_MISMATCH: $Context; actual=$($Actual | ConvertTo-Json -Depth 8 -Compress); expected=$($Expected | ConvertTo-Json -Depth 8 -Compress)"
    }
}

Set-PrivateDirectory -Path $Root
$RootAudit.SetAuditRuleProtection($true, $false)
[IO.Directory]::SetAccessControl($Root, $RootAudit)
$Before = @{}
foreach ($Name in $Names) {
    $Directory = Join-Path $Root $Name
    Set-PrivateDirectory -Path $Directory -BroaderRead ($Name -ne 'inheritance-mismatch')
    if ($Name -eq 'audit' -or
        $Name -eq 'audit-protected') {
        $ParentAudit = [IO.Directory]::GetAccessControl($Directory, $AuditSection)
        $ParentAudit.AddAuditRule([Security.AccessControl.FileSystemAuditRule]::new(
            $User, 'ReadData', 'ContainerInherit, ObjectInherit', 'None', 'Success'))
        [IO.Directory]::SetAccessControl($Directory, $ParentAudit)
    }

    $Active = Join-Path $Directory 'active.json'
    [IO.File]::WriteAllText($Active, "{`"private`":`"synthetic-secret`",`"minWarm`":0}`n", $Utf8)
    $Access = [IO.File]::GetAccessControl($Active, $AccessSections)
    $Access.SetOwner($User)
    $Access.SetGroup($User)
    if ($Name -ne 'inherited' -and
        $Name -ne 'inheritance-mismatch') {
        $Access.SetAccessRuleProtection($true, $false)
        $Rights = 'FullControl'
        if ($Name -eq 'readonly') {
            $Rights = 'Read'
        }
        if ($Name -eq 'creator-refused') {
            $Rights = 'Modify'
        }

        $Access.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($User, $Rights, 'Allow'))
    }

    if (@('creator-allowed', 'creator-refused', 'owner-rights', 'creator-special') -contains $Name) {
        $Access.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    }
    if ($Name -eq 'owner-rights') {
        $Access.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-3-4'), 'ReadPermissions', 'Allow'))
    }
    if ($Name -eq 'deny-other') {
        $Access.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-546'), 'WriteData', 'Deny'))
    }
    if ($Name -eq 'callback') {
        $Raw = [Security.AccessControl.RawSecurityDescriptor]::new($Access.GetSecurityDescriptorBinaryForm(), 0)
        $Ace = [Security.AccessControl.CommonAce]::new(
            'None', 'AccessAllowed', 0x1f01ff, $User, $true, [byte[]]@())
        $Raw.DiscretionaryAcl.InsertAce($Raw.DiscretionaryAcl.Count, $Ace)
        $Binary = New-Object byte[] $Raw.BinaryLength
        $Raw.GetBinaryForm($Binary, 0)
        $Access.SetSecurityDescriptorBinaryForm($Binary, $AccessSections)
    }
    [IO.File]::SetAccessControl($Active, $Access)
    if ($Name -eq 'creator-special') {
        $Raw = [Security.AccessControl.RawSecurityDescriptor]::new($Reader.ReadControlDescriptor($Active), 0)
        $Raw.DiscretionaryAcl.InsertAce($Raw.DiscretionaryAcl.Count,
            [Security.AccessControl.CommonAce]::new('None', 'AccessAllowed', 0x20000,
                [Security.Principal.SecurityIdentifier]::new('S-1-3-0'), $false, $null))
        $Binary = New-Object byte[] $Raw.BinaryLength
        $Raw.GetBinaryForm($Binary, 0)
        $Policy.SetDacl($Active, $Binary)
        $Actual = [Security.AccessControl.RawSecurityDescriptor]::new($Reader.ReadControlDescriptor($Active), 0)
        $Special = @($Actual.DiscretionaryAcl | Where-Object {
            $_.SecurityIdentifier.Value.StartsWith('S-1-3-')
        })
        Assert-Equal -Actual $Special.Count -Expected 1 -Context 'creator-special fixture retains special SID'
    }

    if (@('low', 'medium', 'high') -contains $Name) {
        $Label = @{ low = 'L'; medium = 'M'; high = 'H' }[$Name]
        $Output = & icacls.exe $Active /setintegritylevel $Label
        if ($LASTEXITCODE -ne 0) {
            throw 'TEST_LABEL_SETUP_FAILED'
        }
    }
    if ($Name.StartsWith('label-mask')) {
        $Mask = [int]$Name.Substring('label-mask'.Length)
        $Policy.SetLabel($Active, ('S:(ML;;0x{0:x};;;ME)' -f $Mask))
        $Actual = [Security.AccessControl.RawSecurityDescriptor]::new($Reader.ReadControlDescriptor($Active), 0)
        $Binary = New-Object byte[] $Actual.SystemAcl[0].BinaryLength
        $Actual.SystemAcl[0].GetBinaryForm($Binary, 0)
        Assert-Equal -Actual ([BitConverter]::ToInt32($Binary, 4)) -Expected $Mask -Context "$Name fixture mask"
    }
    if ($Name -eq 'resource-policy') {
        $Policy.SetNonAuditPolicy($Active, 'S:(RA;;;;;WD;("SyntheticPolicy",TS,0x0,"fixture"))', 0x20)
        $Actual = [Security.AccessControl.RawSecurityDescriptor]::new($Reader.ReadControlDescriptor($Active), 0)
        Assert-Equal -Actual ([int]$Actual.SystemAcl[0].AceType) -Expected 18 -Context 'resource policy fixture'
    }
    if ($Name -eq 'audit' -or
        $Name -eq 'audit-protected') {
        $Audit = [IO.File]::GetAccessControl($Active, $AuditSection)
        $Audit.AddAuditRule([Security.AccessControl.FileSystemAuditRule]::new($User, 'WriteData', 'Success'))
        if ($Name -eq 'audit-protected') {
            $Audit.SetAuditRuleProtection($true, $true)
        }
        [IO.File]::SetAccessControl($Active, $Audit)
        $Output = & icacls.exe $Active /setintegritylevel L
        if ($LASTEXITCODE -ne 0) {
            throw 'TEST_AUDIT_LABEL_SETUP_FAILED'
        }
    }

    $Before[$Name] = Get-Snapshot -Path $Active
    if ($Name -eq 'audit') {
        Assert-Equal -Actual $Before[$Name].explicit -Expected 1 -Context 'source explicit audit fixture'
        Assert-Equal -Actual $Before[$Name].inherited -Expected 1 -Context 'source inherited audit fixture'
        $Parent = [IO.Directory]::GetAccessControl($Directory, $AuditSection)
        $ParentRules = @($Parent.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))
        Assert-Equal -Actual $ParentRules.Count -Expected 1 -Context 'parent audit fixture'
    }
}

$DifferentParent = Join-Path $Root 'different-parent'
Set-PrivateDirectory -Path $DifferentParent -BroaderRead $true
$Policy.SetLabel($DifferentParent, 'S:(ML;OICI;NW;;;LW)')
$Worker = Join-Path $PSScriptRoot 'normal-worker.mjs'
$Arguments = '"{0}" "{1}" "{2}"' -f $Worker, $Root, $Helper
$Explorer.Document.Application.ShellExecute($Node, $Arguments, $Root, 'open', 0)
$ResultPath = Join-Path $Root 'normal-result.json'
$FailurePath = Join-Path $Root 'normal-failure.json'
$Deadline = [DateTime]::UtcNow.AddSeconds(20)
while (-not [IO.File]::Exists($ResultPath)) {
    if ([IO.File]::Exists($FailurePath)) {
        throw [IO.File]::ReadAllText($FailurePath)
    }
    if ([DateTime]::UtcNow -ge $Deadline) {
        throw 'TEST_NORMAL_WORKER_DEADLINE'
    }
    Start-Sleep -Milliseconds 50
}

$Normal = [IO.File]::ReadAllText($ResultPath) | ConvertFrom-Json
$AuditReport = $null
foreach ($Name in $Names) {
    $Directory = Join-Path $Root $Name
    $Active = Join-Path $Directory 'active.json'
    if ($Successful -notcontains $Name) {
        Assert-Equal -Actual (Get-Snapshot -Path $Active) -Expected $Before[$Name] -Context "$Name unchanged"
        continue
    }

    $Previous = Get-Snapshot -Path (Join-Path $Directory 'previous.json')
    Assert-Equal -Actual $Previous -Expected $Before[$Name] -Context "$Name retained original"
    $Current = Get-Snapshot -Path $Active
    foreach ($Field in @('group', 'dacl', 'protected', 'labels', 'attributes')) {
        Assert-Equal -Actual $Current[$Field] -Expected $Previous[$Field] -Context "$Name $Field"
    }
    Assert-Equal -Actual ($Current.control -band (-bnot 0x2c00)) -Expected ($Previous.control -band (-bnot 0x2c00)) -Context "$Name non-audit descriptor control"
    Assert-Equal -Actual $Current.owner -Expected $User.Value -Context "$Name accepted owner"
    if ($Name -eq 'audit-protected') {
        Assert-Equal -Actual $Previous.auditProtected -Expected $true -Context 'protected original audit retained'
        Assert-Equal -Actual $Current.auditProtected -Expected $false -Context 'protected source does not suppress candidate audit inheritance'
        Assert-Equal -Actual $Current.inherited -Expected 1 -Context 'candidate inherits parent audit'
        Assert-Equal -Actual $Current.explicit -Expected 0 -Context 'candidate does not clone protected audits'
    }
    if ($Name -eq 'audit') {
        Assert-Equal -Actual $Current.auditProtected -Expected $false -Context 'candidate inherits folder auditing'
        $Parent = [IO.Directory]::GetAccessControl($Directory, $AuditSection)
        $ParentRules = @($Parent.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $CurrentAudit = [IO.File]::GetAccessControl($Active, $AuditSection)
        $CurrentRules = @($CurrentAudit.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))
        Assert-Equal -Actual $CurrentRules.Count -Expected 1 -Context 'one inherited candidate audit'
        Assert-Equal -Actual $CurrentRules[0].IdentityReference.Value -Expected $ParentRules[0].IdentityReference.Value -Context 'audit principal'
        Assert-Equal -Actual ([int]$CurrentRules[0].FileSystemRights) -Expected ([int]$ParentRules[0].FileSystemRights) -Context 'audit rights'
        Assert-Equal -Actual ([int]$CurrentRules[0].AuditFlags) -Expected ([int]$ParentRules[0].AuditFlags) -Context 'audit flags'
        $AuditReport = @{
            sourceExplicit = $Previous.explicit
            sourceInherited = $Previous.inherited
            candidateExplicit = $Current.explicit
            candidateInherited = $Current.inherited
            previousExact = $true
        }
    }
}

[ordered]@{
    normal = $Normal
    audit = $AuditReport
    securityVerified = $true
} | ConvertTo-Json -Depth 6 -Compress
