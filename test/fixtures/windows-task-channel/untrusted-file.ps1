param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$descriptor = [Security.AccessControl.FileSecurity]::new()
$descriptor.SetOwner($sid)
$descriptor.SetAccessRuleProtection($true, $false)
$descriptor.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
$descriptor.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), [Security.AccessControl.FileSystemRights]::Write,
    [Security.AccessControl.AccessControlType]::Allow))
$stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path), [IO.FileMode]::CreateNew,
    [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $descriptor)
try { $stream.WriteByte(32) } finally { $stream.Dispose() }
'{"createdNew":true,"existingAclModified":false}'
