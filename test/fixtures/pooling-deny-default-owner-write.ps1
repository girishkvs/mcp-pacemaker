param([Parameter(Mandatory)][string] $Path)

$ErrorActionPreference = 'Stop'
$fullPath = [IO.Path]::GetFullPath($Path)
$directory = [IO.Path]::GetDirectoryName($fullPath)
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$ownedFixture = [IO.Path]::GetDirectoryName($directory) -eq $temporaryRoot -and
    [IO.Path]::GetFileName($directory).StartsWith('pooling-postcommit-') -and
    [IO.Path]::GetFileName($fullPath) -eq 'servers.json'
if (-not $ownedFixture) { throw 'Only the owned temporary fixture is accepted.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $acl = Get-Acl -LiteralPath $fullPath
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $owner.Equals($identity.Owner)) { throw 'Fixture is not owned by the token default owner.' }
    $deny = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity.User,
        [Security.AccessControl.FileSystemRights]::WriteData,
        [Security.AccessControl.AccessControlType]::Deny)
    $acl.AddAccessRule($deny)
    Set-Acl -LiteralPath $fullPath -AclObject $acl
    $after = Get-Acl -LiteralPath $fullPath
    if (-not $after.GetOwner([Security.Principal.SecurityIdentifier]).Equals($owner)) {
        throw 'Fixture setup changed the default owner.'
    }
} finally {
    $identity.Dispose()
}
