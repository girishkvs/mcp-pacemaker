param(
    [Parameter(Mandatory)][string] $Parent,
    [Parameter(Mandatory)][string] $Leaf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Leaf -notmatch '^windows-lab-[0-9]+-1$') {
    throw 'INVALID_WORK_DIRECTORY'
}
$directory = Get-Item -LiteralPath $Parent
if (-not $directory.PSIsContainer) {
    throw 'RUNNER_TEMP_NOT_DIRECTORY'
}
for ($item = $directory; $null -ne $item; $item = $item.Parent) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'REPARSE_POINT_IN_RUNNER_TEMP'
    }
}
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($directory.FullName))
if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
    throw 'RUNNER_TEMP_NOT_LOCAL'
}
$target = Join-Path $directory.FullName $Leaf
New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    foreach ($sid in @($identity.User, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $target -AclObject $acl
}
finally {
    $identity.Dispose()
}
