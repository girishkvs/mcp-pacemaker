param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
# Node reads this JSON as UTF-8. Without pinning the encoding the path is written in the console
# code page, so a non-ASCII name comes back corrupted and compares unequal to the original.
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$filesystem = New-Object -ComObject Scripting.FileSystemObject
$folder = $null
try {
    $folder = $filesystem.GetFolder($Path)
    @{ path = $folder.ShortPath } | ConvertTo-Json -Compress
} finally {
    if ($folder) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($folder) }
    $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($filesystem)
}
