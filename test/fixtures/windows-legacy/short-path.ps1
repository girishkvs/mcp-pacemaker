param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
$filesystem = New-Object -ComObject Scripting.FileSystemObject
$folder = $null
try {
    $folder = $filesystem.GetFolder($Path)
    @{ path = $folder.ShortPath } | ConvertTo-Json -Compress
} finally {
    if ($folder) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($folder) }
    $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($filesystem)
}
