param(
    [Parameter(Mandatory)][string] $Archive,
    [Parameter(Mandatory)][string] $Destination
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$parent = Get-Item -LiteralPath (Split-Path -Parent $Destination)
if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'INVALID_EXTRACTION_PARENT'
}
if (Test-Path -LiteralPath $Destination) {
    throw 'EXTRACTION_DESTINATION_EXISTS'
}
$zip = [IO.Compression.ZipFile]::OpenRead($Archive)
try {
    if ($zip.Entries.Count -gt 128) {
        throw 'TOO_MANY_BUNDLE_ENTRIES'
    }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $entries = [Collections.Generic.List[object]]::new()
    [long] $total = 0
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        $parts = $name.TrimEnd('/').Split('/')
        foreach ($part in $parts) {
            $invalid = (
                $part -notmatch '^[A-Za-z0-9_.-]+$' -or
                $part -in @('.', '..') -or
                $part.EndsWith('.') -or
                $part -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)'
            )
            if ($invalid) {
                throw 'INVALID_BUNDLE_PATH'
            }
        }
        $relative = $parts -join '\'
        if (-not $names.Add($relative)) {
            throw 'DUPLICATE_BUNDLE_PATH'
        }
        $unixType = ($entry.ExternalAttributes -shr 16) -band 0xF000
        $invalidType = (
            $unixType -notin @(0, 0x4000, 0x8000) -or
            ($entry.ExternalAttributes -band 0x400) -ne 0
        )
        if ($invalidType) {
            throw 'LINK_OR_SPECIAL_FILE_IN_BUNDLE'
        }
        $total += $entry.Length
        if ($total -gt 32MB) {
            throw 'EXPANDED_BUNDLE_TOO_LARGE'
        }
        $entries.Add([pscustomobject]@{
            Entry = $entry
            Relative = $relative
            Directory = $name.EndsWith('/')
        })
    }
    if (-not $names.Contains('run.ps1')) {
        throw 'BUNDLE_ENTRYPOINT_MISSING'
    }
    New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
    [long] $writtenTotal = 0
    $buffer = [byte[]]::new(65536)
    foreach ($item in $entries) {
        $target = Join-Path $Destination $item.Relative
        if ($item.Directory) {
            [IO.Directory]::CreateDirectory($target) | Out-Null
            continue
        }
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        $source = $item.Entry.Open()
        try {
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            try {
                [long] $writtenEntry = 0
                while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $writtenEntry += $count
                    $writtenTotal += $count
                    if ($writtenTotal -gt 32MB) {
                        throw 'EXPANDED_BUNDLE_TOO_LARGE'
                    }
                    $output.Write($buffer, 0, $count)
                }
                if ($writtenEntry -ne $item.Entry.Length) {
                    throw 'BUNDLE_ENTRY_LENGTH_MISMATCH'
                }
            }
            finally {
                $output.Dispose()
            }
        }
        finally {
            $source.Dispose()
        }
    }
}
finally {
    $zip.Dispose()
}
