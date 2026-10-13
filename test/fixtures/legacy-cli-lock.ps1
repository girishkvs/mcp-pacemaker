<#
.SYNOPSIS
Holds an owned fixture CLI file open without write sharing.
.DESCRIPTION
Signals readiness on stdout and releases the file when stdin supplies one line.
.PARAMETER Path
Exact owned test file.
.OUTPUTS
A readiness line.
.EXAMPLE
.\legacy-cli-lock.ps1 -Path C:\owned-fixture\cli.mjs
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
$handle = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    [Console]::Out.WriteLine('held')
    [Console]::Out.Flush()
    $null = [Console]::In.ReadLine()
}
finally { $handle.Dispose() }
