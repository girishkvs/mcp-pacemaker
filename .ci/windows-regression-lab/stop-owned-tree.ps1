param(
    [Parameter(Mandatory)][int] $ProcessId,
    [Parameter(Mandatory)][int] $ExpectedParent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Stop-OwnedProcess {
    param([int] $Id, [int] $ParentId)
    $item = Get-CimInstance Win32_Process -Filter "ProcessId=$Id"
    if ($null -eq $item) {
        return
    }
    if ($item.ParentProcessId -ne $ParentId) {
        throw 'PROCESS_OWNERSHIP_CHANGED'
    }
    foreach ($child in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$Id")) {
        Stop-OwnedProcess -Id $child.ProcessId -ParentId $Id
    }
    $current = Get-CimInstance Win32_Process -Filter "ProcessId=$Id"
    if ($null -ne $current) {
        $sameProcess = (
            $current.ParentProcessId -eq $ParentId -and
            $current.CreationDate -eq $item.CreationDate
        )
        if (-not $sameProcess) {
            throw 'PROCESS_ID_REUSED'
        }
        Stop-Process -Id $Id -Force
    }
}
Stop-OwnedProcess -Id $ProcessId -ParentId $ExpectedParent
