function Get-OracleExplorerContext {
    <#
    .SYNOPSIS
    Finds an existing Explorer context before the audit oracle changes fixture policy.
    .DESCRIPTION
    Reports absent processes or windows; COM and process discovery errors remain failures.
    .PARAMETER SessionId
    Windows session whose existing Explorer context is required.
    .PARAMETER FindProcesses
    Process discovery callback, replaceable by isolated capability tests.
    .PARAMETER CreateShell
    Shell discovery callback, replaceable by isolated capability tests.
    .OUTPUTS
    An Explorer object or a structured unavailable report. Discovery errors propagate.
    .EXAMPLE
    Get-OracleExplorerContext
    #>
    [CmdletBinding()]
    param(
        [int]$SessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId,
        [scriptblock]$FindProcesses = { [Diagnostics.Process]::GetProcessesByName('explorer') },
        [scriptblock]$CreateShell = { New-Object -ComObject Shell.Application }
    )

    # Dot-property access can suppress getter exceptions and falsely report a missing capability.
    $Processes = @(& $FindProcesses |
        Where-Object { $_.PSObject.Properties['SessionId'].get_Value() -eq $SessionId })
    $Capability = [ordered]@{
        stage = 'explorer-process-discovery'
        sessionId = $SessionId
        explorerPids = @($Processes | ForEach-Object { $_.PSObject.Properties['Id'].get_Value() })
        policyChanged = $false
    }
    $Report = [ordered]@{
        unavailable = 'TEST-SETUP existing ordinary Explorer context unavailable'
        capability = $Capability
    }
    if ($Processes.Count -eq 0) {
        return @{ Explorer = $null; Report = $Report }
    }

    $Capability.stage = 'explorer-window-discovery'
    $Shell = & $CreateShell
    $Explorer = @($Shell.Windows()) |
        Where-Object {
            $FullName = $_.PSObject.Properties['FullName'].get_Value()
            $FullName -and
            [IO.Path]::GetFileName($FullName) -ieq 'explorer.exe'
        } |
        Select-Object -First 1
    if ($null -eq $Explorer) {
        return @{ Explorer = $null; Report = $Report }
    }
    return @{ Explorer = $Explorer; Report = $null }
}
