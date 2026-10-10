<#
.SYNOPSIS
Checks session facts for the original-user broker's bounded captured identities.
.DESCRIPTION
Reads a same-user request on stdin. Queries only its listed process identities,
or the selected managed loopback listener, and performs no process or security
mutation. Native held-generation revalidation remains the stop authority.
.OUTPUTS
A verification result without command lines or account identifiers.
.EXAMPLE
.\inspect-worker-process-sessions.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$watch = [Diagnostics.Stopwatch]::StartNew()
$stream = [Console]::OpenStandardInput()
$bytes = [byte[]]::new(131073)
$length = 0
while ($length -lt $bytes.Length) {
    $read = $stream.Read($bytes, $length, $bytes.Length - $length)
    if ($read -eq 0) { break }
    $length += $read
}
if ($length -gt 131072) { throw 'Worker identity request exceeds its bound.' }
$text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $length)
$request = $text | ConvertFrom-Json
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$hasSessionType = $request.sessionId -is [long] -or $request.sessionId -is [int]
if ($request.ownerSid -isnot [string] -or
    $request.ownerSid -cne $sid -or
    $request.ownerSid.Length -gt 184 -or
    -not $hasSessionType -or
    $request.sessionId -ne [Diagnostics.Process]::GetCurrentProcess().SessionId) {
    throw 'Worker process/session scope is not the actual current account.'
}
if ($null -ne $request.port) {
    if ((($request.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'ownerSid,port,sessionId') {
        throw 'Invalid managed listener request shape.'
    }
    $port = [int]$request.port
    if ($port -lt 1 -or
        $port -gt 65535 -or
        $null -ne $request.identities) { throw 'Invalid managed listener scope.' }
    $listeners = @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_NetTCPConnection `
        -Filter "LocalAddress='127.0.0.1' AND LocalPort=$port AND State=2" -OperationTimeoutSec 10)
    # A verified stopped/failed-start generation has no listener; its native proof is checked by the caller.
    if ($listeners.Count -eq 0) {
        '{"verified":true}'
        return
    }
    if ($listeners.Count -ne 1) { throw 'Managed listener is ambiguous.' }
    $processId = [int]$listeners[0].OwningProcess
    $row = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$processId" -OperationTimeoutSec 10
    $owner = Invoke-CimMethod -InputObject $row -MethodName GetOwnerSid -ErrorAction Stop
    if ($null -eq $row -or
        $row.SessionId -ne $request.sessionId -or
        $owner.ReturnValue -ne 0 -or
        $owner.Sid -cne $sid) { throw 'Managed listener account/session changed; replan before stop.' }
    '{"verified":true}'
    return
}
if ((($request.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'identities,ownerSid,sessionId' -or
    $request.identities -isnot [Array]) { throw 'Invalid captured identity request shape.' }
$identities = @($request.identities)
if ($identities.Count -lt 2 -or
    $identities.Count -gt 512) { throw 'Captured identity count is unsupported.' }
$seen = @{}
foreach ($identity in $identities) {
    if ((($identity.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'creationTime,ownerSid,pid' -or
        ($identity.pid -isnot [long] -and $identity.pid -isnot [int]) -or
        $identity.pid -le 0 -or
        $identity.pid -gt [int]::MaxValue -or
        $identity.ownerSid -isnot [string] -or
        $identity.creationTime -isnot [string]) { throw 'Invalid captured identity shape.' }
    $number = [int]$identity.pid
    if ($seen.ContainsKey($number) -or
        $identity.ownerSid -cne $sid -or
        $identity.creationTime -cnotmatch '^[1-9][0-9]{0,18}$') {
        throw 'Invalid original-user captured identity.'
    }
    $null = [DateTime]::FromFileTimeUtc([long]$identity.creationTime)
    $seen[$number] = $true
}
$query = {
    param([string]$Filter)
    $ErrorActionPreference = 'Stop'
    Import-Module CimCmdlets -ErrorAction Stop
    $session = New-CimSession -ErrorAction Stop
    try {
        foreach ($row in Get-CimInstance -CimSession $session -ClassName Win32_Process -Filter $Filter `
            -Property ProcessId, SessionId, CreationDate -OperationTimeoutSec 2) {
            [pscustomobject]@{
                pid = [int]$row.ProcessId
                sessionId = [int]$row.SessionId
                creationTicks = $row.CreationDate.ToUniversalTime().Ticks
            }
        }
    } finally { Remove-CimSession -CimSession $session }
}
$observed = @{}
$pool = [RunspaceFactory]::CreateRunspacePool(1, 4)
$pool.Open()
try {
    for ($offset = 0; $offset -lt $identities.Count; $offset += 128) {
        $pending = @()
        try {
            for ($index = $offset; $index -lt [Math]::Min($offset + 128, $identities.Count); $index += 32) {
                if ($watch.ElapsedMilliseconds -ge 13000) { throw 'Worker session query deadline.' }
                $batch = @($identities[$index..([Math]::Min($index + 31, $identities.Count - 1))])
                $expected = @{}
                $clauses = foreach ($identity in $batch) {
                    $expected[[int]$identity.pid] = $true
                    'ProcessId=' + ([int]$identity.pid).ToString([Globalization.CultureInfo]::InvariantCulture)
                }
                $pipeline = [PowerShell]::Create()
                $pipeline.RunspacePool = $pool
                $null = $pipeline.AddScript($query.ToString()).AddArgument(($clauses -join ' OR '))
                $pending += @{ Pipeline = $pipeline; Expected = $expected; Result = $pipeline.BeginInvoke() }
            }
            foreach ($item in $pending) {
                while (-not $item.Result.IsCompleted) {
                    if ($watch.ElapsedMilliseconds -ge 13000) { throw 'Worker session query deadline.' }
                    Start-Sleep -Milliseconds 10
                }
                $rows = @($item.Pipeline.EndInvoke($item.Result))
                if ($item.Pipeline.HadErrors -or
                    $rows.Count -ne $item.Expected.Count) { throw 'Worker session query did not return its exact captured set.' }
                foreach ($row in $rows) {
                    $number = [int]$row.pid
                    if (-not $item.Expected.ContainsKey($number) -or
                        $observed.ContainsKey($number)) { throw 'Worker session query returned an unexpected or duplicate identity.' }
                    $observed[$number] = $row
                }
            }
        } finally {
            foreach ($item in $pending) {
                if (-not $item.Result.IsCompleted) { $item.Pipeline.Stop() }
                $item.Pipeline.Dispose()
            }
        }
    }
} finally { $pool.Close(); $pool.Dispose() }
foreach ($identity in $identities) {
    $matching = $observed[[int]$identity.pid]
    if ($null -eq $matching -or
        $matching.sessionId -ne $request.sessionId) { throw 'Captured generation/session changed; replan before stop.' }
    $actual = $matching.creationTicks
    $expected = [DateTime]::FromFileTimeUtc([long]$identity.creationTime).Ticks
    # CIM creation dates have microsecond precision; this read never authorizes termination.
    if ([decimal]::Truncate([decimal]$actual / 10) -ne [decimal]::Truncate([decimal]$expected / 10)) {
        throw 'Captured process birth changed; replan before stop.'
    }
}
'{"verified":true}'
