param([Parameter(Mandatory)][string]$Helper)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFile($Helper)
$type = $assembly.GetType('ChannelSession', $true)
$snapshotType = $assembly.GetType('SessionSnapshot', $true)
$session = [Activator]::CreateInstance($type, $true)
$flags = [Reflection.BindingFlags]'Instance,NonPublic'
$validate = $type.GetMethod('Validate', $flags)
$results = @()
foreach ($case in @('active','disconnected','connected','idle','listen','reset','down','init','shadow',
    'no-logon','wrong-owner','no-owner','wrong-session','changed-generation','stale-generation','changed-name')) {
    $before = [Activator]::CreateInstance($snapshotType, $true)
    $after = [Activator]::CreateInstance($snapshotType, $true)
    foreach ($value in @($before,$after)) {
        $value.sessionId = 2
        $value.state = 0
        $value.logonTime = 134358000000000001
        $value.shortUser = 'owned'
        $value.shortDomain = 'MODEL'
    }
    $resolved = 'S-1-5-21-1-2-3-1000'
    $expectedLogon = '134358000000000001'
    $states = @{ disconnected = 4; connected = 1; idle = 5; listen = 6; reset = 7; down = 8; init = 9; shadow = 3 }
    if ($states.ContainsKey($case)) { $before.state = $states[$case]; $after.state = $states[$case] }
    elseif ($case -eq 'no-logon') { $before.logonTime = 0; $after.logonTime = 0 }
    elseif ($case -eq 'wrong-owner') { $resolved = 'S-1-5-21-1-2-3-1001' }
    elseif ($case -eq 'no-owner') { $resolved = '' }
    elseif ($case -eq 'wrong-session') { $after.sessionId = 3 }
    elseif ($case -eq 'changed-generation') { $after.logonTime++ }
    elseif ($case -eq 'stale-generation') { $expectedLogon = '134358000000000002' }
    elseif ($case -eq 'changed-name') { $after.shortUser = 'different' }
    $accepted = $false
    $reason = $null
    try {
        $fact = $validate.Invoke($session, @($before,$after,$resolved,'S-1-5-21-1-2-3-1000',2,$expectedLogon))
        $accepted = $true
        if ($fact.atomicRunExBinding) { throw 'False atomicity claim.' }
    }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        $reason = $exception.Message
        if (-not $reason.StartsWith('SESSION_')) { throw }
    }
    $results += @{ case = $case; accepted = $accepted; reason = $reason }
}
$query = $type.GetMethod('RequireQuery', $flags)
foreach ($code in @(5,7022,1332)) {
    try { $query.Invoke($session, @($false,$code)); throw 'Failed query accepted.' }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        if ($exception.Message -ne "SESSION_QUERY_FAILED_$code") { throw }
        $results += @{ case = "query-failed-$code"; accepted = $false; reason = $exception.Message }
    }
}
$requireUser = $type.GetMethod('RequireUser', $flags)
foreach ($use in @(2,3,4,8,9)) {
    try { $requireUser.Invoke($session, @($use)); throw 'Non-user SID accepted.' }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        if ($exception.Message -ne 'SESSION_ACCOUNT_NOT_USER') { throw }
        $results += @{ case = "non-user-$use"; accepted = $false; reason = $exception.Message }
    }
}
@{ qualification = 'pure-session-policy-model-no-session-mutations'; results = $results } |
    ConvertTo-Json -Depth 5 -Compress
