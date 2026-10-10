param([Parameter(Mandatory)][string]$Helper)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFile($Helper)
$guardType = $assembly.GetType('TaskChannelGuard', $true)
$factsType = $assembly.GetType('ActorFacts', $true)
$guard = [Activator]::CreateInstance($guardType, $true)
$method = $guardType.GetMethod('RequireAdmin', [Reflection.BindingFlags]'Instance,NonPublic')
$results = @()
$cases = @('valid','elevated','enabledAdministrator','restricted','appContainer','guardThreadImpersonating','parentThreadImpersonation')
foreach ($case in $cases) {
    $facts = [Activator]::CreateInstance($factsType, $true)
    $facts.elevated = $true
    $facts.enabledAdministrator = $true
    $facts.parentThreadImpersonation = 'observed-none'
    if ($case -eq 'elevated' -or
        $case -eq 'enabledAdministrator') { $facts.$case = $false }
    elseif ($case -eq 'parentThreadImpersonation') { $facts.$case = 'not-observed' }
    elseif ($case -ne 'valid') { $facts.$case = $true }
    $accepted = $false
    try { $method.Invoke($guard, @($facts)); $accepted = $true }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        if ($exception.Message -ne 'ACTUAL_ADMIN_TOKEN_REQUIRED') { throw }
    }
    $results += @{ case = $case; accepted = $accepted }
}
$identityType = $assembly.GetType('Identity', $true)
$peerMethod = $guardType.GetMethod('CheckPeer', [Reflection.BindingFlags]'Instance,NonPublic')
$peerResults = @()
foreach ($case in @('valid','sid','session','birth')) {
    $identity = [Activator]::CreateInstance($identityType, $true)
    $identity.ownerSid = 'S-1-5-21-1-2-3-1000'
    $identity.sessionId = 2
    $identity.creationTime = '134359000000000001'
    if ($case -eq 'sid') { $identity.ownerSid = 'S-1-5-21-1-2-3-1001' }
    elseif ($case -eq 'session') { $identity.sessionId = 3 }
    elseif ($case -eq 'birth') { $identity.creationTime = '134359000000000002' }
    $accepted = $false
    try { $peerMethod.Invoke($guard, @($identity,'S-1-5-21-1-2-3-1000',2,'134359000000000001')); $accepted = $true }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        if ($exception.Message -ne 'PEER_IDENTITY_MISMATCH') { throw }
    }
    $peerResults += @{ case = $case; accepted = $accepted }
}
@{ qualification = 'pure-policy-model-not-OS-authorization'; results = $results; peerResults = $peerResults } |
    ConvertTo-Json -Depth 5 -Compress
