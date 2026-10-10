param([Parameter(Mandatory)][string]$Helper)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFile($Helper)
$type = $assembly.GetType('ChannelCliContext', $true)
$factsType = $assembly.GetType('ActorFacts', $true)
$observationType = $assembly.GetType('ContextObservation', $true)
$context = [Runtime.Serialization.FormatterServices]::GetUninitializedObject($type)
$method = $type.GetMethod('Eligible', [Reflection.BindingFlags]'Instance,NonPublic')
$results = @()
foreach($case in @('complete','elevated','admin','guard-token','parent-token','unknown','incomplete','changed-primary',
    'empty','too-many','atomic-claim','missing-facts','missing-observation')) {
    $facts = [Activator]::CreateInstance($factsType, $true)
    $facts.parentThreadImpersonation = 'observed-none'
    $observation = [Activator]::CreateInstance($observationType, $true)
    $observation.completeStableThreadSet = $true
    $observation.primaryStable = $true
    $observation.threadCount = 8
    switch ($case) {
        'elevated' { $facts.elevated = $true }
        'admin' { $facts.enabledAdministrator = $true }
        'guard-token' { $facts.guardThreadImpersonating = $true }
        'parent-token' { $facts.parentThreadImpersonation = 'observed-impersonating' }
        'unknown' { $facts.parentThreadImpersonation = 'unverified' }
        'incomplete' { $observation.completeStableThreadSet = $false }
        'changed-primary' { $observation.primaryStable = $false }
        'empty' { $observation.threadCount = 0 }
        'too-many' { $observation.threadCount = 129 }
        'atomic-claim' { $observation.atomicFutureProtection = $true }
        'missing-facts' { $facts = $null }
        'missing-observation' { $observation = $null }
    }
    $eligible = $method.Invoke($context, @($facts, $observation))
    $results += @{ case = $case; eligible = $eligible }
}
@{ qualification = 'pure-policy-only-no-token-mutation'; results = $results } | ConvertTo-Json -Depth 5 -Compress
