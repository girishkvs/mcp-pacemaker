<#
.SYNOPSIS
Runs one CI test contract as a provisioned ordinary local account.
.DESCRIPTION
A stock hosted Windows runner signs in as the built-in Administrator with a full elevated token, and
Task Scheduler ignores RunLevel for that account, so the product's user-runtime contract refuses
there. Creating a genuine standard account sidesteps that: the account is never an administrator, so
nothing has to be demoted, filtered or impersonated.

This is CI-only. It refuses to run anywhere except a GitHub-hosted runner, so it can never create an
account on a development machine. The account exists for one command and is removed afterwards.
.PARAMETER Contract
Test contract passed to tools/ci/run-tests.mjs.
.PARAMETER Repository
Absolute workspace root containing the checkout.
.PARAMETER NodePath
Absolute Node executable the worker must use.
.PARAMETER WorkerTimeoutMinutes
Upper bound on the worker, kept below the job timeout so cleanup always runs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('source-ordinary', 'compatibility')][string]$Contract,
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][string]$NodePath,
    [ValidateRange(1, 1440)][int]$WorkerTimeoutMinutes = 130
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'CI_ONLY: this provisions a local account and runs only on a GitHub-hosted runner.'
}
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($current -notmatch '^S-1-5-21-(?:[0-9]+-){3}500$') {
    throw "CI_ONLY: expected the hosted built-in Administrator context, found $current."
}
foreach ($path in @($Repository, $NodePath)) {
    if (-not [IO.Path]::IsPathRooted($path)) { throw "An absolute path is required: $path" }
}

$account = 'mcpordinary'
$work = Join-Path $env:RUNNER_TEMP "ordinary-$Contract"
$stdout = Join-Path $work 'worker.stdout.log'
$stderr = Join-Path $work 'worker.stderr.log'
$exitCode = 1
$positions = @{ $stdout = [int64]0; $stderr = [int64]0 }

function Remove-OwnedAccount {
    param([string]$Name)
    $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return }
    $sid = $existing.SID.Value
    # Read the authoritative profile location before deleting the record that holds it: Windows
    # appends .<COMPUTERNAME> or .000 on collision and honours a redirected ProfilesDirectory.
    $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $profilePath = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath `
        -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $profilePath) { $profilePath = Join-Path $env:SystemDrive "Users\$Name" }
    Remove-LocalUser -Name $Name
    Remove-Item -LiteralPath $profileKey -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $profilePath) {
        Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# The worker runs as a different account, so its output can only be collected through files. Stream
# them while it runs: a job-level timeout would otherwise kill this process before any final dump.
function Write-NewOutput {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $start = $positions[$Path]
        $end = $stream.Length
        if ($end -le $start) { return }
        $stream.Position = $start
        $buffer = New-Object byte[] ($end - $start)
        [void]$stream.Read($buffer, 0, $buffer.Length)
        $positions[$Path] = $end
        $text = [Text.Encoding]::UTF8.GetString($buffer).TrimEnd()
        if ($text) { Write-Host $text }
    }
    finally { $stream.Dispose() }
}

try {
    Remove-OwnedAccount -Name $account
    # Generated in memory for this job only; never written to disk, logged or exported.
    $raw = New-Object byte[] 48
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($raw)
    $secret = (([Convert]::ToBase64String($raw)) -replace '[^A-Za-z0-9]', '') + 'aA1!'
    $password = ConvertTo-SecureString $secret -AsPlainText -Force
    $secret = $null

    New-LocalUser -Name $account -Password $password -FullName 'mcp-pacemaker CI ordinary user' `
        -Description 'Disposable mcp-pacemaker CI account' `
        -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $account
    $elevated = @(Get-LocalGroupMember -Group 'Administrators' | Where-Object { $_.Name -like "*\$account" })
    if ($elevated.Count -ne 0) { throw 'The CI account must never be an administrator.' }

    $homeTree = Join-Path $work 'home'
    $temp = Join-Path $work 'temp'
    foreach ($directory in @($work, $homeTree, (Join-Path $homeTree 'AppData\Roaming'),
            (Join-Path $homeTree 'AppData\Local'), $temp)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    foreach ($grant in @(@{ Path = $work; Rights = '(OI)(CI)F' }, @{ Path = $Repository; Rights = '(OI)(CI)M' })) {
        $result = & icacls.exe $grant.Path /grant "${account}:$($grant.Rights)" /Q
        if ($LASTEXITCODE -ne 0) { throw "Could not grant the CI account access to $($grant.Path): $result" }
    }

    # A private home tree keeps the worker off the administrator's profile, which it cannot write,
    # and matches the private-home convention the other harnesses in this repository use.
    # Compatibility fixtures record the temp root that owns them, so an administrator-prepared
    # pair is correctly refused by the worker. Prepare, exercise and remove them in one account.
    # Preparation reads npm configuration through npm_execpath, so it must run as an npm script
    # rather than a bare node invocation.
    $npmCli = Join-Path (Split-Path -Parent $NodePath) 'node_modules\npm\bin\npm-cli.js'
    $contractCommands = if ($Contract -eq 'compatibility') {
        if (-not (Test-Path -LiteralPath $npmCli)) { throw "The npm CLI is not next to Node: $npmCli" }
        @("`"$NodePath`" `"$npmCli`" run compat:prepare",
            'if errorlevel 1 exit /b 1',
            "`"$NodePath`" tools\ci\run-tests.mjs $Contract",
            'set "CONTRACT_RESULT=%ERRORLEVEL%"',
            "`"$NodePath`" `"$npmCli`" run compat:clean",
            'exit /b %CONTRACT_RESULT%')
    } else {
        @("`"$NodePath`" tools\ci\run-tests.mjs $Contract")
    }
    $launcher = Join-Path $work 'run-contract.cmd'
    # The launcher is written as ASCII and uses `set "NAME=value"`, so a non-ASCII character would
    # be mangled and a literal % would break expansion. Assert rather than assume.
    foreach ($value in @($work, $homeTree, $temp, $Repository, $NodePath, $npmCli)) {
        if ($value -match '[^\x20-\x7E]' -or $value.Contains('%')) {
            throw "Launcher paths must be ASCII without '%': $value"
        }
    }
    Set-Content -LiteralPath $launcher -Encoding ascii -Value (@(
        '@echo off',
        "set `"USERPROFILE=$homeTree`"",
        "set `"HOME=$homeTree`"",
        "set `"APPDATA=$homeTree\AppData\Roaming`"",
        "set `"LOCALAPPDATA=$homeTree\AppData\Local`"",
        "set `"TEMP=$temp`"",
        "set `"TMP=$temp`"",
        'set "CI=true"',
        # Start-Process -Credential passes the parent's environment block, so the worker would
        # otherwise report the administrator's identity and ACL work would target the wrong account.
        "set `"USERNAME=$account`"",
        "set `"USERDOMAIN=$env:COMPUTERNAME`"",
        "set `"HOMEDRIVE=$($homeTree.Substring(0, 2))`"",
        "set `"HOMEPATH=$($homeTree.Substring(2))`"",
        "set `"MCP_POOLING_TRACE_RUN_FAULTS=$env:MCP_POOLING_TRACE_RUN_FAULTS`"",
        "set `"MCP_NATIVE_COMPILER=$env:MCP_NATIVE_COMPILER`"",
        "set `"MCP_NATIVE_REFERENCES=$env:MCP_NATIVE_REFERENCES`"",
        "cd /d `"$Repository`""
    ) + $contractCommands)
    foreach ($log in @($stdout, $stderr)) { New-Item -ItemType File -Path $log -Force | Out-Null }

    $credential = New-Object System.Management.Automation.PSCredential($account, $password)
    # -Wait would also wait for descendants, and this suite leaves detached native helpers running by
    # design, so wait on the worker itself and stream its output meanwhile.
    $process = Start-Process -FilePath $launcher -Credential $credential -WorkingDirectory $work `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    if ($null -eq $process) { throw 'The ordinary worker did not start.' }
    # Bound the wait below the job timeout so cleanup always runs: compat prepare/clean sit
    # outside the contract's own deadline, so a hang there would otherwise leak the account.
    $deadline = [DateTime]::UtcNow.AddMinutes($WorkerTimeoutMinutes)
    while (-not $process.HasExited) {
        Start-Sleep -Milliseconds 2000
        foreach ($log in @($stdout, $stderr)) { Write-NewOutput -Path $log }
        if ([DateTime]::UtcNow -gt $deadline) {
            Write-Host "The ordinary worker exceeded $WorkerTimeoutMinutes minutes; terminating."
            $process.Kill($true)
            break
        }
    }
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    if ($null -eq $exitCode) { throw 'The ordinary worker exit code is unavailable.' }
}
finally {
    foreach ($log in @($stdout, $stderr)) { Write-NewOutput -Path $log }
    $removalFailure = $null
    try { Remove-OwnedAccount -Name $account }
    catch { $removalFailure = $_ }
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne (Get-LocalUser -Name $account -ErrorAction SilentlyContinue)) {
        throw 'The disposable CI account was not removed.'
    }
    if ($null -ne $removalFailure) { throw $removalFailure }
}

exit $exitCode
