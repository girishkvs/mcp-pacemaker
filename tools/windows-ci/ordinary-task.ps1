<#
.SYNOPSIS
Owns one existing-user, least-privilege CI task and its cleanup.
.DESCRIPTION
The guardian is launched before the controller joins its lifetime job. It owns
create/run/cleanup of one no-trigger InteractiveToken task. The worker starts
the explicit Node executable with only the supplied non-secret environment.
.PARAMETER InputDirectory
New private run directory created by ordinary-run.mjs.
.PARAMETER Worker
Internal task-action role; the native Node caller check still applies.
.PARAMETER CheckOnly
Reads the exact recorded task name and requires absence; performs no writes.
.PARAMETER Recover
Retries only cleanup after a recorded guardian cleanup failure, never execution.
.OUTPUTS
Separate guardian, native-drain, task-instance, cleanup and bootstrap receipts.
.EXAMPLE
.\tools\windows-ci\ordinary-task.ps1 -InputDirectory C:\private\ordinary-run -CheckOnly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputDirectory,
    [switch]$Worker,
    [switch]$CheckOnly,
    [switch]$Recover
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Write-Receipt {
    param([string]$Name, [object]$Value)
    $path = Join-Path $InputDirectory $Name
    $temporary = "$path.tmp.$PID"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $path
}

function Get-Digest {
    param([string]$Text, [byte[]]$Bytes)
    if ($null -eq $Bytes) { $Bytes = [Text.Encoding]::UTF8.GetBytes($Text) }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Get-TaskDigest {
    param([string]$Xml)
    $document = [xml]$Xml
    return Get-Digest -Text $document.OuterXml
}

$inputPath = Join-Path $InputDirectory 'input.json'
if (-not $Worker -and
    -not $CheckOnly -and
    -not $Recover) {
    Write-Receipt -Name 'guardian-host-ready.json' -Value @{ pid = $PID;
        creationTime = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc().ToString() }
}
$inputDeadline = [DateTime]::UtcNow.AddSeconds(45)
while (-not (Test-Path -LiteralPath $inputPath)) {
    if ([DateTime]::UtcNow -gt $inputDeadline) { throw 'Controller input never arrived; no task created.' }
    Start-Sleep -Milliseconds 100
}
$inputBytes = [IO.File]::ReadAllBytes($inputPath)
$inputText = [Text.Encoding]::UTF8.GetString($inputBytes)
$inputRecord = $inputText | ConvertFrom-Json
$inputHash = Get-Digest -Bytes $inputBytes
if ([Guid]::ParseExact($inputRecord.runId, 'D').ToString('D') -cne $inputRecord.runId -or
    $inputRecord.taskName -cne "mcp-pacemaker-ci-$($inputRecord.runId)" -or
    ($InputDirectory + $PSCommandPath + $inputRecord.node) -match '["\r\n]') {
    throw 'Invalid owned task input binding.'
}
$taskName = $inputRecord.taskName
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $service.GetFolder('\')

function Get-OwnedTask {
    try { return $folder.GetTask($taskName) }
    catch {
        if ($_.Exception.GetBaseException().HResult -ne -2147024894) { throw }
        return $null
    }
}

if ($CheckOnly) {
    if ($null -ne (Get-OwnedTask)) { throw 'Recorded CI task registration remains.' }
    '{"taskAbsent":true}'
    return
}

function Set-Cancellation {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $path = Join-Path $InputDirectory 'cancel.json'
    if (-not (Test-Path -LiteralPath $path) -and
        $PSCmdlet.ShouldProcess($path, 'Write owned cancellation receipt')) {
        try { Write-Receipt -Name 'cancel.json' -Value @{ runId = $inputRecord.runId } }
        catch { if (-not (Test-Path -LiteralPath $path)) { throw } }
    }
}

function Start-OwnerObserver {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Identity)
    if ($Identity.protocol -ne 1 -or
        $Identity.ownerPid -le 0 -or
        $Identity.ownerCreationTime -notmatch '^[1-9][0-9]{0,18}$') { throw 'Invalid recorded lifetime owner.' }
    $binary = Join-Path $inputRecord.cwd 'bin\windows-lifetime\ProcessLifetimeHelper.exe'
    $metadata = Get-Content -LiteralPath (Join-Path $inputRecord.cwd 'bin\windows-lifetime\ProcessLifetimeHelper.build.json') -Raw | ConvertFrom-Json
    if ((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $metadata.binarySha256) {
        throw 'Lifetime observer binary differs from packaged metadata.'
    }
    if (-not $PSCmdlet.ShouldProcess("owned lifetime owner $($Identity.ownerPid)", 'Start read-only observer')) {
        throw 'Required lifetime observation was declined.'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $binary
    $start.Arguments = "observe-owner $($Identity.ownerPid) $($Identity.ownerCreationTime)"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $ready = $process.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(5000) -or
        $ready.Result -cne 'MCP_JOB_OBSERVER_READY') {
        if (-not $process.HasExited) { $process.Kill() }
        throw 'Lifetime observation could not be armed.'
    }
    return @{ Process = $process; Output = $process.StandardOutput.ReadToEndAsync(); Error = $process.StandardError.ReadToEndAsync() }
}

function Wait-OwnerDrain {
    param([object]$Observer)
    if (-not $Observer.Process.WaitForExit(15000)) { throw 'Native job drain deadline exceeded.' }
    if (-not [Threading.Tasks.Task]::WaitAll(@($Observer.Output, $Observer.Error), 1000) -or
        $Observer.Process.ExitCode -ne 0 -or
        $Observer.Output.Result.Trim() -cne 'MCP_JOB_DRAINED' -or
        $Observer.Error.Result.Trim() -cne '') { throw 'Native job drain is unverified.' }
    return @{ verified = $true; ownerExited = $true; activeProcesses = 0 }
}

function Get-OwnedDefinition {
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.URI = "\$taskName"
    $definition.RegistrationInfo.Date = $inputRecord.createdAt
    $definition.RegistrationInfo.Description = "mcp-pacemaker CI $($inputRecord.runId) input=$inputHash"
    $definition.Principal.Id = 'ci-user'
    $definition.Principal.UserId = $inputRecord.expectedSid
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 0
    $definition.Settings.ExecutionTimeLimit = [Xml.XmlConvert]::ToString([TimeSpan]::FromMilliseconds($inputRecord.timeoutMs + 30000))
    $definition.Settings.RestartCount = 0
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.AllowHardTerminate = $true
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Actions.Context = 'ci-user'
    $action = $definition.Actions.Create(0)
    $action.Path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action.Arguments = "-NoProfile -NonInteractive -File `"$PSCommandPath`" -InputDirectory `"$InputDirectory`" -Worker"
    $action.WorkingDirectory = $inputRecord.cwd
    return $definition
}

function Assert-OwnedTask {
    param([object]$Task)
    if ($null -eq $Task -or
        $Task.Path -cne "\$taskName" -or
        (Get-TaskDigest -Xml $Task.Definition.XmlText) -cne $definitionHash) {
        throw 'Owned task definition changed; stop/delete refused.'
    }
}

if (-not $Worker) {
    $state = [ordered]@{ runId = $inputRecord.runId; registrationAttempted = $false; collision = $false;
        instanceId = $null; workerStarted = $false; controllerLost = $false; error = $null;
        cleanupError = $null; taskAbsent = $false; nativeDrain = $null; controllerDrain = $null; instanceCompleted = $false }
    $controlObserver = $null
    $workerObserver = $null
    $definition = $null
    $definitionHash = $null
    function Assert-Controller {
        if ($controlObserver.Process.HasExited -or
            (Test-Path -LiteralPath (Join-Path $InputDirectory 'cancel.json'))) {
            $state.controllerLost = $true
            throw 'CI controller exited or cancelled.'
        }
        $grace = if ($state.workerStarted) { 5000 } else { 0 }
        if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $inputRecord.deadline + $grace) {
            throw 'CI command deadline exceeded.'
        }
    }
    function Wait-Barrier {
        param([string]$Phase)
        Write-Receipt -Name "$Phase.json" -Value @{ runId = $inputRecord.runId }
        while (-not (Test-Path -LiteralPath (Join-Path $InputDirectory 'continue.json'))) {
            Assert-Controller
            if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $inputRecord.startDeadline) {
                throw 'CI registration barrier deadline exceeded.'
            }
            Start-Sleep -Milliseconds 100
        }
    }
    try {
        if ($Recover) {
            $guardianPath = Join-Path $InputDirectory 'guardian.json'
            if (Test-Path -LiteralPath $guardianPath) {
                $prior = Get-Content -LiteralPath $guardianPath -Raw | ConvertFrom-Json
            } else {
                $hostResult = Get-Content -LiteralPath (Join-Path $InputDirectory 'guardian-host-result.json') -Raw | ConvertFrom-Json
                $childExit = Get-Content -LiteralPath (Join-Path $InputDirectory 'guardian-child-exit.json') -Raw | ConvertFrom-Json
                $created = Get-Content -LiteralPath (Join-Path $InputDirectory 'task-created.json') -Raw | ConvertFrom-Json
                $started = Get-Content -LiteralPath (Join-Path $InputDirectory 'task-started.json') -Raw | ConvertFrom-Json
                if ($hostResult.runId -cne $inputRecord.runId -or
                    $hostResult.taskName -cne $taskName -or
                    $childExit.pid -ne $hostResult.childPid -or
                    ($null -eq $childExit.code -and $null -eq $childExit.signal) -or
                    $created.runId -cne $inputRecord.runId -or
                    $started.runId -cne $inputRecord.runId) { throw 'Guardian host cleanup evidence is incomplete.' }
                $prior = @{ collision = $false; registrationAttempted = $true;
                    cleanupError = 'Guardian host deadline'; instanceId = $started.instanceId }
            }
            if ($prior.collision -or
                -not $prior.registrationAttempted -or
                -not $prior.cleanupError) { throw 'No owned failed cleanup to recover.' }
            $state.registrationAttempted = $true
            $state.instanceId = $prior.instanceId
            $definition = Get-OwnedDefinition
            $definitionHash = Get-TaskDigest -Xml $definition.XmlText
            $binding = Get-Content -LiteralPath (Join-Path $InputDirectory 'task-binding.json') -Raw | ConvertFrom-Json
            if ($binding.inputSha256 -cne $inputHash -or
                $binding.definitionSha256 -cne $definitionHash) { throw 'Recorded cleanup binding differs.' }
        } else {
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
            $diagnostic = [ordered]@{
                isBuiltinAdministrator = $sid -match '^S-1-5-21-(?:[0-9]+-){3}500$'
                positiveSession = $session -gt 0
                registryAccess = 'unknown'
            }
            foreach ($name in @('EnableLUA', 'ConsentPromptBehaviorAdmin', 'FilterAdministratorToken')) {
                $diagnostic["${name}Present"] = $null
                $diagnostic[$name] = $null
            }
            try {
                $policy = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                $names = @($policy.GetValueNames())
                foreach ($name in @('EnableLUA', 'ConsentPromptBehaviorAdmin', 'FilterAdministratorToken')) {
                    $diagnostic["${name}Present"] = $names -contains $name
                    $diagnostic[$name] = $policy.GetValue($name)
                }
                $diagnostic.registryAccess = 'read'
            } catch {
                $diagnostic.registryAccess = if ($_.CategoryInfo.Category -eq 'PermissionDenied') { 'denied' } else { 'unavailable' }
            }
            Write-Receipt -Name 'task-diagnostic.json' -Value $diagnostic
            if (-not $diagnostic.positiveSession -or
                $diagnostic.registryAccess -cne 'read' -or
                $diagnostic.EnableLUA -ne 1 -or
                $inputRecord.expectedSid -cne $sid -or
                $inputRecord.expectedSession -ne $session) {
                throw 'Existing caller/session/UAC prerequisites are unverified; no task created.'
            }
            $definition = Get-OwnedDefinition
            $definitionHash = Get-TaskDigest -Xml $definition.XmlText
            Write-Receipt -Name 'task-binding.json' -Value @{ runId = $inputRecord.runId; inputSha256 = $inputHash; definitionSha256 = $definitionHash }
            $controlObserver = Start-OwnerObserver -Identity $inputRecord.owner
            Write-Receipt -Name 'guardian-ready.json' -Value @{ runId = $inputRecord.runId }
            while (-not (Test-Path -LiteralPath (Join-Path $InputDirectory 'registration-go.json'))) {
                Assert-Controller
                Start-Sleep -Milliseconds 100
            }
            if ($inputRecord.operation -eq 'probe-before-registration') { Wait-Barrier -Phase 'before-registration' }
            Assert-Controller
            if ($inputRecord.operation -eq 'probe-guardian-startup-stall') {
                Write-Receipt -Name 'guardian-stall-entered.json' -Value @{ runId = $inputRecord.runId; phase = 'startup' }
                [Threading.Thread]::Sleep(120000)
            }
            if ($null -ne (Get-OwnedTask)) { $state.collision = $true; throw 'Task name collision; existing task is not adopted.' }
            $state.registrationAttempted = $true
            try {
                # Create only, without adding a principal ACE; explicit null password and SDDL.
                $task = $folder.RegisterTaskDefinition($taskName, $definition, 18, $inputRecord.expectedSid, $null, 3, $null)
            } catch {
                if ($_.Exception.GetBaseException().HResult -in @(-2147024713, -2147024816)) { $state.collision = $true }
                throw
            }
            if ($inputRecord.operation -eq 'probe-registration-uncertain') { throw 'Owned registration response uncertainty control.' }
            Assert-OwnedTask -Task $task
            Write-Receipt -Name 'task-created.json' -Value @{ runId = $inputRecord.runId }
            if ($inputRecord.operation -in @('probe-after-registration', 'probe-mismatch', 'probe-input-change')) {
                Wait-Barrier -Phase 'after-registration'
            }
            Assert-Controller
            Assert-OwnedTask -Task (Get-OwnedTask)
            $running = $task.RunEx($null, 4, $inputRecord.expectedSession, $null)
            $state.instanceId = $running.InstanceGuid
            Write-Receipt -Name 'task-started.json' -Value @{ runId = $inputRecord.runId; instanceId = $state.instanceId }
            while (-not (Test-Path -LiteralPath (Join-Path $InputDirectory 'started.json'))) {
                Assert-Controller
                if (Test-Path -LiteralPath (Join-Path $InputDirectory 'bootstrap.json')) { throw 'Task bootstrap ended before lifetime readiness.' }
                if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $inputRecord.startDeadline) { throw 'Task worker startup deadline exceeded.' }
                Start-Sleep -Milliseconds 100
            }
            $started = Get-Content -LiteralPath (Join-Path $InputDirectory 'started.json') -Raw | ConvertFrom-Json
            if ($started.runId -cne $inputRecord.runId) { throw 'Worker lifetime receipt binding differs.' }
            $state.workerStarted = $true
            $workerObserver = Start-OwnerObserver -Identity $started.owner
            Write-Receipt -Name 'guardian-armed.json' -Value @{ runId = $inputRecord.runId;
                taskName = $taskName; inputSha256 = $inputHash; owner = $started.owner;
                armedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
            while (-not (Test-Path -LiteralPath (Join-Path $InputDirectory 'bootstrap.json'))) {
                Assert-Controller
                Start-Sleep -Milliseconds 100
            }
            if ($inputRecord.operation -eq 'probe-guardian-operation-stall') {
                Write-Receipt -Name 'guardian-stall-entered.json' -Value @{ runId = $inputRecord.runId; phase = 'operation' }
                [Threading.Thread]::Sleep(120000)
            }
        }
    } catch {
        $state.error = $_.Exception.Message -replace 'S-\d+(?:-\d+)+', '[SID]'
    } finally {
        try {
            if ($state.error) { Set-Cancellation }
            if ($state.controllerLost -and
                $null -ne $controlObserver -and
                $controlObserver.Process.HasExited) {
                $state.controllerDrain = Wait-OwnerDrain -Observer $controlObserver
            }
            if ($null -ne $workerObserver) {
                $state.nativeDrain = Wait-OwnerDrain -Observer $workerObserver
                Write-Receipt -Name 'guardian-drain.json' -Value $state.nativeDrain
            }
        } catch { $state.error = "Native cleanup unverified: $($_.Exception.Message)" }
        try {
            if ($state.registrationAttempted -and
                -not $state.collision) {
                $task = Get-OwnedTask
                if ($null -ne $task) {
                    Assert-OwnedTask -Task $task
                    $finishDeadline = [DateTime]::UtcNow.AddSeconds(5)
                    while ($task.GetInstances(0).Count -ne 0 -and
                        [DateTime]::UtcNow -lt $finishDeadline) { Start-Sleep -Milliseconds 100 }
                    foreach ($instance in $task.GetInstances(0)) {
                        Assert-OwnedTask -Task (Get-OwnedTask)
                        if ($instance.InstanceGuid -cne $state.instanceId) { throw 'Task instance binding is unknown; stop refused.' }
                        if (-not $Recover -and
                            $inputRecord.operation -eq 'probe-stop-failure') { throw 'Owned stop failure control.' }
                        $instance.Stop()
                    }
                    $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
                    while ($task.GetInstances(0).Count -ne 0 -and
                        [DateTime]::UtcNow -lt $stopDeadline) { Start-Sleep -Milliseconds 100 }
                    if ($task.GetInstances(0).Count -ne 0) { throw 'Owned task instance completion unverified.' }
                    $state.instanceCompleted = $null -ne $state.instanceId
                    Write-Receipt -Name $(if ($Recover) { 'task-instance-recovered.json' } else { 'task-instance.json' }) `
                        -Value @{ runId = $inputRecord.runId; instanceId = $state.instanceId; started = $null -ne $state.instanceId;
                            completed = $state.instanceCompleted; noActiveInstances = $true; lastTaskResult = $task.LastTaskResult }
                    Assert-OwnedTask -Task (Get-OwnedTask)
                    if (-not $Recover -and
                        $inputRecord.operation -eq 'probe-delete-failure') { throw 'Owned delete failure control.' }
                    $folder.DeleteTask($taskName, 0)
                }
            }
            $state.taskAbsent = $null -eq (Get-OwnedTask)
        } catch { $state.cleanupError = $_.Exception.Message -replace 'S-\d+(?:-\d+)+', '[SID]' }
        Write-Receipt -Name $(if ($Recover) { 'task-cleanup-recovered.json' } else { 'task-cleanup.json' }) `
            -Value @{ runId = $inputRecord.runId; taskAbsent = $state.taskAbsent; error = $state.cleanupError; collision = $state.collision }
        Write-Receipt -Name $(if ($Recover) { 'guardian-recovered.json' } else { 'guardian.json' }) -Value $state
        foreach ($observer in @($workerObserver, $controlObserver)) {
            if ($null -ne $observer) { $observer.Process.Dispose() }
        }
    }
    if ($state.error -or
        $state.cleanupError) { exit 1 }
    return
}

$allowed = @('PATH', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'OS', 'ProgramFiles',
    'ProgramFiles(x86)', 'ProgramData', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA',
    'TEMP', 'TMP', 'CI', 'MCP_NATIVE_COMPILER', 'MCP_NATIVE_REFERENCES', 'MCP_POOLING_TRACE_RUN_FAULTS')
$process = [Diagnostics.Process]::new()
$stdout = $null
$stderr = $null
$started = $false
$receipt = [ordered]@{ runId = $inputRecord.runId; exitCode = $null; childStarted = $false; error = $null }
try {
    $binding = Get-Content -LiteralPath (Join-Path $InputDirectory 'task-binding.json') -Raw | ConvertFrom-Json
    if ($binding.runId -cne $inputRecord.runId -or
        $binding.inputSha256 -cne $inputHash) { throw 'Task input changed after registration; Node launch refused.' }
    Write-Receipt -Name 'worker-bootstrap-entered.json' -Value @{ runId = $inputRecord.runId }
    if ($inputRecord.operation -eq 'probe-stop-failure') { Start-Sleep -Seconds 30 }
    if ($inputRecord.operation -eq 'probe-after-run') {
        while (-not (Test-Path -LiteralPath (Join-Path $InputDirectory 'continue.json'))) {
            if ((Test-Path -LiteralPath (Join-Path $InputDirectory 'cancel.json')) -or
                [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $inputRecord.startDeadline) {
                throw 'Owned task startup cancelled before Node launch.'
            }
            Start-Sleep -Milliseconds 100
        }
    }
    if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $inputRecord.startDeadline) { throw 'Task startup deadline expired.' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $inputRecord.node
    $start.Arguments = "`"$(Join-Path $PSScriptRoot 'ordinary-run.mjs')`" --worker `"$InputDirectory`""
    $start.WorkingDirectory = $inputRecord.cwd
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables.Clear()
    foreach ($entry in $inputRecord.environment.PSObject.Properties) {
        if ($entry.Name -cnotin $allowed) { throw 'Unexpected environment key in ordinary launch input.' }
        $start.EnvironmentVariables[$entry.Name] = [string]$entry.Value
    }
    $process.StartInfo = $start
    $stdout = [IO.File]::Open((Join-Path $InputDirectory 'bootstrap.stdout'), [IO.FileMode]::CreateNew)
    $stderr = [IO.File]::Open((Join-Path $InputDirectory 'bootstrap.stderr'), [IO.FileMode]::CreateNew)
    if (-not $process.Start()) { throw 'Ordinary Node process did not start.' }
    $started = $true
    $receipt.childStarted = $true
    $copyOut = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $copyErr = $process.StandardError.BaseStream.CopyToAsync($stderr)
    $remaining = $inputRecord.deadline - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 15000
    $wait = [int][Math]::Max(1, [Math]::Min($remaining, 3615000))
    if (-not $process.WaitForExit($wait)) {
        $process.Kill()
        if (-not $process.WaitForExit(10000)) { throw 'Owned Node process did not exit after bootstrap timeout.' }
        throw 'Ordinary Node bootstrap completion deadline exceeded.'
    }
    if (-not [Threading.Tasks.Task]::WaitAll(@($copyOut, $copyErr), 10000)) {
        throw 'Ordinary bootstrap output did not close.'
    }
    $receipt.exitCode = $process.ExitCode
} catch {
    $receipt.error = $_.Exception.Message
    if ($started -and
        -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(10000)) { $receipt.error += '; owned Node exit is unverified.' }
    }
} finally {
    if ($null -ne $stdout) { $stdout.Dispose() }
    if ($null -ne $stderr) { $stderr.Dispose() }
    $process.Dispose()
    if ($null -eq $receipt.exitCode) { $receipt.exitCode = 1 }
    Write-Receipt -Name 'bootstrap.json' -Value $receipt
}
exit $receipt.exitCode
