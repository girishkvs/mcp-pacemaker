param(
    [Parameter(Mandatory)][string]$Node,
    [Parameter(Mandatory)][string]$Evidence,
    [string]$RuntimeRoot,
    [ValidateSet('normal-delete', 'recycle', 'abrupt-root-loss', 'shared-abrupt',
        'concurrent-abrupt', 'pool-abrupt', 'auth-abrupt', 'owner-loss', 'supervisor-restart')][string]$Mode = 'abrupt-root-loss'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if ($RuntimeRoot) { $Repo = [IO.Path]::GetFullPath($RuntimeRoot) }
$Bridge = Join-Path $Repo 'bin\mcp-bridge.mjs'
$Fixture = Join-Path $PSScriptRoot 'fixture.mjs'
$Expiry = Join-Path $PSScriptRoot 'expiry.mjs'
$ExpiryUri = [Uri]::new($Expiry).AbsoluteUri

function Save-Json($Path, $Value) {
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Value -Depth 20))
}

function Add-Event($Case, $Event, $Value) {
    $entry = @{ at = [DateTime]::UtcNow.ToString('o'); event = $Event; data = $Value }
    [IO.File]::AppendAllText(
        (Join-Path $Case.Directory 'observations.jsonl'),
        (ConvertTo-Json -InputObject $entry -Depth 15 -Compress) + "`n")
}

function Get-Identity($Record) {
    @{
        role = $Record.Role
        pid = $Record.Id
        parentPid = $Record.ParentId
        creationUtc = $Record.CreationUtc
        creationTicks = $Record.StartTicks.ToString()
        cimCreationUtc = $Record.CimCreationUtc
        name = $Record.Name
    }
}

function Add-OwnedProcess($Case, [int] $ProcessId, $Parent, [string] $Role, $Existing = $null) {
    $process = $Existing
    if ($null -eq $process) {
        $process = [Diagnostics.Process]::GetProcessById($ProcessId)
    }
    try {
        $null = $process.Handle
        $created = $process.StartTime.ToUniversalTime()
        $known = @($Case.Records | Where-Object {
            $_.Id -eq $ProcessId -and
            $_.StartTicks -eq $created.Ticks
        })
        if ($known.Count -ne 0) {
            if ($Role -ne 'cleanup-discovered') { $known[0].Role = $Role }
            if ($process -ne $known[0].Process) { $process.Dispose() }
            return $known[0]
        }
        $row = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" `
            -Property ProcessId,ParentProcessId,CreationDate,Name
        if ($null -eq $row) { throw "Identity query lost owned PID $ProcessId" }
        $creationDifference = [Math]::Abs($created.Ticks - $row.CreationDate.ToUniversalTime().Ticks)
        if ($creationDifference -gt 10000) { throw "Creation identity changed for PID $ProcessId" }
        if ($null -ne $Parent) {
            $Parent.Process.Refresh()
            $outsideParentLifetime = $created.Ticks -lt $Parent.StartTicks
            if ($Parent.Process.HasExited) {
                $outsideParentLifetime = $outsideParentLifetime -or
                    $created -gt $Parent.Process.ExitTime.ToUniversalTime()
            }
            if ($row.ParentProcessId -ne $Parent.Id -or
                $outsideParentLifetime) {
                throw "Owned ancestry check failed for PID $ProcessId"
            }
        }
        $record = [pscustomobject]@{
            Role = $Role
            Id = $ProcessId
            ParentId = [int] $row.ParentProcessId
            StartTicks = $created.Ticks
            CreationUtc = $created.ToString('o')
            CimCreationUtc = $row.CreationDate.ToUniversalTime().ToString('o')
            Name = $row.Name
            Process = $process
        }
        $Case.Records.Add($record)
        Add-Event $Case 'identity-captured-handle-held' (Get-Identity $record)
        return $record
    } catch {
        if ($process -ne $Existing) { $process.Dispose() }
        throw
    }
}

function Get-Liveness($Record) {
    $Record.Process.Refresh()
    $alive = -not $Record.Process.HasExited
    if ($alive -and
        $Record.Process.StartTime.ToUniversalTime().Ticks -ne $Record.StartTicks) {
        throw "Captured process identity changed for PID $($Record.Id)"
    }
    $identity = Get-Identity $Record
    $identity.alive = $alive
    if (-not $alive) {
        $identity.exitUtc = $Record.Process.ExitTime.ToUniversalTime().ToString('o')
        $identity.exitCode = $Record.Process.ExitCode
    }
    return $identity
}

function Stop-OwnedProcess($Case, $Record, $Reason) {
    $state = Get-Liveness $Record
    if (-not $state.alive) {
        Add-Event $Case 'already-exited' $state
        return
    }
    Add-Event $Case 'identity-checked-single-process-kill' @{
        reason = $Reason
        identity = $state
        method = 'System.Diagnostics.Process.Kill() on held process handle; no tree/name kill'
    }
    $Record.Process.Kill()
    if (-not $Record.Process.WaitForExit(3000)) {
        throw "Owned PID $($Record.Id) did not exit within 3000 ms"
    }
    Add-Event $Case 'exit-verified' (Get-Liveness $Record)
}

function Find-OwnedDescendants($Case) {
    for ($index = 0; $index -lt $Case.Records.Count; $index++) {
        $parent = $Case.Records[$index]
        $rows = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($parent.Id)" `
            -Property ProcessId,ParentProcessId,CreationDate,Name)
        foreach ($row in $rows) {
            $born = $row.CreationDate.ToUniversalTime()
            $parent.Process.Refresh()
            if ($born.Ticks -lt ($parent.StartTicks - 10000)) { continue }
            if ($parent.Process.HasExited -and
                $born -gt $parent.Process.ExitTime.ToUniversalTime()) {
                continue
            }
            $known = @($Case.Records | Where-Object {
                $_.Id -eq [int] $row.ProcessId -and
                [Math]::Abs($_.StartTicks - $born.Ticks) -le 10000
            })
            if ($known.Count -ne 0) { continue }
            try {
                $null = Add-OwnedProcess $Case ([int] $row.ProcessId) $parent 'cleanup-discovered'
            } catch [ArgumentException] {
                Add-Event $Case 'discovered-child-already-gone' @{ pid = [int] $row.ProcessId }
            }
        }
        if ($Case.Records.Count -gt 16) { throw 'Unexpected fixture process count; cleanup must be reviewed' }
    }
}

function Wait-ReadyFile($Case, $Role, $Directory = $Case.Directory) {
    $path = Join-Path $Directory "$Role.ready.json"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 8) {
        if (Test-Path -LiteralPath $path) {
            try { return ([IO.File]::ReadAllText($path) | ConvertFrom-Json) }
            catch [ArgumentException] { }
        }
        if (-not (Get-Liveness $Case.Records[0]).alive) { throw 'Bridge exited during fixture readiness' }
        Start-Sleep -Milliseconds 100
    }
    throw "Owned $Role readiness timed out"
}

function Get-Heartbeats($Case) {
    while ($Case.HeartbeatListener.Pending()) {
        $client = $Case.HeartbeatListener.AcceptTcpClient()
        if (-not [Net.IPAddress]::IsLoopback($client.Client.RemoteEndPoint.Address)) {
            $client.Dispose()
            throw 'Heartbeat connection was not loopback'
        }
        $client.NoDelay = $true
        $Case.HeartbeatConnections.Add([pscustomobject]@{
            Client = $client
            Stream = $client.GetStream()
            Buffer = ''
        })
        if ($Case.HeartbeatConnections.Count -gt $Case.MaximumHeartbeatConnections) {
            throw 'Unexpected heartbeat connection count'
        }
    }
    foreach ($connection in $Case.HeartbeatConnections) {
        while ($connection.Stream.DataAvailable) {
            $bytes = [byte[]]::new(4096)
            $count = $connection.Stream.Read($bytes, 0, $bytes.Length)
            if ($count -eq 0) { break }
            $connection.Buffer += [Text.Encoding]::UTF8.GetString($bytes, 0, $count)
        }
        $newline = $connection.Buffer.IndexOf("`n")
        while ($newline -ge 0) {
            $line = $connection.Buffer.Substring(0, $newline)
            $connection.Buffer = $connection.Buffer.Substring($newline + 1)
            $message = $line | ConvertFrom-Json
            if ($message.role -notin @('standin', 'worker')) {
                throw 'Unexpected heartbeat role'
            }
            $recordRole = if ($message.role -eq 'standin') { 'npx-standin' } else { 'worker' }
            $owner = @($Case.Records | Where-Object {
                $_.Id -eq $message.pid -and
                $_.Role -in @($recordRole, "$recordRole-2")
            })
            if ($owner.Count -ne 1 -or
                $owner[0].Id -ne $message.pid) {
                throw 'Heartbeat PID does not match its captured owned identity'
            }
            $key = if ($owner[0].Role.EndsWith('-2')) { "$($message.role)-2" } else { $message.role }
            $previous = $Case.Heartbeats[$key]
            if ($null -ne $previous -and
                $message.sequence -le $previous.sequence) {
                throw 'Heartbeat sequence did not increase'
            }
            $Case.Heartbeats[$key] = $message
            Add-Event $Case 'socket-heartbeat-received' $message
            $newline = $connection.Buffer.IndexOf("`n")
        }
    }
    return $Case.Heartbeats.Clone()
}

function Save-Observation($Case, $Label) {
    $value = @{
        label = $Label
        at = [DateTime]::UtcNow.ToString('o')
        elapsedMs = $Case.Timer.ElapsedMilliseconds
        identities = @($Case.Records | ForEach-Object { Get-Liveness $_ })
        heartbeats = Get-Heartbeats $Case
    }
    Add-Event $Case 'observation' $value
    return $value
}

function New-Request($Method, $Uri, $Body = $null, $SessionId = $null) {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Uri)
    $request.Headers.ConnectionClose = $true
    if ($null -ne $Body) {
        $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json')
    }
    if ($null -ne $SessionId) {
        $null = $request.Headers.TryAddWithoutValidation('mcp-session-id', $SessionId)
    }
    return $request
}

function Start-AdditionalTree($Case, $Root, $Directory, $Uri, $Mode, $Body) {
    $task = $null
    if ($Mode -ne 'pool-abrupt') {
        $request = New-Request 'POST' $Uri $Body
        $task = $Case.Client.SendAsync($request)
    }
    $standinReady = Wait-ReadyFile $Case 'standin' $Directory
    $outer = Add-OwnedProcess $Case $standinReady.parentPid $Root 'outer-cmd-2'
    $standin = Add-OwnedProcess $Case $standinReady.pid $outer 'npx-standin-2'
    [IO.File]::WriteAllText((Join-Path $Directory 'allow-inner'), 'Identities captured')
    $workerReady = Wait-ReadyFile $Case 'worker' $Directory
    $inner = Add-OwnedProcess $Case $workerReady.parentPid $standin 'inner-cmd-2'
    $null = Add-OwnedProcess $Case $workerReady.pid $inner 'worker-2'
    [IO.File]::WriteAllText((Join-Path $Directory 'allow-worker'), 'Identities captured')
    if ($Mode -eq 'concurrent-abrupt') {
        if (-not $task.Wait(8000)) { throw 'Second MCP initialization timed out' }
        $response = $task.GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ne 200 -or
            $body -notmatch 'owned-nested-fixture') { throw 'Second MCP initialization failed' }
        $response.Dispose()
        $request.Dispose()
    }
}

function Finish-Cleanup($Case) {
    [IO.File]::WriteAllText((Join-Path $Case.Directory 'cancel-spawn'), 'No additional fixture spawns')
    $errors = [Collections.Generic.List[string]]::new()
    # File gates limit births. Parent lifetime bounds reject PID reuse in failure-path discovery.
    try { Find-OwnedDescendants $Case } catch { $errors.Add($_.Exception.Message) }
    for ($index = $Case.Records.Count - 1; $index -ge 0; $index--) {
        try { Stop-OwnedProcess $Case $Case.Records[$index] 'final-owned-cleanup' }
        catch { $errors.Add($_.Exception.Message) }
    }
    try { Find-OwnedDescendants $Case } catch { $errors.Add($_.Exception.Message) }
    for ($index = $Case.Records.Count - 1; $index -ge 0; $index--) {
        try {
            if ((Get-Liveness $Case.Records[$index]).alive) {
                Stop-OwnedProcess $Case $Case.Records[$index] 'late-owned-descendant'
            }
        } catch { $errors.Add($_.Exception.Message) }
    }
    # Normally unused; allow the 45 s self-expiry backstop a bounded final chance.
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        $live = @($Case.Records | Where-Object { (Get-Liveness $_).alive })
        if ($live.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    }
    $identities = @($Case.Records | ForEach-Object { Get-Liveness $_ })
    $survivors = @($identities | Where-Object { $_.alive })
    if ($survivors.Count -ne 0) {
        $errors.Add('ERROR: owned process still alive after bounded cleanup: ' +
            (($survivors | ForEach-Object { $_.pid }) -join ','))
    }
    $receipt = @{
        completedAt = [DateTime]::UtcNow.ToString('o')
        allCapturedIdentitiesGone = $survivors.Count -eq 0
        identities = $identities
        errors = @($errors)
    }
    Save-Json (Join-Path $Case.Directory 'cleanup-receipt.json') $receipt
    foreach ($stream in @('Stdout', 'Stderr')) {
        $task = $Case[$stream]
        if ($null -ne $task) {
            if ($task.Wait(2000)) {
                [IO.File]::WriteAllText(
                    (Join-Path $Case.Directory ("bridge.$($stream.ToLowerInvariant()).txt")),
                    $task.GetAwaiter().GetResult())
            } else {
                $errors.Add("Owned bridge $stream capture did not finish")
            }
        }
    }
    # The bridge creates this private nonce itself. It is never read or used by this probe.
    $nonce = Join-Path $Case.Directory 'admin.nonce'
    if (Test-Path -LiteralPath $nonce) { [IO.File]::Delete($nonce) }
    $receipt.privateUnusedNonceRemoved = -not (Test-Path -LiteralPath $nonce)
    foreach ($connection in $Case.HeartbeatConnections) { $connection.Client.Dispose() }
    $Case.HeartbeatListener.Stop()
    $receipt.heartbeatConnectionsDisposed = $Case.HeartbeatConnections.Count
    $receipt.heartbeatListenerStopped = $true
    $receipt.errors = @($errors)
    Save-Json (Join-Path $Case.Directory 'cleanup-receipt.json') $receipt
    foreach ($record in $Case.Records) { $record.Process.Dispose() }
    $Case.Client.Dispose()
    if ($errors.Count -ne 0) { throw ($errors -join '; ') }
    return $receipt
}

function Invoke-Case([string] $Mode) {
    $directory = Join-Path $Evidence ($Mode + '-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $directory
    $case = @{
        Directory = $directory
        Records = [Collections.Generic.List[object]]::new()
        Timer = [Diagnostics.Stopwatch]::StartNew()
        Stdout = $null
        Stderr = $null
        Client = [Net.Http.HttpClient]::new([Net.Http.HttpClientHandler]@{ UseProxy = $false })
        HeartbeatListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        HeartbeatConnections = [Collections.Generic.List[object]]::new()
        Heartbeats = @{}
        MaximumHeartbeatConnections = 2
    }
    $case.Client.Timeout = [TimeSpan]::FromSeconds(15)
    $result = @{ mode = $Mode; directory = $directory; outcome = 'SETUP_NOT_COMPLETED' }
    $failure = $null
    try {
        $case.HeartbeatListener.Start()
        $heartbeatPort = $case.HeartbeatListener.LocalEndpoint.Port
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $listener.Stop()
        if ($port -eq 8792) { throw 'Refusing live runtime port' }
        $serverName = 'owned-' + [Guid]::NewGuid().ToString('N')
        $configPath = Join-Path $directory 'servers.json'
        $config = @{
            $serverName = @{
                command = 'node'
                args = @($Fixture, 'standin', $directory)
                sharing = $(if ($Mode -eq 'shared-abrupt') { 'shared' } else { 'isolated' })
                minWarm = 0
                maxSessions = 1
                recycleMinutes = 0
            }
        }
        $additional = $Mode -in @('concurrent-abrupt', 'pool-abrupt', 'auth-abrupt')
        $secondDirectory = Join-Path $directory 'second'
        if ($additional) {
            $null = New-Item -ItemType Directory -Path $secondDirectory
            $case.MaximumHeartbeatConnections = 4
            $config["$serverName-second"] = @{
                command = 'node'
                args = @($Fixture, 'standin', $secondDirectory)
                sharing = $(if ($Mode -eq 'pool-abrupt') { 'pool' } else { 'isolated' })
                minWarm = $(if ($Mode -eq 'pool-abrupt') { 1 } else { 0 })
            }
            if ($Mode -eq 'auth-abrupt') {
                $config["$serverName-second"] = @{
                    type = 'http'
                    url = "http://127.0.0.1:$port/unused-owned-upstream"
                    auth = @{
                        type = 'command'
                        command = '"' + $Node + '" "' + $Fixture + '" standin "' + $secondDirectory + '"'
                    }
                }
            }
        }
        Save-Json $configPath $config
        $environment = @{
            SystemRoot = $env:SystemRoot
            WINDIR = $env:SystemRoot
            ComSpec = Join-Path $env:SystemRoot 'System32\cmd.exe'
            PATH = (Split-Path $Node) + ';' + (Join-Path $env:SystemRoot 'System32')
            PATHEXT = '.COM;.EXE;.BAT;.CMD'
            USERPROFILE = $directory
            HOME = $directory
            TEMP = $directory
            TMP = $directory
            MCP_CONFIG_WATCH = '0'
            MCP_RESUME = '0'
            MCP_IDLE_TIMEOUT_MS = '0'
            MCP_HEALTH_INTERVAL_MS = '0'
            MCP_RECYCLE_MINUTES = '0'
            MCP_INIT_TIMEOUT_MS = '15000'
            PROBE_HEARTBEAT_PORT = "$heartbeatPort"
        }
        Save-Json (Join-Path $directory 'inputs.json') @{
            node = $Node
            bridge = $Bridge
            expiryPreload = $Expiry
            expiryImportUrl = $ExpiryUri
            fixture = $Fixture
            config = $config
            environmentAllowlist = $environment
            host = '127.0.0.1'
            port = $port
            heartbeatPort = $heartbeatPort
            selfExpiryMs = 45000
            launchMethod = 'Actual candidate CLI entry point with --config, --cwd and private --import expiry'
            readiness = 'File IPC gates before inner spawn and worker input; MCP initialize; advancing loopback TCP heartbeats'
        }
        $start = [Diagnostics.ProcessStartInfo]::new($Node)
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.WorkingDirectory = $directory
        $start.Environment.Clear()
        foreach ($key in $environment.Keys) { $start.Environment[$key] = $environment[$key] }
        $entry = if ($Mode -eq 'supervisor-restart') { Join-Path $Repo 'supervisor\supervise.mjs' } else { $Bridge }
        $arguments = @('--import', $ExpiryUri, $entry, '--port', "$port", '--config', $configPath)
        if ($Mode -ne 'supervisor-restart') { $arguments += @('--host', '127.0.0.1', '--cwd', $directory) }
        foreach ($argument in $arguments) {
            $start.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Owned bridge launch failed' }
        $case.Stdout = $process.StandardOutput.ReadToEndAsync()
        $case.Stderr = $process.StandardError.ReadToEndAsync()
        # Record the directly launched root before any CIM call can fail.
        $null = $process.Handle
        $rootCreated = $process.StartTime.ToUniversalTime()
        $root = [pscustomobject]@{
            Role = $(if ($Mode -eq 'supervisor-restart') { 'supervisor' } else { 'bridge' })
            Id = $process.Id
            ParentId = $PID
            StartTicks = $rootCreated.Ticks
            CreationUtc = $rootCreated.ToString('o')
            CimCreationUtc = $null
            Name = 'node.exe'
            Process = $process
        }
        $case.Records.Add($root)
        Add-Event $case 'direct-launch-identity-captured-handle-held' (Get-Identity $root)
        $rootRow = Get-CimInstance Win32_Process -Filter "ProcessId = $($root.Id)" `
            -Property ProcessId,ParentProcessId,CreationDate,Name
        if ($null -eq $rootRow -or
            $rootRow.ParentProcessId -ne $PID) {
            throw 'Direct launch ancestry could not be confirmed'
        }
        $root.CimCreationUtc = $rootRow.CreationDate.ToUniversalTime().ToString('o')
        Add-Event $case 'direct-launch-cim-confirmed' (Get-Identity $root)
        $baseUri = "http://127.0.0.1:$port"
        $ready = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            if (-not (Get-Liveness $root).alive) { throw 'Owned bridge exited before listening' }
            if (Test-Path -LiteralPath (Join-Path $directory 'admin.nonce')) {
                $response = $case.Client.GetAsync("$baseUri/api/status").GetAwaiter().GetResult()
                $status = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
                $response.Dispose()
                $expectedServers = if ($additional) { 2 } else { 1 }
                if (@($status.servers).Count -ne $expectedServers -or
                    $serverName -notin @($status.servers | ForEach-Object { $_.name })) {
                    throw 'Loopback endpoint does not match the private fixture config'
                }
                $ready = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $ready) { throw 'Private bridge listen readiness timed out' }
        Find-OwnedDescendants $case
        $supervisor = $null
        if ($Mode -eq 'supervisor-restart') {
            $supervisor = $root
            $bridges = @($case.Records | Where-Object {
                $_.ParentId -eq $supervisor.Id -and
                $_.Name -eq 'node.exe'
            })
            if ($bridges.Count -ne 1) { throw 'Expected one owned bridge under the actual supervisor' }
            $root = $bridges[0]
            $root.Role = 'bridge'
        }
        $init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"owned-root-loss-probe","version":"0.0.0"}}}'
        $initRequest = New-Request 'POST' "$baseUri/$serverName/mcp" $init
        $initTask = $case.Client.SendAsync($initRequest)
        $standinReady = Wait-ReadyFile $case 'standin'
        $outer = Add-OwnedProcess $case $standinReady.parentPid $root 'outer-cmd'
        $standin = Add-OwnedProcess $case $standinReady.pid $outer 'npx-standin'
        if ($outer.Name -ne 'cmd.exe' -or
            $standin.Name -ne 'node.exe') {
            throw 'Unexpected outer fixture process shape'
        }
        [IO.File]::WriteAllText((Join-Path $directory 'allow-inner'), 'Captured outer-cmd and standin identities')
        $workerReady = Wait-ReadyFile $case 'worker'
        $inner = Add-OwnedProcess $case $workerReady.parentPid $standin 'inner-cmd'
        $worker = Add-OwnedProcess $case $workerReady.pid $inner 'worker'
        if ($inner.Name -ne 'cmd.exe' -or
            $worker.Name -ne 'node.exe') {
            throw 'Unexpected inner fixture process shape'
        }
        [IO.File]::WriteAllText((Join-Path $directory 'allow-worker'), 'Captured inner-cmd and worker identities')
        if (-not $initTask.Wait(8000)) { throw 'MCP initialization timed out' }
        $response = $initTask.GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $directory 'initialize-response.txt'), $body)
        if ([int] $response.StatusCode -ne 200 -or
            $body -notmatch 'owned-nested-fixture') {
            throw 'MCP initialize did not confirm the owned worker'
        }
        $sessionId = @($response.Headers.GetValues('mcp-session-id'))[0]
        $response.Dispose()
        $initRequest.Dispose()
        if ($additional) {
            Start-AdditionalTree $case $root $secondDirectory "$baseUri/$serverName-second/mcp" $Mode $init
        }
        $first = Save-Observation $case 'initialized'
        Start-Sleep -Milliseconds 600
        $before = Save-Observation $case 'before-action'
        foreach ($role in $before.heartbeats.Keys) {
            if ($before.heartbeats[$role].sequence -le $first.heartbeats[$role].sequence) {
                throw "Owned $role heartbeat did not advance before action"
            }
        }
        if ($case.Timer.Elapsed.TotalSeconds -ge 20) {
            throw 'Readiness too slow: refusing action near fixture expiry'
        }
        $result.before = $before
        if ($Mode -in @('normal-delete', 'recycle')) {
            if ($Mode -eq 'recycle') {
                $request = New-Request 'POST' "$baseUri/admin/recycle/$serverName"
                $nonce = [IO.File]::ReadAllText((Join-Path $directory 'admin.nonce')).Trim()
                $null = $request.Headers.TryAddWithoutValidation('x-mcp-nonce', $nonce)
            } else {
                $request = New-Request 'DELETE' "$baseUri/$serverName/mcp" $null $sessionId
            }
            $response = $case.Client.SendAsync($request).GetAwaiter().GetResult()
            $result.httpStatus = [int] $response.StatusCode
            $response.Dispose()
            $request.Dispose()
            $expectedStatus = if ($Mode -eq 'recycle') { 200 } else { 204 }
            if ($result.httpStatus -ne $expectedStatus) { throw 'Normal cleanup was not accepted' }
            $wait = [Diagnostics.Stopwatch]::StartNew()
            while ($wait.Elapsed.TotalSeconds -lt 6) {
                $alive = @($case.Records | Where-Object {
                    $_.Role -match '^(outer-cmd|npx-standin|inner-cmd|worker)(-2)?$' -and
                    (Get-Liveness $_).alive
                })
                if ($alive.Count -eq 0) { break }
                Start-Sleep -Milliseconds 100
            }
            $result.after = Save-Observation $case 'after-supported-delete'
            Start-Sleep -Milliseconds 600
            $result.finalObservation = Save-Observation $case 'delete-heartbeat-stability'
        } else {
            $target = $root
            if ($Mode -eq 'owner-loss') {
                $owners = @($case.Records | Where-Object {
                    $_.Name -eq 'ProcessLifetimeHelper.exe' -and
                    $_.ParentId -eq $root.Id
                })
                if ($owners.Count -ne 1) { throw 'Expected one owned job helper' }
                $target = $owners[0]
            }
            Stop-OwnedProcess $case $target 'abrupt-owned-lifetime-root-loss'
            Start-Sleep -Milliseconds 1000
            $result.after = Save-Observation $case 'one-second-after-abrupt-loss'
            Start-Sleep -Milliseconds 2000
            $result.finalObservation = Save-Observation $case 'three-seconds-after-abrupt-loss'
        }
        $survivors = @($result.finalObservation.identities | Where-Object {
            $_.role -match '^(outer-cmd|npx-standin|inner-cmd|worker)(-2)?$' -and
            $_.alive
        })
        $result.survivingDescendants = $survivors.Count
        $result.nativeOwners = @($result.finalObservation.identities | Where-Object {
            $_.name -eq 'ProcessLifetimeHelper.exe' -and
            $_.parentPid -eq $root.Id
        })
        $result.containmentPassed = $survivors.Count -eq 0
        $result.outcome = if ($result.containmentPassed) { 'NO_DESCENDANTS_SURVIVED' } else { 'DESCENDANTS_SURVIVED' }
        $result.heartbeatEvidence = @{}
        foreach ($role in $before.heartbeats.Keys) {
            $recordRole = $role.Replace('standin', 'npx-standin')
            $alive = @($survivors | Where-Object { $_.role -eq $recordRole }).Count -eq 1
            $advanced = $result.finalObservation.heartbeats[$role].sequence -gt
                $result.after.heartbeats[$role].sequence
            $result.heartbeatEvidence[$role] = @{
                alive = $alive
                firstPostActionSequence = $result.after.heartbeats[$role].sequence
                finalSequence = $result.finalObservation.heartbeats[$role].sequence
                firstPostActionAt = $result.after.heartbeats[$role].at
                finalAt = $result.finalObservation.heartbeats[$role].at
                advancedAfterAction = $advanced
            }
            if ($Mode -notin @('normal-delete', 'recycle') -and
                $alive -and
                -not $advanced) {
                throw "Surviving owned $role did not heartbeat after root loss"
            }
            if ($Mode -in @('normal-delete', 'recycle') -and
                -not $alive -and
                $advanced) {
                throw "Owned $role heartbeat advanced after verified DELETE exit"
            }
        }
        if ($Mode -eq 'supervisor-restart') {
            $response = $case.Client.GetAsync("$baseUri/api/status").GetAwaiter().GetResult()
            $replacement = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
            $response.Dispose()
            if ($replacement.instanceId -eq $status.instanceId -or
                $replacement.sessions -ne 0) { throw 'Supervisor did not restart cleanly without replaying sessions' }
            Find-OwnedDescendants $case
            $result.replacement = @{ instanceChanged = $true; sessions = $replacement.sessions; responsive = $true }
        }
    } catch {
        $failure = $_.Exception.Message
        $result.error = $failure
        Add-Event $case 'probe-error' @{ message = $failure }
    } finally {
        try { $result.cleanup = Finish-Cleanup $case }
        catch {
            $result.cleanupError = $_.Exception.Message
            $failure = 'Cleanup error: ' + $_.Exception.Message
        }
        Save-Json (Join-Path $directory 'result.json') $result
    }
    if ($null -ne $failure) { throw $failure }
    return $result
}

$result = Invoke-Case $Mode
Write-Output (ConvertTo-Json -InputObject $result -Depth 20 -Compress)
