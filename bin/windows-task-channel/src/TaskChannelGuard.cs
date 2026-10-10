using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

internal sealed class TaskChannelGuard
{
    private readonly ChannelNative native = new ChannelNative();
    private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 12 };
    private readonly UTF8Encoding utf8 = new UTF8Encoding(false, true);
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private Stream input;
    private Stream output;
    private ProcessHandle parent;
    private Identity controller;
    private Identity guardIdentity;
    private ProcessHandle heldPeer;
    private NamedPipeServerStream heldPipe;
    private Identity heldPeerIdentity;
    private SessionFact targetSession;
    private int limit = 13000;
    private long partialDeadline;
    private long handshakeDeadline;
    private Task<string> controlRead;
    private Task controlPump;
    private Task<Dictionary<string, object>> peerRead;
    private readonly Queue<Command> commands = new Queue<Command>();
    private readonly object commandLock = new object();
    private bool controlClosing;
    private bool readyPublished;
    private bool monitorStopped;

    private static int Main(string[] arguments)
    {
        if (arguments.Length != 0) return 2;
        return new TaskChannelGuard().Run();
    }

    private int Run()
    {
        input = Console.OpenStandardInput();
        output = Console.OpenStandardOutput();
        var monitor = new Thread(Monitor) { IsBackground = true };
        monitor.Start();
        try
        {
            try
            {
                int selfPid = Process.GetCurrentProcess().Id;
                using (var self = native.Open(selfPid))
                {
                    guardIdentity = native.Identity(selfPid, self);
                    Emit(new { type = "started" });
                    var initial = NextControl();
                    Wait(initial, 5000);
                    var request = Parse<Request>(initial.GetAwaiter().GetResult());
                    bool cliContext = request.action == "cli-context";
                    var context = new ChannelCliContext(native, CheckQueryProgress);
                    int parentPid;
                    if (cliContext)
                    {
                        // A blocking read on this synchronous pipe would block its server-PID query.
                        parentPid = context.Parent(self, selfPid);
                        StartControlReader();
                    }
                    else
                    {
                        StartControlReader();
                        parentPid = native.Parent(selfPid, self);
                    }
                    bool captureParentThreads = cliContext ||
                        request.action == "caller" ||
                        request.action == "serve";
                    parent = captureParentThreads ? context.OpenParent(parentPid) : native.Open(parentPid);
                    if (!native.Alive(parent) ||
                        native.Birth(parent) > native.Birth(self))
                        throw new InvalidOperationException("PARENT_GENERATION_INVALID");
                    controller = native.Identity(parentPid, parent);
                    using (parent)
                    using (var parentToken = native.Token(parent))
                    {
                        if (cliContext)
                        {
                            var observed = context.Observe(parent, controller);
                            Emit(new { type = "result", identity = controller, observed.proofScope,
                                observed.ordinaryEligible, observed.reason, observed.actorFacts, observed.observation });
                        }
                        else if (request.action == "caller")
                        {
                            Emit(new { type = "result", identity = controller, actorFacts = Facts() });
                        }
                        else if (request.action == "inspect-root")
                        {
                            using (var files = new ChannelFiles(controller.ownerSid, CheckQueryProgress))
                            {
                                var proof = files.InspectRoot(request.root);
                                Emit(new { type = "result", identity = controller, actorFacts = Facts(false), proof });
                            }
                        }
                        else if (request.action == "read-manifest") ReadManifest(request);
                        else if (request.action == "serve") Serve(request);
                        else throw new InvalidOperationException("UNKNOWN_ROLE");
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                try { Emit(new { type = "failed", reason = Reason(error), errorType = error.GetType().Name,
                    nativeError = error is Win32Exception ? ((Win32Exception)error).NativeErrorCode : 0 }); }
                catch (IOException) { }
                return 3;
            }
        }
        finally { Volatile.Write(ref monitorStopped, true); }
    }

    private Task<string> NextControl()
    {
        var next = Task.Run(() => Read(input, 65536));
        Volatile.Write(ref controlRead, next);
        return next;
    }

    private void StartControlReader()
    {
        controlPump = Task.Run(() =>
        {
            var parser = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 12 };
            int lastId = 0;
            while (true)
            {
                var value = parser.DeserializeObject(Read(input, 65536));
                if (!(value is Dictionary<string, object>)) throw new InvalidOperationException("OBJECT_FRAME_REQUIRED");
                var command = parser.ConvertToType<Command>(value);
                if (command.action == "close")
                {
                    Volatile.Write(ref controlClosing, true);
                    lock (commandLock)
                    {
                        if (commands.Count < 32) commands.Enqueue(command);
                    }
                    return;
                }
                if (command.action != "authorize" &&
                    command.action != "send") throw new InvalidOperationException("UNKNOWN_COMMAND");
                if (lastId == int.MaxValue ||
                    command.id != lastId + 1) throw new InvalidOperationException("COMMAND_SEQUENCE_INVALID");
                lastId = command.id;
                lock (commandLock)
                {
                    if (commands.Count >= 32) throw new InvalidOperationException("COMMAND_QUEUE_BOUNDS");
                    commands.Enqueue(command);
                }
            }
        });
    }

    private bool TryControl(out Command command)
    {
        lock (commandLock)
        {
            command = commands.Count == 0 ? null : commands.Dequeue();
            return command != null;
        }
    }

    private void NextPeerRead()
    {
        peerRead = Task.Run(ReadPeerFrame);
    }

    private Dictionary<string, object> ReadPeerFrame()
    {
        var parser = new JavaScriptSerializer { MaxJsonLength = 16384, RecursionLimit = 12 };
        var value = parser.DeserializeObject(Read(heldPipe, 16384, true));
        var frame = value as Dictionary<string, object>;
        if (frame == null) throw new InvalidOperationException("OBJECT_FRAME_REQUIRED");
        return frame;
    }

    private void CheckPeerRead()
    {
        if (peerRead != null &&
            peerRead.IsCompleted) peerRead.GetAwaiter().GetResult();
    }

    private bool CloseRequested(Task<string> task)
    {
        if (task == null ||
            task.Status != TaskStatus.RanToCompletion) return false;
        try
        {
            var parser = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 12 };
            var command = parser.Deserialize<Dictionary<string, object>>(task.Result);
            object action;
            return command != null && command.TryGetValue("action", out action) && (action as string) == "close";
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private int Deadline()
    {
        return Volatile.Read(ref readyPublished) ? Volatile.Read(ref limit) : Math.Min(13000, Volatile.Read(ref limit));
    }

    private void Monitor()
    {
        long cancellationAt = -1;
        Task<string> inspected = null;
        bool close = false;
        while (!Volatile.Read(ref monitorStopped))
        {
            try
            {
                var heldParent = Volatile.Read(ref parent);
                if (heldParent != null &&
                    !heldParent.IsClosed &&
                    !native.Alive(heldParent)) Environment.Exit(4);
                if (clock.ElapsedMilliseconds > Deadline()) Environment.Exit(4);
                var control = Volatile.Read(ref controlRead);
                if (control != inspected &&
                    control != null &&
                    control.IsCompleted)
                {
                    close = CloseRequested(control);
                    inspected = control;
                }
                var pump = Volatile.Read(ref controlPump);
                bool cancelled = Volatile.Read(ref controlClosing) ||
                    (control != null && (control.IsFaulted || control.IsCanceled || close)) ||
                    (pump != null && (pump.IsFaulted || pump.IsCanceled));
                if (cancelled &&
                    cancellationAt < 0) cancellationAt = clock.ElapsedMilliseconds;
                if (cancellationAt >= 0 &&
                    clock.ElapsedMilliseconds - cancellationAt >= 500) Environment.Exit(4);
            }
            catch (ObjectDisposedException) { return; }
            catch (Exception) { Environment.Exit(4); }
            Thread.Sleep(20);
        }
    }

    private string Reason(Exception error)
    {
        if (error is InvalidOperationException &&
            error.Message.Length < 100 &&
            error.Message.All(character => char.IsUpper(character) || char.IsDigit(character) || character == '_'))
            return error.Message;
        return "QUERY_OR_PROTOCOL_REFUSED";
    }

    private ActorFacts Facts(bool observeThreads = true)
    {
        CheckParent();
        var facts = native.Facts(parent, observeThreads, CheckQueryProgress);
        if (facts.ownerSid != controller.ownerSid ||
            facts.sessionId != controller.sessionId) throw new InvalidOperationException("PARENT_TOKEN_CHANGED");
        CheckParent();
        return facts;
    }

    private void RequireAdmin(ActorFacts facts)
    {
        bool authorized = facts.elevated &&
            facts.enabledAdministrator &&
            !facts.restricted &&
            !facts.appContainer &&
            !facts.guardThreadImpersonating &&
            facts.parentThreadImpersonation == "observed-none";
        if (!authorized) throw new InvalidOperationException("ACTUAL_ADMIN_TOKEN_REQUIRED");
    }

    private void CheckParent()
    {
        if (parent != null &&
            !native.Alive(parent)) throw new InvalidOperationException("PARENT_EXITED");
        var control = Volatile.Read(ref controlRead);
        if (control != null &&
            control.IsFaulted) throw new InvalidOperationException("CONTROL_DISCONNECTED");
        var pump = Volatile.Read(ref controlPump);
        if (pump != null &&
            pump.IsCompleted) pump.GetAwaiter().GetResult();
        if (clock.ElapsedMilliseconds > Deadline()) throw new InvalidOperationException("OPERATION_EXPIRED");
    }

    private void CheckQueryProgress()
    {
        CheckParent();
        if (Volatile.Read(ref controlClosing) ||
            CloseRequested(Volatile.Read(ref controlRead))) throw new InvalidOperationException("CONTROL_CLOSED");
    }

    private void Wait(Task task, int timeout)
    {
        long deadline = clock.ElapsedMilliseconds + timeout;
        while (!task.IsCompleted)
        {
            CheckParent();
            if (clock.ElapsedMilliseconds >= deadline) throw new InvalidOperationException("CHANNEL_DEADLINE");
            Thread.Sleep(20);
        }
        task.GetAwaiter().GetResult();
    }

    private T Parse<T>(string text)
    {
        if (string.IsNullOrEmpty(text)) throw new InvalidOperationException("EMPTY_FRAME");
        var value = json.DeserializeObject(text);
        if (!(value is Dictionary<string, object>)) throw new InvalidOperationException("OBJECT_FRAME_REQUIRED");
        return json.ConvertToType<T>(value);
    }

    private string Read(Stream stream, int maximum, bool peer = false)
    {
        using (var buffer = new MemoryStream())
        {
            while (true)
            {
                int value = stream.ReadByte();
                if (value < 0) throw new InvalidOperationException("CHANNEL_DISCONNECTED");
                if (value == 10)
                {
                    if (buffer.Length + 1 > maximum) throw new InvalidOperationException("FRAME_BOUNDS");
                    if (peer) Interlocked.Exchange(ref partialDeadline, 0);
                    return utf8.GetString(buffer.ToArray());
                }
                if (peer &&
                    buffer.Length == 0) Interlocked.Exchange(ref partialDeadline, clock.ElapsedMilliseconds + 5000);
                if (value == 13 ||
                    buffer.Length >= maximum) throw new InvalidOperationException("FRAME_BOUNDS_OR_FRAMING");
                buffer.WriteByte((byte)value);
            }
        }
    }

    private byte[] Bytes(object value, int maximum)
    {
        var bytes = utf8.GetBytes(json.Serialize(value) + "\n");
        if (bytes.Length > maximum) throw new InvalidOperationException("FRAME_BOUNDS");
        return bytes;
    }

    private void Emit(object value)
    {
        var envelope = json.Deserialize<Dictionary<string, object>>(json.Serialize(value));
        envelope.Add("guardIdentity", guardIdentity);
        var bytes = Bytes(envelope, 65536);
        output.Write(bytes, 0, bytes.Length);
        output.Flush();
    }

    private void Validate(Request request)
    {
        Guid operation;
        if (!Guid.TryParseExact(request.operationId, "D", out operation) ||
            operation.ToString("D") != request.operationId) throw new InvalidOperationException("OPERATION_ID_INVALID");
        if (new SecurityIdentifier(request.targetSid).Value != request.targetSid ||
            request.sessionId < 0) throw new InvalidOperationException("TARGET_INVALID");
        if (request.handshakeTimeoutMs < 2000 ||
            request.handshakeTimeoutMs > 30000 ||
            request.lifetimeMs < 2000 ||
            request.lifetimeMs > 900000) throw new InvalidOperationException("DEADLINE_BOUNDS");
        if (request.bootstrap == null ||
            request.document == null) throw new InvalidOperationException("BOOTSTRAP_REQUIRED");
        if (Bytes(request.document, 49152).Length < 3) throw new InvalidOperationException("DOCUMENT_REQUIRED");
    }

    private void BindBootstrap(ChannelFiles files, Bootstrap bootstrap, string manifestPath, string parentPath, string operationId, bool cross)
    {
        var node = files.HoldFile(bootstrap.nodePath, cross);
        var script = files.HoldFile(bootstrap.scriptPath, cross);
        if (files.Hash(node) != bootstrap.nodeSha256 ||
            files.Hash(script) != bootstrap.scriptSha256) throw new InvalidOperationException("BOOTSTRAP_HASH_MISMATCH");
        bootstrap.nodePath = files.Canonical(node);
        bootstrap.scriptPath = files.Canonical(script);
        var expected = new[] { bootstrap.scriptPath, "--manifest", manifestPath, "--operation", operationId,
            "--controller-root", parentPath };
        if (bootstrap.argv != null &&
            !bootstrap.argv.SequenceEqual(expected, StringComparer.Ordinal))
            throw new InvalidOperationException("BOOTSTRAP_ARGV_MISMATCH");
        bootstrap.argv = expected;
    }

    private Identity BindPeer(ChannelFiles files, int pid, ProcessHandle process, Bootstrap bootstrap,
        string targetSid, int sessionId, string expectedCreationTime)
    {
        var identity = native.Identity(pid, process);
        CheckPeer(identity, targetSid, sessionId, expectedCreationTime);
        using (var image = new FileStream(identity.imagePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (!string.Equals(files.Canonical(image), bootstrap.nodePath, StringComparison.OrdinalIgnoreCase) ||
                files.Hash(image) != bootstrap.nodeSha256) throw new InvalidOperationException("PEER_IMAGE_MISMATCH");
        }
        var arguments = native.Arguments(pid, process);
        if (arguments.Length != bootstrap.argv.Length + 1 ||
            !arguments.Skip(1).SequenceEqual(bootstrap.argv, StringComparer.Ordinal))
            throw new InvalidOperationException("PEER_ARGV_MISMATCH");
        identity.imageSha256 = bootstrap.nodeSha256;
        identity.argvSha256 = files.Digest(utf8.GetBytes(json.Serialize(arguments.Skip(1).ToArray())));
        if (!native.Alive(process)) throw new InvalidOperationException("PEER_EXITED");
        return identity;
    }

    private void CheckPeer(Identity identity, string targetSid, int sessionId, string expectedCreationTime)
    {
        if (identity.ownerSid != targetSid ||
            identity.sessionId != sessionId ||
            (expectedCreationTime != null && identity.creationTime != expectedCreationTime))
            throw new InvalidOperationException("PEER_IDENTITY_MISMATCH");
    }

    private void Serve(Request request)
    {
        Validate(request);
        limit = request.lifetimeMs;
        var facts = Facts();
        bool cross = request.targetSid != controller.ownerSid;
        if (cross) RequireAdmin(facts);
        targetSession = Session(request.targetSid, request.sessionId, null);
        using (var files = new ChannelFiles(controller.ownerSid))
        {
            var manifestParent = files.PathValue(request.manifestParent);
            files.Chain(manifestParent, true);
            var operationDirectory = Path.Combine(manifestParent, request.operationId);
            var manifestPath = Path.Combine(operationDirectory, "manifest.json");
            BindBootstrap(files, request.bootstrap, manifestPath, manifestParent, request.operationId, cross);
            if (cross)
            {
                files.HoldFile(controller.imagePath, true);
                files.HoldFile(Process.GetCurrentProcess().MainModule.FileName, true);
            }
            var endpoint = @"\\.\pipe\mcp-pacemaker-task-" + Guid.NewGuid().ToString("N");
            var pipeHandle = files.WithDescriptor(request.targetSid, false, security =>
                ChannelApi.CreateNamedPipeW(endpoint, 0x40080003, 8, 1, 16384, 16384, 0, ref security), true);
            if (pipeHandle.IsInvalid)
            {
                pipeHandle.Dispose();
                throw new InvalidOperationException("EXCLUSIVE_PIPE_CREATE_FAILED");
            }
            using (var pipe = new NamedPipeServerStream(PipeDirection.InOut, true, false, pipeHandle))
            {
                files.CreateDirectory(operationDirectory, request.targetSid);
                var manifest = new Manifest
                {
                    protocol = 1, operationId = request.operationId, targetSid = request.targetSid,
                    sessionId = request.sessionId, endpoint = endpoint, controllerIdentity = controller,
                    actorFacts = facts, bootstrap = request.bootstrap, document = request.document, targetSession = targetSession
                };
                files.CreateManifest(manifestPath, request.targetSid, Bytes(manifest, 65536));
                var connected = pipe.WaitForConnectionAsync();
                handshakeDeadline = clock.ElapsedMilliseconds + request.handshakeTimeoutMs;
                Emit(new { type = "ready", endpoint, manifestPath, actorFacts = facts, controllerIdentity = controller, targetSession });
                Volatile.Write(ref readyPublished, true);
                while (!connected.IsCompleted)
                {
                    CheckParent();
                    Command early;
                    if (TryControl(out early))
                    {
                        if (early.action == "close") { Emit(new { type = "closed", reason = "controller-close" }); return; }
                        if (early.action != "authorize") throw new InvalidOperationException("PEER_NOT_CONNECTED");
                        Authorize(early.id, cross);
                    }
                    if (clock.ElapsedMilliseconds >= handshakeDeadline) throw new InvalidOperationException("HANDSHAKE_TIMEOUT");
                    Thread.Sleep(20);
                }
                connected.GetAwaiter().GetResult();
                uint pid, session;
                native.Require(ChannelApi.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid));
                native.Require(ChannelApi.GetNamedPipeClientSessionId(pipe.SafePipeHandle, out session));
                using (var peerProcess = native.Open(checked((int)pid)))
                using (var peerToken = native.Token(peerProcess))
                {
                    if (session != request.sessionId) throw new InvalidOperationException("PIPE_SESSION_MISMATCH");
                    var peer = BindPeer(files, checked((int)pid), peerProcess, request.bootstrap,
                        request.targetSid, request.sessionId, request.expectedCreationTime);
                    uint confirmed;
                    native.Require(ChannelApi.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out confirmed));
                    if (pid != confirmed) throw new InvalidOperationException("PIPE_CLIENT_CHANGED");
                    CheckConnection();
                    heldPeer = peerProcess;
                    heldPipe = pipe;
                    heldPeerIdentity = peer;
                    targetSession = Session(targetSession.ownerSid, targetSession.sessionId, targetSession.logonTime);
                    CheckConnection();
                    handshakeDeadline = 0;
                    Emit(new { type = "worker", peer, targetSession });
                    NextPeerRead();
                    while (true)
                    {
                        CheckParent();
                        if (!native.Alive(peerProcess)) throw new InvalidOperationException("PEER_EXITED");
                        long partial = Interlocked.Read(ref partialDeadline);
                        if (partial != 0 &&
                            clock.ElapsedMilliseconds > partial) throw new InvalidOperationException("FRAME_TIMEOUT");
                        Command message;
                        if (TryControl(out message))
                        {
                            if (message.action == "close") { Emit(new { type = "closed", reason = "controller-close" }); return; }
                            if (message.action == "authorize")
                            {
                                Authorize(message.id, cross);
                            }
                            else if (message.action == "send")
                            {
                                if (message.frame == null) throw new InvalidOperationException("OBJECT_FRAME_REQUIRED");
                                var bytes = Bytes(message.frame, 16384);
                                Wait(pipe.WriteAsync(bytes, 0, bytes.Length), 1000);
                                CheckConnection();
                                Emit(new { type = "sent", id = message.id });
                            }
                            else throw new InvalidOperationException("UNKNOWN_COMMAND");
                        }
                        if (peerRead.IsCompleted)
                        {
                            var frame = peerRead.GetAwaiter().GetResult();
                            Emit(new { type = "frame", peer, frame });
                            NextPeerRead();
                        }
                        Thread.Sleep(20);
                    }
                }
            }
        }
    }

    private void Authorize(int id, bool cross)
    {
        var current = Facts();
        if (cross) RequireAdmin(current);
        targetSession = Session(targetSession.ownerSid, targetSession.sessionId, targetSession.logonTime);
        CheckConnection();
        Emit(new { type = "authorized", id, actorFacts = current, controllerIdentity = controller, targetSession });
    }

    private SessionFact Session(string sid, int sessionId, string logonTime)
    {
        var observation = Task.Run(() => new ChannelSession().Observe(sid, sessionId, logonTime));
        Wait(observation, 5000);
        return observation.GetAwaiter().GetResult();
    }

    private void CheckConnection()
    {
        CheckQueryProgress();
        if (handshakeDeadline != 0 &&
            clock.ElapsedMilliseconds >= handshakeDeadline) throw new InvalidOperationException("HANDSHAKE_TIMEOUT");
        long partial = Interlocked.Read(ref partialDeadline);
        if (partial != 0 &&
            clock.ElapsedMilliseconds > partial) throw new InvalidOperationException("FRAME_TIMEOUT");
        if (heldPeer == null) return;
        if (!native.Alive(heldPeer)) throw new InvalidOperationException("PEER_EXITED");
        using (var token = native.Token(heldPeer))
        {
            if (native.Sid(token) != heldPeerIdentity.ownerSid ||
                native.Number(token, 12) != heldPeerIdentity.sessionId)
                throw new InvalidOperationException("PEER_TOKEN_CHANGED");
        }
        uint available;
        if (!ChannelApi.PeekNamedPipe(heldPipe.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero))
            throw new InvalidOperationException("CHANNEL_DISCONNECTED");
        if (!native.Alive(heldPeer)) throw new InvalidOperationException("PEER_EXITED");
        CheckPeerRead();
    }

    private void ReadManifest(Request request)
    {
        Guid operation;
        if (!Guid.TryParseExact(request.operationId, "D", out operation)) throw new InvalidOperationException("OPERATION_ID_INVALID");
        Manifest manifest;
        using (var preliminary = new ChannelFiles(controller.ownerSid))
        {
            var parentPath = preliminary.PathValue(request.manifestParent);
            var path = preliminary.PathValue(request.path);
            var expected = Path.Combine(parentPath, operation.ToString("D"), "manifest.json");
            if (!string.Equals(path, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("MANIFEST_PATH_MISMATCH");
            using (var stream = preliminary.HoldFile(path, false))
            {
                if (stream.Length > 65536) throw new InvalidOperationException("MANIFEST_BOUNDS");
                var bytes = new byte[checked((int)stream.Length)];
                int count = stream.Read(bytes, 0, bytes.Length);
                if (count != bytes.Length) throw new InvalidOperationException("MANIFEST_READ_INCOMPLETE");
                manifest = Parse<Manifest>(utf8.GetString(bytes));
            }
            if (manifest.protocol != 1 ||
                manifest.operationId != request.operationId ||
                manifest.targetSid != controller.ownerSid ||
                manifest.sessionId != controller.sessionId ||
                manifest.controllerIdentity == null ||
                manifest.targetSession == null ||
                manifest.targetSession.ownerSid != manifest.targetSid ||
                manifest.targetSession.sessionId != manifest.sessionId ||
                string.IsNullOrEmpty(manifest.targetSession.logonTime))
                throw new InvalidOperationException("MANIFEST_BINDING_MISMATCH");
            var actor = manifest.controllerIdentity;
            using (var protectedFiles = new ChannelFiles(actor.ownerSid))
            {
                protectedFiles.Chain(path, true);
                var owner = protectedFiles.Owner(path);
                if (owner != actor.ownerSid) throw new InvalidOperationException("MANIFEST_OWNER_MISMATCH");
                bool cross = actor.ownerSid != controller.ownerSid;
                BindBootstrap(protectedFiles, manifest.bootstrap, path, parentPath, request.operationId, cross);
                var reader = BindPeer(protectedFiles, controller.pid, parent, manifest.bootstrap,
                    manifest.targetSid, manifest.sessionId, controller.creationTime);
                var session = Session(manifest.targetSid, manifest.sessionId, manifest.targetSession.logonTime);
                Emit(new { type = "result", document = manifest, readerIdentity = reader, targetSession = session,
                    protection = new { actorOwnerSid = owner, actorProcessQueried = false,
                        scope = cross ? "other-user-read-only" : "same-user-not-self-tamper-proof",
                        loadedCodeAttestation = false } });
            }
        }
    }
}

internal sealed class Request
{
    public string action { get; set; }
    public string operationId { get; set; }
    public string targetSid { get; set; }
    public int sessionId { get; set; }
    public Bootstrap bootstrap { get; set; }
    public string manifestParent { get; set; }
    public Dictionary<string, object> document { get; set; }
    public int handshakeTimeoutMs { get; set; }
    public int lifetimeMs { get; set; }
    public string expectedCreationTime { get; set; }
    public string path { get; set; }
    public string root { get; set; }
}

internal sealed class Bootstrap
{
    public string nodePath { get; set; }
    public string scriptPath { get; set; }
    public string nodeSha256 { get; set; }
    public string scriptSha256 { get; set; }
    public string[] argv { get; set; }
}

internal sealed class Command
{
    public string action { get; set; }
    public int id { get; set; }
    public Dictionary<string, object> frame { get; set; }
}

internal sealed class Manifest
{
    public int protocol { get; set; }
    public string operationId { get; set; }
    public string endpoint { get; set; }
    public string targetSid { get; set; }
    public int sessionId { get; set; }
    public Identity controllerIdentity { get; set; }
    public ActorFacts actorFacts { get; set; }
    public SessionFact targetSession { get; set; }
    public Bootstrap bootstrap { get; set; }
    public Dictionary<string, object> document { get; set; }
}
