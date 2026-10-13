using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal sealed class LegacyProcessBroker
{
    private readonly LegacyNative native = new LegacyNative();
    private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 262144, RecursionLimit = 20 };
    private readonly List<Held> held = new List<Held>();
    private readonly List<ExcludedIdentity> excluded = new List<ExcludedIdentity>();
    private readonly List<FileStream> scripts = new List<FileStream>();
    private readonly string user = WindowsIdentity.GetCurrent().User.Value;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private long deadline = 15000;
    private volatile bool committed;
    private string stage = "request";
    private string root;
    private int port;
    private string token;
    private Plan plan;
    private object captureFailure;
    private LegacySnapshot snapshot;
    private LegacyArgumentQueries arguments;
    private bool revalidating;
    private readonly Stopwatch phaseClock = new Stopwatch();
    private object captureDiagnostics;
    private object revalidationDiagnostics;
    private object brokerIdentity;

    private static int Main(string[] args)
    {
        return new LegacyProcessBroker().Run(args);
    }

    private int Run(string[] args)
    {
        try
        {
            if (args.Length != 0) throw new ArgumentException();
            Console.SetIn(new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false, true), false));
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false, true)) { AutoFlush = true });
            StartWatchdog();
            var request = Read();
            if (request.action == "verify")
            {
                ValidatePlan(request.expected);
                Write(new { ok = true, receipt = VerifyGone(request.expected), brokerIdentity });
                return 0;
            }
            if (request.action != "prepare") throw new ArgumentException();
            if (request.expected != null) ValidatePlan(request.expected);
            root = Path.GetFullPath(request.root).TrimEnd(Path.DirectorySeparatorChar);
            port = request.port;
            if (!Path.IsPathRooted(request.root) ||
                port < 1 ||
                port > 65535 ||
                !Directory.Exists(root)) throw new ArgumentException();
            stage = "capture-roots";
            phaseClock.Start();
            arguments = new LegacyArgumentQueries(CheckPhase);
            arguments.BeginPhase(48);
            Held bridge;
            Held supervisor;
            using (var images = new LegacyImageCache(CheckPhase))
            {
                bridge = Capture(native.Listener(port), null);
                supervisor = Capture(bridge.Info.parentPid, null);
                if (bridge.Info.pid == supervisor.Info.pid ||
                    bridge.Created < supervisor.Created) throw new InvalidOperationException();
                bridge.Info.parentCreationTime = supervisor.Info.creationTime;
                bridge.KeepArguments = true;
                supervisor.KeepArguments = true;
                bridge.SelectedRoot = true;
                supervisor.SelectedRoot = true;
                var roots = new List<Held> { bridge, supervisor };
                CaptureFacts(roots, images);
                CheckRootArguments(bridge, supervisor);
                RefreshSnapshot();
                if (!snapshot.Contains(bridge.Info.pid, supervisor.Info.pid) ||
                    !snapshot.Contains(supervisor.Info.pid, supervisor.Info.parentPid))
                    throw new InvalidOperationException("Snapshot root changed");
                CaptureChildren(supervisor, 0);
                var descendants = held.FindAll(value => value != bridge && value != supervisor);
                CaptureFacts(descendants, images);
                if (!native.Alive(supervisor.Handle) ||
                    !native.Alive(bridge.Handle) ||
                    native.Listener(port) != bridge.Info.pid) throw new InvalidOperationException("Root changed");
                stage = "plan";
                plan = MakePlan(supervisor, bridge);
                int planBytes = PlanBytes(plan);
                CheckPhase();
                captureDiagnostics = new { elapsedMilliseconds = phaseClock.ElapsedMilliseconds,
                    argumentQueries = arguments.Count, imageFiles = images.Count,
                    imageBytesHashed = images.Bytes, planUtf8Bytes = planBytes, memory = native.Memory() };
            }
            if (request.expected != null &&
                json.Serialize(request.expected) != json.Serialize(plan))
                throw new InvalidOperationException("Plan changed");
            token = NewToken();
            Interlocked.Exchange(ref deadline, clock.ElapsedMilliseconds + 120000);
            Write(new { ok = true, plan, token, diagnostics = captureDiagnostics, brokerIdentity });
            while (true)
            {
                request = Read();
                if (request.action == "close")
                {
                    Write(new { ok = true, closed = true, brokerIdentity });
                    return 0;
                }
                if (request.action == "status")
                {
                    Write(new { ok = true, receipt = HeldStatus(), brokerIdentity });
                    continue;
                }
                if (request.action != "stop" ||
                    request.token != token ||
                    request.planSha256 != plan.planSha256) throw new ArgumentException();
                stage = "revalidate";
                revalidating = true;
                phaseClock.Restart();
                Interlocked.Exchange(ref deadline, clock.ElapsedMilliseconds + 15000);
                arguments.BeginPhase(32);
                Revalidate(supervisor, bridge);
                arguments.Dispose();
                arguments = null;
                committed = true;
                stage = "stop";
                Interlocked.Exchange(ref deadline, clock.ElapsedMilliseconds + 12000);
                var stopWatch = Stopwatch.StartNew();
                var receipt = Stop(supervisor, bridge);
                Write(new { ok = true, receipt, diagnostics = new {
                    revalidation = revalidationDiagnostics, stopMilliseconds = stopWatch.ElapsedMilliseconds,
                    memory = native.Memory() }, brokerIdentity });
                return 0;
            }
        }
        catch (Exception error)
        {
            if (arguments != null) { arguments.Dispose(); arguments = null; }
            var win32 = error as Win32Exception;
            captureFailure = captureFailure ?? native.FailureDetails(error);
            Write(new { ok = false, error = "LEGACY_PROCESS_REFUSED", stage,
                type = error.GetType().Name, nativeError = win32 == null ? 0 : win32.NativeErrorCode,
                reason = RefusalReason(error), captureFailure, mutationStarted = committed, treeCompleteness = "unproven", brokerIdentity });
            return 1;
        }
        finally
        {
            if (arguments != null) arguments.Dispose();
            foreach (var process in held) process.Handle.Dispose();
            foreach (var script in scripts) script.Dispose();
        }
    }

    private void StartWatchdog()
    {
        var self = Api.OpenProcess(0x1000, false, Process.GetCurrentProcess().Id);
        int parentId;
        long selfCreated;
        using (self)
        {
            native.Require(!self.IsInvalid);
            parentId = native.Parent(self);
            selfCreated = native.Creation(self);
            brokerIdentity = new { pid = Process.GetCurrentProcess().Id,
                creationTime = selfCreated.ToString(CultureInfo.InvariantCulture) };
        }
        var parent = Api.OpenProcess(0x00100000 | 0x1000, false, parentId);
        native.Require(!parent.IsInvalid);
        if (native.Creation(parent) > selfCreated ||
            !native.Alive(parent))
        {
            parent.Dispose();
            throw new InvalidOperationException("Broker parent identity lost");
        }
        var thread = new Thread(() =>
        {
            using (parent)
            {
                while (clock.ElapsedMilliseconds < Interlocked.Read(ref deadline))
                {
                    uint wait = Api.WaitForSingleObject(parent, 100);
                    if (wait == 0 &&
                        !committed) Environment.Exit(2);
                    if (wait == 0xffffffff) Environment.Exit(2);
                    if (wait == 0) Thread.Sleep(100);
                }
                Environment.Exit(3);
            }
        });
        thread.IsBackground = true;
        thread.Start();
    }

    private Request Read()
    {
        var line = new StringBuilder();
        while (line.Length < 262144)
        {
            int value = Console.In.Read();
            if (value < 0) throw new EndOfStreamException();
            if (value == 10)
            {
                var text = line.ToString();
                if (Encoding.UTF8.GetByteCount(text) + 1 > 262144) throw new ArgumentException("Request bounds");
                return json.Deserialize<Request>(text);
            }
            line.Append((char)value);
        }
        throw new ArgumentException("Request bounds");
    }

    private void Write(object value)
    {
        Console.Out.WriteLine(json.Serialize(value));
        Console.Out.Flush();
    }

    private Held Capture(int id, Held parent)
    {
        CheckPhase();
        var known = held.Find(value => value.Info.pid == id);
        if (known != null)
        {
            if (!native.Alive(known.Handle) ||
                native.Creation(known.Handle) != known.Created ||
                native.Parent(known.Handle) != known.Info.parentPid ||
                native.Owner(known.Handle) != user) throw new InvalidOperationException("Capture changed");
            if (parent != null &&
                !KnownEdge(known, parent)) return null;
            return known;
        }
        if (held.Count + excluded.Count >= 512) throw new InvalidOperationException("Capture bound");
        var substage = LegacyFailureStage.CaptureOpenQuery;
        long? observedBirth = null;
        int? observedParent = null;
        bool? observedAlive = null;
        bool? observedParentAlive = null;
        bool? observedOwnerMatch = null;
        var handle = Api.OpenProcess(0x00100000 | 0x1000, false, id);
        try
        {
            native.Require(!handle.IsInvalid, LegacyFailureApi.OpenProcessQuery);
            substage = LegacyFailureStage.CaptureIdentity;
            bool alive = native.Alive(handle);
            observedAlive = alive;
            if (!alive) throw new InvalidOperationException("Capture exited");
            long created = native.Creation(handle);
            observedBirth = created;
            substage = LegacyFailureStage.CaptureParent;
            int parentId = native.Parent(handle);
            observedParent = parentId;
            if (parent != null)
            {
                bool parentAlive;
                try { parentAlive = native.Alive(parent.Handle); }
                catch (Exception error)
                {
                    native.TagFailure(error, LegacyFailureStage.CaptureParentLiveness,
                        parent.Info.pid, parent.Created, parent.Info.parentPid, ownerMatched: true);
                    throw;
                }
                observedParentAlive = parentAlive;
                bool bornBeforeParent = created < parent.Created;
                bool changedEdge = parentId != parent.Info.pid;
                if (!parentAlive ||
                    changedEdge)
                {
                    captureFailure = new { pid = id, creationTime = created.ToString(CultureInfo.InvariantCulture),
                        actualParentPid = parentId,
                        expectedParentPid = parent.Info.pid, parentCreationTime = parent.Info.creationTime,
                        parentAlive, bornBeforeParent, changedEdge };
                    throw new InvalidOperationException("Unproven ancestry");
                }
                if (bornBeforeParent)
                {
                    // A reused creator PID is not ownership of its older survivors.
                    // This candidate never receives terminate access or enters held.
                    excluded.Add(new ExcludedIdentity { pid = id,
                        creationTime = created.ToString(CultureInfo.InvariantCulture),
                        parentPid = parentId, parentCreationTime = parent.Info.creationTime,
                        reason = "predates-held-parent" });
                    handle.Dispose();
                    return null;
                }
            }
            substage = LegacyFailureStage.CaptureOwner;
            var owner = native.Owner(handle);
            observedOwnerMatch = owner == user;
            if (owner != user ||
                id == Process.GetCurrentProcess().Id) throw new InvalidOperationException("Owner mismatch");
            substage = LegacyFailureStage.CaptureOpenTerminate;
            var terminable = Api.OpenProcess(0x00100000 | 0x1000 | 1, false, id);
            try
            {
                native.Require(!terminable.IsInvalid, LegacyFailureApi.OpenProcessTerminate);
                if (native.Creation(terminable) != created ||
                    !native.Alive(terminable)) throw new InvalidOperationException("Capture changed");
            }
            catch { terminable.Dispose(); throw; }
            handle.Dispose();
            handle = terminable;
            substage = LegacyFailureStage.CaptureImage;
            var image = native.Image(handle);
            var info = new Identity { pid = id, creationTime = created.ToString(CultureInfo.InvariantCulture),
                parentPid = parentId, parentCreationTime = parent == null ? null : parent.Info.creationTime,
                ownerSid = owner, imagePath = image };
            if (!native.Alive(handle)) throw new InvalidOperationException("Capture changed");
            var result = new Held { Handle = handle, Info = info, Created = created };
            held.Add(result);
            return result;
        }
        catch (Exception error)
        {
            native.TagFailure(error, substage, id, observedBirth, observedParent,
                parent == null ? (int?)null : parent.Info.pid, parent == null ? null : parent.Info.creationTime,
                observedAlive, observedParentAlive, observedOwnerMatch);
            handle.Dispose();
            throw;
        }
    }

    private bool KnownEdge(Held child, Held parent)
    {
        CheckPhase();
        if (!native.Alive(child.Handle) ||
            !native.Alive(parent.Handle) ||
            native.Creation(child.Handle) != child.Created ||
            native.Creation(parent.Handle) != parent.Created ||
            native.Parent(child.Handle) != parent.Info.pid ||
            child.Info.parentPid != parent.Info.pid ||
            native.Owner(child.Handle) != user ||
            native.Owner(parent.Handle) != user)
            throw new InvalidOperationException("Ancestry changed");
        if (child.Created < parent.Created)
        {
            // The selected root stays held; only this false reused-creator edge is ignored.
            if (child.SelectedRoot) return false;
            throw new InvalidOperationException("Unproven ancestry");
        }
        if (child.Info.parentCreationTime != parent.Info.creationTime)
            throw new InvalidOperationException("Ancestry changed");
        return true;
    }

    private List<int> Children(int parentId)
    {
        CheckPhase();
        var parent = held.Find(value => value.Info.pid == parentId);
        if (snapshot == null ||
            parent == null ||
            !native.Alive(parent.Handle)) throw new InvalidOperationException("Unproven ancestry");
        var ids = snapshot.Children(parentId);
        ids.Sort();
        return ids;
    }

    private void CheckPhase()
    {
        if ((!revalidating && clock.ElapsedMilliseconds > 14000) ||
            (revalidating && phaseClock.ElapsedMilliseconds >= 15000))
            throw new InvalidOperationException("Capture bound");
    }

    private void RefreshSnapshot()
    {
        var current = new LegacySnapshot();
        current.Read(CheckPhase);
        snapshot = current;
    }

    private void CaptureFacts(List<Held> processes, LegacyImageCache images)
    {
        arguments.Read(processes, true);
        foreach (var process in processes)
        {
            try
            {
                CheckPhase();
                if (!native.Alive(process.Handle) ||
                    native.Creation(process.Handle) != process.Created ||
                    native.Owner(process.Handle) != user ||
                    native.Parent(process.Handle) != process.Info.parentPid ||
                    !Equal(native.Image(process.Handle), process.Info.imagePath))
                    throw new InvalidOperationException("Capture changed");
                process.Info.imageSha256 = images.Hash(process.Info.imagePath);
            }
            catch (Exception error)
            {
                native.TagFailure(error, LegacyFailureStage.CaptureImageFacts, process.Info.pid,
                    process.Created, process.Info.parentPid, ownerMatched: true);
                throw;
            }
        }
    }

    private int PlanBytes(Plan value)
    {
        try
        {
            int bytes = Encoding.UTF8.GetByteCount(json.Serialize(value));
            if (bytes > 240 * 1024) throw new InvalidOperationException("Plan byte bound");
            return bytes;
        }
        catch (InvalidOperationException) { throw new InvalidOperationException("Plan byte bound"); }
    }

    private void CaptureChildren(Held parent, int depth)
    {
        if (depth >= 8) throw new InvalidOperationException("Depth bound");
        foreach (int id in Children(parent.Info.pid))
        {
            if (id == parent.Info.pid) throw new InvalidOperationException("Ancestry cycle");
            var child = Capture(id, parent);
            if (child == null) continue;
            child.Info.parentCreationTime = parent.Info.creationTime;
            CaptureChildren(child, depth + 1);
        }
    }

    private void CheckRootArguments(Held bridge, Held supervisor)
    {
        var bridgeScript = Path.Combine(root, "bin", "mcp-bridge.mjs");
        var supervisorScript = Path.Combine(root, "supervisor", "supervise.ps1");
        var bridgeArgs = bridge.Arguments;
        var supervisorArgs = supervisor.Arguments;
        var supervisorImage = Path.GetFileName(supervisor.Info.imagePath).ToLowerInvariant();
        bool bridgeValid = string.Equals(Path.GetFileName(bridge.Info.imagePath), "node.exe", StringComparison.OrdinalIgnoreCase) &&
            bridgeArgs.Length == 4 &&
            EqualPath(bridgeArgs[1], bridgeScript) &&
            bridgeArgs[2] == "--port" &&
            bridgeArgs[3] == port.ToString(CultureInfo.InvariantCulture);
        bool supervisorValid = (supervisorImage == "pwsh.exe" || supervisorImage == "powershell.exe") &&
            supervisorArgs.Length == 10 &&
            Equal(supervisorArgs[1], "-NoProfile") &&
            Equal(supervisorArgs[2], "-ExecutionPolicy") &&
            Equal(supervisorArgs[3], "Bypass") &&
            Equal(supervisorArgs[4], "-WindowStyle") &&
            Equal(supervisorArgs[5], "Hidden") &&
            Equal(supervisorArgs[6], "-File") &&
            EqualPath(supervisorArgs[7], supervisorScript) &&
            Equal(supervisorArgs[8], "-Port") &&
            supervisorArgs[9] == port.ToString(CultureInfo.InvariantCulture);
        if (!bridgeValid ||
            !supervisorValid) throw new InvalidOperationException("Root arguments mismatch");
        bridge.Info.scriptSha256 = HoldScript(bridgeScript);
        supervisor.Info.scriptSha256 = HoldScript(supervisorScript);
    }

    private string HoldScript(string path)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        scripts.Add(stream);
        if (stream.Length > 4 * 1024 * 1024) throw new InvalidOperationException("Script bound");
        using (var hash = SHA256.Create())
            return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private bool Equal(string left, string right) { return string.Equals(left, right, StringComparison.OrdinalIgnoreCase); }
    private bool EqualPath(string left, string right)
    {
        // Target argv belongs to the target's cwd/drive context, never ours.
        // Only unambiguous drive-absolute or UNC paths can identify its script.
        if (!FullyQualifiedScriptPath(left))
            throw new InvalidOperationException("Script argument not fully qualified");
        return Equal(Path.GetFullPath(left), Path.GetFullPath(right));
    }

    private bool FullyQualifiedScriptPath(string value)
    {
        if (string.IsNullOrEmpty(value) ||
            value.Length < 3) return false;
        bool driveLetter = (value[0] >= 'A' && value[0] <= 'Z') ||
            (value[0] >= 'a' && value[0] <= 'z');
        if (driveLetter &&
            value[1] == ':' &&
            (value[2] == '\\' || value[2] == '/')) return true;
        var path = value.Replace('/', '\\');
        if (!path.StartsWith(@"\\", StringComparison.Ordinal) ||
            path[2] == '?' ||
            path[2] == '.') return false;
        int serverEnd = path.IndexOf('\\', 2);
        if (serverEnd <= 2 ||
            serverEnd + 1 >= path.Length) return false;
        int shareEnd = path.IndexOf('\\', serverEnd + 1);
        if (shareEnd < 0) shareEnd = path.Length;
        var share = path.Substring(serverEnd + 1, shareEnd - serverEnd - 1);
        return share.Length > 0 &&
            share != "." &&
            share != "..";
    }

    private Plan MakePlan(Held supervisor, Held bridge)
    {
        var observed = new List<Identity>();
        foreach (var process in held)
            if (process != supervisor &&
                process != bridge) observed.Add(process.Info);
        observed.Sort((left, right) => left.pid.CompareTo(right.pid));
        excluded.Sort((left, right) => left.pid.CompareTo(right.pid));
        var result = new Plan { protocol = 1, kind = "legacy-observed-process-set", port = port, root = root,
            ownerSid = user, roots = new Roots { supervisor = supervisor.Info, bridge = bridge.Info },
            observed = observed.ToArray(), excluded = excluded.ToArray(), treeCompleteness = "unproven",
            scope = "Selected roots and captured proven descendants only; uncaptured and historical orphans are untouched." };
        result.observedSetSha256 = native.Hash(Encoding.UTF8.GetBytes(json.Serialize(result.observed)));
        result.planSha256 = DigestPlan(result);
        return result;
    }

    private string DigestPlan(Plan value)
    {
        var saved = value.planSha256;
        value.planSha256 = null;
        var digest = native.Hash(Encoding.UTF8.GetBytes(json.Serialize(value)));
        value.planSha256 = saved;
        return digest;
    }

    private void Revalidate(Held supervisor, Held bridge)
    {
        if (!native.Alive(supervisor.Handle) ||
            !native.Alive(bridge.Handle) ||
            native.Listener(port) != bridge.Info.pid) throw new InvalidOperationException("Root changed");
        var live = held.FindAll(value => native.Alive(value.Handle));
        arguments.Read(live, false);
        using (var images = new LegacyImageCache(CheckPhase))
        {
            foreach (var process in live)
            {
                CheckPhase();
                if (!native.Alive(process.Handle) ||
                    native.Creation(process.Handle) != process.Created ||
                    native.Parent(process.Handle) != process.Info.parentPid ||
                    native.Owner(process.Handle) != user ||
                    !Equal(native.Image(process.Handle), process.Info.imagePath) ||
                    images.Hash(process.Info.imagePath) != process.Info.imageSha256)
                    throw new InvalidOperationException("Identity changed");
            }
            RefreshSnapshot();
            foreach (var process in held)
            {
                if (!native.Alive(process.Handle)) continue;
                if (!snapshot.Contains(process.Info.pid, process.Info.parentPid))
                    throw new InvalidOperationException("Snapshot held member changed");
                foreach (int id in Children(process.Info.pid))
                {
                    var known = held.Find(value => value.Info.pid == id);
                    if (known != null)
                    {
                        if (!KnownEdge(known, process)) continue;
                    }
                    else if (!ApprovedNonmember(process, id))
                        throw new InvalidOperationException("Observed set expanded; replan");
                }
            }
            if (!native.Alive(supervisor.Handle) ||
                !native.Alive(bridge.Handle) ||
                native.Listener(port) != bridge.Info.pid) throw new InvalidOperationException("Root changed");
            CheckPhase();
            revalidationDiagnostics = new { elapsedMilliseconds = phaseClock.ElapsedMilliseconds,
                argumentQueries = arguments.Count, imageFiles = images.Count, imageBytesHashed = images.Bytes };
        }
    }

    private bool ApprovedNonmember(Held parent, int id)
    {
        var prior = excluded.Find(value => value.pid == id &&
            value.parentPid == parent.Info.pid &&
            value.parentCreationTime == parent.Info.creationTime);
        if (prior == null) return false;
        using (var process = Api.OpenProcess(0x00100000 | 0x1000, false, id))
        {
            native.Require(!process.IsInvalid);
            long created = native.Creation(process);
            return native.Alive(parent.Handle) &&
                native.Alive(process) &&
                native.Parent(process) == parent.Info.pid &&
                created < parent.Created &&
                created.ToString(CultureInfo.InvariantCulture) == prior.creationTime;
        }
    }

    private Receipt Stop(Held supervisor, Held bridge)
    {
        var errors = new List<string>();
        var stopClock = Stopwatch.StartNew();
        Kill(supervisor, stopClock, errors);
        if (!native.Alive(supervisor.Handle))
        {
            Kill(bridge, stopClock, errors);
            for (int index = held.Count - 1; index >= 0; index--)
                if (held[index] != supervisor &&
                    held[index] != bridge) Kill(held[index], stopClock, errors);
        }
        var result = HeldStatus();
        result.errors = errors.ToArray();
        return result;
    }

    private void Kill(Held process, Stopwatch stopClock, List<string> errors)
    {
        try
        {
            if (!native.Alive(process.Handle)) return;
            if (stopClock.ElapsedMilliseconds >= 8000) throw new TimeoutException();
            bool terminated = Api.TerminateProcess(process.Handle, 1);
            int terminationError = terminated ? 0 : Marshal.GetLastWin32Error();
            uint remaining = (uint)Math.Max(1, 8000 - stopClock.ElapsedMilliseconds);
            // Parent exit can already be terminating this child. A racing
            // TerminateProcess failure is reconciled only by this held handle
            // becoming signaled within the same total stop budget.
            if (Api.WaitForSingleObject(process.Handle, remaining) != 0)
            {
                if (!terminated) throw new Win32Exception(terminationError);
                throw new TimeoutException();
            }
        }
        catch (Exception error)
        {
            var win32 = error as Win32Exception;
            errors.Add(process.Info.pid + ":" + error.GetType().Name +
                (win32 == null ? "" : ":" + win32.NativeErrorCode));
        }
    }

    private Receipt HeldStatus()
    {
        bool rootsGone = true;
        bool observedGone = true;
        foreach (var process in held)
        {
            if (!native.Alive(process.Handle)) continue;
            if (process.Info.pid == plan.roots.bridge.pid ||
                process.Info.pid == plan.roots.supervisor.pid) rootsGone = false;
            else observedGone = false;
        }
        return new Receipt { legacyRootStopVerified = rootsGone, observedDescendantsStopped = observedGone,
            treeCompleteness = "unproven", observedCount = plan.observed.Length,
            excludedCount = plan.excluded.Length, planSha256 = plan.planSha256,
            errors = new string[0], unattributed = "Not discovered or not provable; left untouched." };
    }

    private void ValidatePlan(Plan value)
    {
        if (value == null ||
            value.protocol != 1 ||
            value.kind != "legacy-observed-process-set" ||
            value.treeCompleteness != "unproven" ||
            value.ownerSid != user ||
            value.roots == null ||
            value.roots.bridge == null ||
            value.roots.supervisor == null ||
            value.observed == null ||
            value.excluded == null ||
            value.observed.Length > 510 ||
            value.excluded.Length + value.observed.Length > 510 ||
            value.port < 1 ||
            value.port > 65535 ||
            !Path.IsPathRooted(value.root) ||
            DigestPlan(value) != value.planSha256 ||
            native.Hash(Encoding.UTF8.GetBytes(json.Serialize(value.observed))) != value.observedSetSha256)
            throw new ArgumentException("Invalid protected plan");
        PlanBytes(value);
        var ids = new HashSet<int>();
        var identities = new List<Identity> { value.roots.supervisor, value.roots.bridge };
        identities.AddRange(value.observed);
        foreach (var identity in identities)
        {
            long created;
            if (identity == null ||
                identity.pid <= 0 ||
                !ids.Add(identity.pid) ||
                identity.ownerSid != user ||
                !Path.IsPathRooted(identity.imagePath) ||
                !long.TryParse(identity.creationTime, NumberStyles.None, CultureInfo.InvariantCulture, out created) ||
                created <= 0) throw new ArgumentException("Invalid captured identity");
        }
        foreach (var identity in value.excluded)
        {
            long created;
            long parentCreated;
            if (identity == null ||
                identity.pid <= 0 ||
                !ids.Add(identity.pid) ||
                identity.reason != "predates-held-parent" ||
                !long.TryParse(identity.creationTime, NumberStyles.None, CultureInfo.InvariantCulture, out created) ||
                !long.TryParse(identity.parentCreationTime, NumberStyles.None, CultureInfo.InvariantCulture, out parentCreated) ||
                created <= 0 ||
                created >= parentCreated ||
                !identities.Exists(parent => parent.pid == identity.parentPid &&
                    parent.creationTime == identity.parentCreationTime))
                throw new ArgumentException("Invalid excluded generation evidence");
        }
    }

    private Receipt VerifyGone(Plan value)
    {
        bool rootsGone = true;
        bool childrenGone = true;
        var errors = new List<string>();
        var identities = new List<Identity> { value.roots.supervisor, value.roots.bridge };
        identities.AddRange(value.observed);
        for (int index = 0; index < identities.Count; index++)
        {
            var identity = identities[index];
            using (var process = Api.OpenProcess(0x00100000 | 0x1000, false, identity.pid))
            {
                if (process.IsInvalid)
                {
                    int code = Marshal.GetLastWin32Error();
                    if (code == 87) continue;
                    errors.Add(identity.pid + ":OpenProcess:" + code);
                    if (index < 2) rootsGone = false; else childrenGone = false;
                    continue;
                }
                if (native.Creation(process).ToString(CultureInfo.InvariantCulture) != identity.creationTime) continue;
                if (!native.Alive(process)) continue;
                if (index < 2) rootsGone = false; else childrenGone = false;
            }
        }
        return new Receipt { legacyRootStopVerified = rootsGone, observedDescendantsStopped = childrenGone,
            observedCount = value.observed.Length, excludedCount = value.excluded.Length, treeCompleteness = "unproven",
            planSha256 = value.planSha256, errors = errors.ToArray(),
            unattributed = "Not discovered or not provable; left untouched." };
    }

    private string NewToken()
    {
        var bytes = new byte[32];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private string RefusalReason(Exception error)
    {
        // Only fixed own-source reasons are safe to expose. Never relay arbitrary
        // WMI/IO exception text, which can contain paths or command-line content.
        var reasons = new HashSet<string> {
            "Plan changed", "Capture bound", "Capture exited", "Owner mismatch",
            "Unproven ancestry", "Capture changed", "Ancestry changed", "Ancestry cycle",
            "Child bound", "Depth bound", "Root arguments mismatch", "Script bound",
            "Root changed", "Identity changed", "Arguments changed",
            "Observed set expanded; replan", "Process query changed",
            "Process query unavailable", "Process query generation changed",
            "Argument bounds", "Listener ambiguity", "Loopback listener missing",
            "Broker parent identity lost", "Script argument not fully qualified",
            "Snapshot schema unavailable", "Snapshot enumeration failed", "Snapshot entry bound",
            "Snapshot duplicate entry", "Snapshot identity unavailable", "Snapshot close failed",
            "Snapshot root changed", "Snapshot held member changed", "Argument query bound",
            "Argument query cancelled", "Image file identity unavailable", "Image file identity changed",
            "Image hash bound", "Plan byte bound", "Request bounds"
        };
        return reasons.Contains(error.Message) ? error.Message : null;
    }
}

internal sealed class Held
{
    internal SafeProcess Handle;
    internal Identity Info;
    internal long Created;
    internal string[] Arguments;
    internal bool KeepArguments;
    internal bool SelectedRoot;
}

internal sealed class Request
{
    public string action { get; set; }
    public int port { get; set; }
    public string root { get; set; }
    public Plan expected { get; set; }
    public string token { get; set; }
    public string planSha256 { get; set; }
}

internal sealed class Identity
{
    public int pid { get; set; }
    public string creationTime { get; set; }
    public int parentPid { get; set; }
    public string parentCreationTime { get; set; }
    public string ownerSid { get; set; }
    public string imagePath { get; set; }
    public string imageSha256 { get; set; }
    public string argvSha256 { get; set; }
    public string scriptSha256 { get; set; }
}

internal sealed class Roots
{
    public Identity supervisor { get; set; }
    public Identity bridge { get; set; }
}

internal sealed class ExcludedIdentity
{
    public int pid { get; set; }
    public string creationTime { get; set; }
    public int parentPid { get; set; }
    public string parentCreationTime { get; set; }
    public string reason { get; set; }
}

internal sealed class Plan
{
    public int protocol { get; set; }
    public string kind { get; set; }
    public int port { get; set; }
    public string root { get; set; }
    public string ownerSid { get; set; }
    public Roots roots { get; set; }
    public Identity[] observed { get; set; }
    public ExcludedIdentity[] excluded { get; set; }
    public string observedSetSha256 { get; set; }
    public string treeCompleteness { get; set; }
    public string scope { get; set; }
    public string planSha256 { get; set; }
}

internal sealed class Receipt
{
    public bool legacyRootStopVerified { get; set; }
    public bool observedDescendantsStopped { get; set; }
    public string treeCompleteness { get; set; }
    public int observedCount { get; set; }
    public int excludedCount { get; set; }
    public string planSha256 { get; set; }
    public string[] errors { get; set; }
    public string unattributed { get; set; }
}
