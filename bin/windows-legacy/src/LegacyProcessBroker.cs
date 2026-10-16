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
    // A plan names only the two roots. Plans written by 2.1.0 also list up to 510 descendants,
    // and recovery still verifies those, so plan bounds stay at their 2.1.0 values.
    private const int MaximumPlanIdentities = 512;
    private const int MaximumPlanBytes = 240 * 1024;
    private const int MaximumMessageBytes = 262144;
    // One query reads both roots' command lines in each phase.
    private const int MaximumArgumentQueries = 1;
    // Descendants are found while stopping. One busy 1.3 host had 533 processes in its tree.
    private const int MaximumSweptProcesses = 2048;
    private const int MaximumSweepRounds = 16;
    private const int MaximumPinPasses = 8;
    private const long RequestMilliseconds = 15000;
    private const long PhaseMilliseconds = 120000;
    private const long StopMilliseconds = 20000;
    private const long WatchdogMarginMilliseconds = 10000;
    private readonly LegacyNative native = new LegacyNative();
    private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = MaximumMessageBytes, RecursionLimit = 20 };
    private readonly List<Held> held = new List<Held>();
    private readonly HashSet<string> rejected = new HashSet<string>();
    // The processes that started this broker, by PID and creation time; the sweep never adopts them.
    private readonly Dictionary<int, long> ancestors = new Dictionary<int, long>();
    private readonly int brokerId = Process.GetCurrentProcess().Id;
    private bool swept;
    private readonly List<FileStream> scripts = new List<FileStream>();
    private readonly string user = WindowsIdentity.GetCurrent().User.Value;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private long deadline = RequestMilliseconds;
    private volatile bool committed;
    private string stage = "request";
    private string root;
    private int port;
    private string token;
    private Plan plan;
    private object captureFailure;
    private LegacySnapshot snapshot;
    private LegacyArgumentQueries arguments;
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
            // Phase budgets start once the request is read, so a slow broker start on a loaded
            // host does not consume the capture budget.
            Interlocked.Exchange(ref deadline, clock.ElapsedMilliseconds + PhaseMilliseconds + WatchdogMarginMilliseconds);
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
            arguments.BeginPhase(MaximumArgumentQueries);
            Held bridge;
            Held supervisor;
            using (var images = new LegacyImageCache(CheckPhase))
            {
                bridge = Capture(native.Listener(port));
                supervisor = Capture(bridge.Info.parentPid);
                if (bridge.Info.pid == supervisor.Info.pid ||
                    bridge.Created < supervisor.Created) throw new InvalidOperationException();
                bridge.Info.parentCreationTime = supervisor.Info.creationTime;
                bridge.KeepArguments = true;
                supervisor.KeepArguments = true;
                var roots = new List<Held> { bridge, supervisor };
                CaptureFacts(roots, images);
                CheckRootArguments(bridge, supervisor);
                RefreshSnapshot();
                if (!snapshot.Contains(bridge.Info.pid, supervisor.Info.pid) ||
                    !snapshot.Contains(supervisor.Info.pid, supervisor.Info.parentPid))
                    throw new InvalidOperationException("Snapshot root changed");
                CheckAncestors(bridge, supervisor);
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
                !SameRoots(request.expected, plan)) throw new InvalidOperationException("Plan changed");
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
                phaseClock.Restart();
                Interlocked.Exchange(ref deadline, clock.ElapsedMilliseconds + PhaseMilliseconds + WatchdogMarginMilliseconds);
                arguments.BeginPhase(MaximumArgumentQueries);
                Revalidate(supervisor, bridge);
                arguments.Dispose();
                arguments = null;
                committed = true;
                stage = "stop";
                Interlocked.Exchange(ref deadline, clock.ElapsedMilliseconds + StopMilliseconds + WatchdogMarginMilliseconds);
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
        while (line.Length < MaximumMessageBytes)
        {
            int value = Console.In.Read();
            if (value < 0) throw new EndOfStreamException();
            if (value == 10)
            {
                var text = line.ToString();
                if (Encoding.UTF8.GetByteCount(text) + 1 > MaximumMessageBytes) throw new ArgumentException("Request bounds");
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

    private Held Capture(int id)
    {
        CheckPhase();
        var substage = LegacyFailureStage.CaptureOpenQuery;
        long? observedBirth = null;
        int? observedParent = null;
        bool? observedAlive = null;
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
                parentPid = parentId, ownerSid = owner, imagePath = image };
            if (!native.Alive(handle)) throw new InvalidOperationException("Capture changed");
            var result = new Held { Handle = handle, Info = info, Created = created };
            held.Add(result);
            return result;
        }
        catch (Exception error)
        {
            native.TagFailure(error, substage, id, observedBirth, observedParent,
                alive: observedAlive, ownerMatched: observedOwnerMatch);
            handle.Dispose();
            throw;
        }
    }

    private void CheckPhase()
    {
        if (phaseClock.ElapsedMilliseconds >= PhaseMilliseconds)
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
            if (bytes > MaximumPlanBytes) throw new InvalidOperationException("Plan byte bound");
            return bytes;
        }
        catch (InvalidOperationException) { throw new InvalidOperationException("Plan byte bound"); }
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

    // The upgrade cannot stop the bridge it runs under. A CLI started from inside the 1.3
    // tree, for example through an MCP server's shell, is refused here before any change.
    private void CheckAncestors(Held bridge, Held supervisor)
    {
        int id = Process.GetCurrentProcess().Id;
        long childCreated = long.MaxValue;
        for (int depth = 0; depth < 64; depth++)
        {
            using (var process = Api.OpenProcess(0x1000, false, id))
            {
                if (process.IsInvalid) return;
                long created = native.Creation(process);
                // A parent PID that now names a newer process is not this process's parent.
                if (created > childCreated) return;
                bool insideRoots = id == bridge.Info.pid ||
                    id == supervisor.Info.pid;
                if (insideRoots) throw new InvalidOperationException("Run the upgrade from a terminal the 1.3 bridge did not start");
                ancestors[id] = created;
                childCreated = created;
                id = native.Parent(process);
            }
        }
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
        var result = new Plan { protocol = 1, kind = "legacy-observed-process-set", port = port, root = root,
            ownerSid = user, roots = new Roots { supervisor = supervisor.Info, bridge = bridge.Info },
            observed = new Identity[0], excluded = new ExcludedIdentity[0], treeCompleteness = "unproven",
            scope = "Selected roots only. When stopping, processes they started are found by parent and stopped; other processes are untouched." };
        result.observedSetSha256 = native.Hash(Encoding.UTF8.GetBytes(json.Serialize(result.observed)));
        result.planSha256 = DigestPlan(result);
        return result;
    }

    // Sessions start and end all the time, so only the roots bind a reopened plan. A plan
    // written by 2.1.0 also lists the descendants it captured; those are not compared.
    private bool SameRoots(Plan expected, Plan actual)
    {
        return json.Serialize(RootBinding(expected)) == json.Serialize(RootBinding(actual));
    }

    private object RootBinding(Plan value)
    {
        return new { value.protocol, value.kind, value.port, value.root, value.ownerSid, value.roots };
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
        var roots = new List<Held> { bridge, supervisor };
        arguments.Read(roots, false);
        using (var images = new LegacyImageCache(CheckPhase))
        {
            foreach (var process in roots)
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
            if (!snapshot.Contains(bridge.Info.pid, supervisor.Info.pid) ||
                !snapshot.Contains(supervisor.Info.pid, supervisor.Info.parentPid))
                throw new InvalidOperationException("Snapshot held member changed");
            if (!native.Alive(supervisor.Handle) ||
                !native.Alive(bridge.Handle) ||
                native.Listener(port) != bridge.Info.pid) throw new InvalidOperationException("Root changed");
            CheckPhase();
            revalidationDiagnostics = new { elapsedMilliseconds = phaseClock.ElapsedMilliseconds,
                argumentQueries = arguments.Count, imageFiles = images.Count, imageBytesHashed = images.Bytes };
        }
    }

    private Receipt Stop(Held supervisor, Held bridge)
    {
        var errors = new List<string>();
        var stopClock = Stopwatch.StartNew();
        // The supervisor goes first so it cannot start another bridge.
        Kill(supervisor, stopClock, errors);
        if (!native.Alive(supervisor.Handle))
        {
            // When a Node process exits, its job object ends its direct children with it (1.3
            // wraps each bare server command in cmd.exe), and their own children then name a
            // parent nobody holds. So the bridge's whole tree is held before the bridge stops.
            bool settled;
            Pin(stopClock, errors, out settled);
            Kill(bridge, stopClock, errors);
            if (!native.Alive(bridge.Handle)) Sweep(stopClock, errors);
        }
        var result = HeldStatus();
        result.errors = errors.ToArray();
        return result;
    }

    // A busy bridge starts and ends sessions every few seconds, so its descendants are found
    // while stopping instead of being frozen into the plan. Each round first holds everything
    // new that descends from a held process, then stops every held process not yet stopped
    // and waits for it, even if the tree was still growing. The next round finds anything
    // those processes started before they died.
    private void Sweep(Stopwatch stopClock, List<string> errors)
    {
        try
        {
            for (int round = 0; round < MaximumSweepRounds; round++)
            {
                // Once the stop budget is spent nothing more can be terminated, so the sweep ends.
                CheckStop(stopClock);
                bool settled;
                int pinned = Pin(stopClock, errors, out settled);
                var terminations = new List<Termination>();
                foreach (var process in held)
                {
                    if (process.Stopping) continue;
                    var termination = Terminate(process, stopClock, errors);
                    if (termination != null) terminations.Add(termination);
                }
                bool done = settled &&
                    pinned == 0 &&
                    terminations.Count == 0;
                if (done)
                {
                    swept = true;
                    return;
                }
                foreach (var termination in terminations) AwaitExit(termination, stopClock, errors);
            }
            errors.Add("sweep:rounds");
        }
        catch (Exception error)
        {
            errors.Add("sweep:" + (RefusalReason(error) ?? error.GetType().Name));
        }
    }

    // Holds every process that descends from a held process, repeating until a snapshot shows
    // nothing new (settled). Every held handle keeps its PID from being reused, so a process
    // whose parent PID is held and which started no earlier than that parent was started by it.
    // A tree still growing after every pass is left to the caller's next round; a snapshot that
    // cannot be read is reported. Nothing is stopped here, and nothing is thrown.
    private int Pin(Stopwatch stopClock, List<string> errors, out bool settled)
    {
        settled = false;
        int total = 0;
        try
        {
            for (int pass = 0; pass < MaximumPinPasses; pass++)
            {
                var current = new LegacySnapshot();
                current.Read(() => CheckStop(stopClock));
                int adopted = 0;
                // Processes held during this pass are walked in the same pass, so one snapshot
                // covers the whole tree; later passes only find processes started since.
                for (int index = 0; index < held.Count; index++)
                {
                    var parent = held[index];
                    foreach (int id in Children(current, parent.Info.pid))
                    {
                        if (held.Exists(value => value.Info.pid == id)) continue;
                        if (Adopt(id, parent, errors) != null) adopted++;
                    }
                }
                total += adopted;
                if (adopted == 0)
                {
                    settled = true;
                    return total;
                }
            }
        }
        catch (Exception error)
        {
            Reject("pin:" + (RefusalReason(error) ?? error.GetType().Name), errors);
        }
        return total;
    }

    private List<int> Children(LegacySnapshot current, int parentId)
    {
        var ids = current.Children(parentId);
        ids.Sort();
        return ids;
    }

    private Held Adopt(int id, Held parent, List<string> errors)
    {
        if (id == brokerId) return null;
        if (held.Count >= MaximumSweptProcesses + 2)
        {
            Reject("sweep:bound", errors);
            return null;
        }
        var opened = Api.OpenProcess(0x00100000 | 0x1000 | 1, false, id);
        if (opened.IsInvalid)
        {
            int code = Marshal.GetLastWin32Error();
            opened.Dispose();
            // 87: the process exited after the snapshot and nothing holds it any more.
            if (code != 87) Reject(id + ":OpenProcess:" + code, errors);
            return null;
        }
        try
        {
            long created = native.Creation(opened);
            long ancestorCreated;
            bool ancestor = ancestors.TryGetValue(id, out ancestorCreated) &&
                ancestorCreated == created;
            // A process older than the held parent got that PID from an earlier owner.
            bool child = native.Parent(opened) == parent.Info.pid &&
                created >= parent.Created;
            if (ancestor ||
                !child)
            {
                opened.Dispose();
                return null;
            }
            // An exited child is held as well: its handle keeps its PID, so its own children
            // stay traceable. Only a live process can belong to another user.
            bool foreign = native.Alive(opened) &&
                native.Owner(opened) != user;
            if (foreign)
            {
                opened.Dispose();
                Reject(id + ":owner", errors);
                return null;
            }
            var result = new Held { Handle = opened, Created = created, Info = new Identity { pid = id,
                creationTime = created.ToString(CultureInfo.InvariantCulture), parentPid = parent.Info.pid,
                parentCreationTime = parent.Info.creationTime, ownerSid = user } };
            held.Add(result);
            return result;
        }
        catch (Exception error)
        {
            opened.Dispose();
            var win32 = error as Win32Exception;
            Reject(id + ":" + error.GetType().Name + (win32 == null ? "" : ":" + win32.NativeErrorCode), errors);
            return null;
        }
    }

    private void Reject(string reason, List<string> errors)
    {
        if (rejected.Add(reason)) errors.Add(reason);
    }

    private void CheckStop(Stopwatch stopClock)
    {
        if (stopClock.ElapsedMilliseconds >= StopMilliseconds) throw new TimeoutException();
    }

    private void Kill(Held process, Stopwatch stopClock, List<string> errors)
    {
        var termination = Terminate(process, stopClock, errors);
        if (termination != null) AwaitExit(termination, stopClock, errors);
    }

    private Termination Terminate(Held process, Stopwatch stopClock, List<string> errors)
    {
        process.Stopping = true;
        try
        {
            if (!native.Alive(process.Handle)) return null;
            if (stopClock.ElapsedMilliseconds >= StopMilliseconds) throw new TimeoutException();
            bool terminated = Api.TerminateProcess(process.Handle, 1);
            int terminationError = terminated ? 0 : Marshal.GetLastWin32Error();
            return new Termination { Process = process, Terminated = terminated, Error = terminationError };
        }
        catch (Exception error)
        {
            RecordStopError(process, error, errors);
            return null;
        }
    }

    private void AwaitExit(Termination termination, Stopwatch stopClock, List<string> errors)
    {
        try
        {
            uint remaining = (uint)Math.Max(0, StopMilliseconds - stopClock.ElapsedMilliseconds);
            // Parent exit can already be terminating this child. A racing
            // TerminateProcess failure is reconciled only by this held handle
            // becoming signaled within the same total stop budget.
            if (Api.WaitForSingleObject(termination.Process.Handle, remaining) != 0)
            {
                if (!termination.Terminated) throw new Win32Exception(termination.Error);
                throw new TimeoutException();
            }
        }
        catch (Exception error) { RecordStopError(termination.Process, error, errors); }
    }

    private void RecordStopError(Held process, Exception error, List<string> errors)
    {
        var win32 = error as Win32Exception;
        errors.Add(process.Info.pid + ":" + error.GetType().Name +
            (win32 == null ? "" : ":" + win32.NativeErrorCode));
    }

    private Receipt HeldStatus()
    {
        bool rootsGone = true;
        int found = 0;
        int stopped = 0;
        foreach (var process in held)
        {
            bool alive = native.Alive(process.Handle);
            bool root = process.Info.pid == plan.roots.bridge.pid ||
                process.Info.pid == plan.roots.supervisor.pid;
            if (root)
            {
                if (alive) rootsGone = false;
                continue;
            }
            found++;
            if (!alive) stopped++;
        }
        bool descendantsGone = swept &&
            stopped == found &&
            rejected.Count == 0;
        return new Receipt { legacyRootStopVerified = rootsGone, observedDescendantsStopped = descendantsGone,
            descendantsFound = found, descendantsStopped = stopped,
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
            value.observed.Length > MaximumPlanIdentities - 2 ||
            value.excluded.Length + value.observed.Length > MaximumPlanIdentities - 2 ||
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
        // A plan written now lists no descendants, so this read-only check cannot vouch for them.
        bool descendantsVerified = childrenGone &&
            value.observed.Length > 0;
        return new Receipt { legacyRootStopVerified = rootsGone, observedDescendantsStopped = descendantsVerified,
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
            "Capture changed", "Child bound", "Root arguments mismatch", "Script bound",
            "Root changed", "Identity changed", "Arguments changed", "Process query changed",
            "Process query unavailable", "Process query generation changed",
            "Run the upgrade from a terminal the 1.3 bridge did not start",
            "Argument bounds", "Listener ambiguity", "Loopback listener missing",
            "Broker parent identity lost", "Script argument not fully qualified",
            "Snapshot schema unavailable", "Snapshot enumeration failed", "Snapshot entry bound",
            "Snapshot duplicate entry", "Snapshot identity unavailable", "Snapshot close failed",
            "Snapshot root changed", "Snapshot held member changed", "Argument query bound",
            "Argument query cancelled", "Argument query timed out", "Image file identity unavailable", "Image file identity changed",
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
    internal bool Stopping;
}

internal sealed class Termination
{
    internal Held Process;
    internal bool Terminated;
    internal int Error;
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
    public int? descendantsFound { get; set; }
    public int? descendantsStopped { get; set; }
    public string treeCompleteness { get; set; }
    public int observedCount { get; set; }
    public int excludedCount { get; set; }
    public string planSha256 { get; set; }
    public string[] errors { get; set; }
    public string unattributed { get; set; }
}
