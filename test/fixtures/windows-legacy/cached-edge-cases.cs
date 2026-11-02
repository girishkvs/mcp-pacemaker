using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Web.Script.Serialization;

// Drives the broker's stop sweep against real owned processes. Five cases model parent
// metadata (reused PIDs) on real processes; the nine-generation chain uses actual parentage.
internal sealed class CachedEdgeCases
{
    internal static CachedEdgeCases Current;
    private readonly LegacyNative native = new LegacyNative();
    private readonly JavaScriptSerializer json = new JavaScriptSerializer();
    private readonly List<Process> owned = new List<Process>();
    private readonly List<SafeProcess> handles = new List<SafeProcess>();
    // SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION.
    private const int TerminateAndQuery = 0x00101001;
    private readonly List<object> cleanups = new List<object>();
    // Modeled parent PID by creation time, and modeled snapshot children by parent PID.
    private readonly Dictionary<long, int> parents = new Dictionary<long, int>();
    private readonly Dictionary<int, List<int>> children = new Dictionary<int, List<int>>();
    private bool modeled;

    private static int Main(string[] args)
    {
        var instance = new CachedEdgeCases();
        Current = instance;
        return instance.Run(args);
    }

    private int Run(string[] args)
    {
        if (args.Length > 0 &&
            args[0] == "worker")
        {
            var directory = args[1];
            int remaining = int.Parse(args[2], CultureInfo.InvariantCulture);
            using (var self = Api.OpenProcess(0x00101000, false, Process.GetCurrentProcess().Id))
            {
                File.WriteAllText(Path.Combine(directory, "worker-" + Process.GetCurrentProcess().Id + ".json"),
                    json.Serialize(new { pid = Process.GetCurrentProcess().Id,
                        creationTime = native.Creation(self).ToString(CultureInfo.InvariantCulture) }));
            }
            if (remaining > 0) Start(directory, remaining - 1);
            Thread.Sleep(45000);
            return 0;
        }
        if (args.Length == 2 &&
            args[0] == "denied")
        {
            Deny();
            File.WriteAllText(Path.Combine(args[1], "denied-" + Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture)), "ready");
            Thread.Sleep(45000);
            return 0;
        }
        if (args.Length != 1) throw new ArgumentException("Test lifetime helper required; the sweep model has no old-code mode");
        ArmCapsule(args[0]);
        var results = new List<object>();
        try
        {
            results.Add(Modeled("older-root"));
            results.Add(Modeled("older-nonmember"));
            results.Add(Modeled("changed-parent"));
            results.Add(Unopenable(older: true));
            results.Add(Unopenable(older: false));
            results.Add(RealChain());
            Console.WriteLine(json.Serialize(new { expectedRed = false, results, cleanup = cleanups,
                limits = "Parent metadata is modeled on real owned handles except in the actual nine-generation chain." }));
            return 0;
        }
        catch (Exception error)
        {
            Console.WriteLine(json.Serialize(new { error = error.Message, stack = error.StackTrace,
                results, cleanup = cleanups }));
            return 1;
        }
    }

    private Process Start(string directory, int descendants)
    {
        var info = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,
            "worker \"" + directory + "\" " + descendants.ToString(CultureInfo.InvariantCulture));
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        var child = Process.Start(info);
        owned.Add(child);
        return child;
    }

    private Held Hold(int pid)
    {
        var handle = Api.OpenProcess(TerminateAndQuery, false, pid);
        native.Require(!handle.IsInvalid);
        handles.Add(handle);
        long created = native.Creation(handle);
        return new Held { Handle = handle, Created = created, Info = new Identity {
            pid = pid, creationTime = created.ToString(CultureInfo.InvariantCulture),
            parentPid = native.Parent(handle), ownerSid = native.Owner(handle), imagePath = native.Image(handle) } };
    }

    private object Modeled(string scenario)
    {
        var directory = NewDirectory("legacy-sweep-model-");
        var broker = new LegacyProcessBroker();
        try
        {
            var first = Hold(Start(directory, 0).Id);
            var second = Hold(Start(directory, 0).Id);
            var third = Hold(Start(directory, 0).Id);
            Held root;
            Held bridge;
            Held untouched = null;
            if (scenario == "older-root")
            {
                // The supervisor's creator PID was reused by a process its bridge started.
                root = first;
                bridge = second;
                Edge(root, bridge);
                Edge(bridge, third);
                Edge(third, root);
            }
            else if (scenario == "older-nonmember")
            {
                // An older process still names the supervisor's PID from that PID's earlier owner.
                root = second;
                bridge = third;
                untouched = first;
                Edge(root, bridge);
                Edge(root, first);
            }
            else
            {
                // The snapshot lists the process under the bridge, but its live parent differs.
                root = first;
                bridge = second;
                untouched = third;
                Edge(root, bridge);
                Child(bridge, third.Info.pid);
                parents[third.Created] = root.Info.pid;
            }
            var receipt = StopModel(broker, root, bridge, directory);
            bool? untouchedAlive = null;
            if (untouched != null) untouchedAlive = native.Alive(untouched.Handle);
            return new { scenario, modeledParentMetadata = true, stopped = receipt, untouchedAlive,
                rootsStopped = !native.Alive(root.Handle) && !native.Alive(bridge.Handle) };
        }
        finally
        {
            modeled = false;
            parents.Clear();
            children.Clear();
            ReleaseBroker(broker);
            Cleanup(directory);
        }
    }

    // A process that refuses this user query and terminate access, as csrss and winlogon do, named as
    // the root's child. An older one only names a PID the root reused and is left alone; a younger
    // one could be a real child, so the stop still reports that it could not verify it.
    private object Unopenable(bool older)
    {
        var directory = NewDirectory("legacy-sweep-unopenable-");
        var broker = new LegacyProcessBroker();
        try
        {
            var denied = older ? StartDenied(directory) : null;
            var root = Hold(Start(directory, 0).Id);
            var bridge = Hold(Start(directory, 0).Id);
            if (!older) denied = StartDenied(directory);
            Edge(root, bridge);
            Child(root, denied.Id);
            var receipt = StopModel(broker, root, bridge, directory);
            return new { scenario = older ? "older-unopenable" : "younger-unopenable", modeledParentMetadata = true,
                deniedPid = denied.Id, stopped = receipt, untouchedAlive = !denied.HasExited };
        }
        finally
        {
            modeled = false;
            parents.Clear();
            children.Clear();
            ReleaseBroker(broker);
            Cleanup(directory);
        }
    }

    private Process StartDenied(string directory)
    {
        var info = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "denied \"" + directory + "\"");
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        var child = Process.Start(info);
        owned.Add(child);
        var ready = Path.Combine(directory, "denied-" + child.Id.ToString(CultureInfo.InvariantCulture));
        var wait = Stopwatch.StartNew();
        while (!File.Exists(ready))
        {
            if (wait.ElapsedMilliseconds > 10000) throw new InvalidOperationException("Owned denied worker startup bound");
            Thread.Sleep(20);
        }
        // An elevated run can open it anyway, which would make the scenarios meaningless.
        var probe = Api.OpenProcess(TerminateAndQuery, false, child.Id);
        int code = probe.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        probe.Dispose();
        if (code != 5) throw new InvalidOperationException(
            "Owned denied worker did not refuse this user (" + code.ToString(CultureInfo.InvariantCulture) + "); run the model without elevation");
        return child;
    }

    // Leaves this user only SYNCHRONIZE and READ_CONTROL on this process, so it refuses query and
    // terminate access as csrss and winlogon do.
    private void Deny()
    {
        var acl = new RawAcl(GenericAcl.AclRevision, 1);
        acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x00120000,
            WindowsIdentity.GetCurrent().User, false, null));
        var bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        uint status = CachedModelApi.SetSecurityInfo(CachedModelApi.GetCurrentProcess(), 6, 4, IntPtr.Zero, IntPtr.Zero, bytes, IntPtr.Zero);
        if (status != 0) throw new Win32Exception((int)status);
    }

    private object RealChain()
    {
        var directory = NewDirectory("legacy-sweep-chain-");
        var broker = new LegacyProcessBroker();
        try
        {
            var first = Start(directory, 8);
            var wait = Stopwatch.StartNew();
            while (Directory.GetFiles(directory, "worker-*.json").Length != 9)
            {
                if (wait.ElapsedMilliseconds > 10000) throw new InvalidOperationException("Owned chain startup bound");
                Thread.Sleep(20);
            }
            var generations = new List<Held>();
            foreach (var file in Directory.GetFiles(directory, "worker-*.json"))
            {
                var identity = json.Deserialize<WorkerIdentity>(File.ReadAllText(file));
                var process = Hold(identity.pid);
                if (process.Created.ToString(CultureInfo.InvariantCulture) != identity.creationTime)
                    throw new InvalidOperationException("Owned chain generation changed");
                generations.Add(process);
            }
            generations.Sort((left, right) => left.Created.CompareTo(right.Created));
            if (generations[0].Info.pid != first.Id) throw new InvalidOperationException("Owned chain order changed");
            var receipt = StopModel(broker, generations[0], generations[1], directory);
            int stopped = 0;
            foreach (var generation in generations)
                if (!native.Alive(generation.Handle)) stopped++;
            return new { scenario = "actual-nine-generation-chain", modeledParentMetadata = false,
                generations = generations.Count, generationsStopped = stopped, stopped = receipt };
        }
        finally
        {
            ReleaseBroker(broker);
            Cleanup(directory);
        }
    }

    private Receipt StopModel(LegacyProcessBroker broker, Held root, Held bridge, string directory)
    {
        var captured = (List<Held>)Field(broker, "held");
        captured.Add(bridge);
        captured.Add(root);
        SetField(broker, "root", directory);
        SetField(broker, "port", 1);
        SetField(broker, "plan", (Plan)Invoke(broker, "MakePlan", root, bridge));
        modeled = parents.Count > 0;
        try { return (Receipt)Invoke(broker, "Stop", root, bridge); }
        finally { modeled = false; }
    }

    private void Edge(Held parent, Held child)
    {
        Child(parent, child.Info.pid);
        parents[child.Created] = parent.Info.pid;
    }

    private void Child(Held parent, int id)
    {
        List<int> group;
        if (!children.TryGetValue(parent.Info.pid, out group))
        {
            group = new List<int>();
            children.Add(parent.Info.pid, group);
        }
        group.Add(id);
    }

    internal int? Parent(SafeProcess process)
    {
        if (!modeled) return null;
        int parent;
        if (parents.TryGetValue(native.Creation(process), out parent)) return parent;
        return null;
    }

    internal List<int> Children(int parent)
    {
        if (!modeled) return null;
        List<int> group;
        if (children.TryGetValue(parent, out group)) return new List<int>(group);
        return new List<int>();
    }

    private string NewDirectory(string prefix)
    {
        var directory = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    // The sweep opens its own handles for what it adopts; this model owns only its Hold handles.
    private void ReleaseBroker(LegacyProcessBroker broker)
    {
        foreach (var process in (List<Held>)Field(broker, "held"))
            if (!handles.Contains(process.Handle)) process.Handle.Dispose();
    }

    private object Field(object instance, string name) { return instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(instance); }
    private void SetField(object instance, string name, object value) { instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(instance, value); }
    private object Invoke(object instance, string name, params object[] args)
    {
        try { return instance.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic).Invoke(instance, args); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    private void Cleanup(string directory)
    {
        var identities = new HashSet<string>();
        foreach (var handle in handles)
        {
            long created = native.Creation(handle);
            uint pid = CachedModelApi.GetProcessId(handle);
            var key = pid.ToString(CultureInfo.InvariantCulture) + ":" + created.ToString(CultureInfo.InvariantCulture);
            if (native.Alive(handle))
            {
                Api.TerminateProcess(handle, 1);
                // WaitForSingleObject reports WAIT_TIMEOUT without setting a Win32 error, so report
                // the real condition, and give a loaded host time to reap a nine-generation chain.
                uint wait = Api.WaitForSingleObject(handle, 30000);
                if (wait != 0) throw new InvalidOperationException(
                    "Owned cleanup did not observe exit for pid " +
                    pid.ToString(CultureInfo.InvariantCulture) + " (wait 0x" + wait.ToString("X") + ")");
            }
            if (identities.Add(key)) cleanups.Add(new { pid, creationTime = created.ToString(CultureInfo.InvariantCulture),
                heldHandleSignaled = !native.Alive(handle) });
            handle.Dispose();
        }
        handles.Clear();
        // A denied worker refuses this user a new handle, but the one Process.Start returned can end it.
        foreach (var process in owned)
        {
            if (!process.HasExited) process.Kill();
            if (!process.WaitForExit(30000)) throw new InvalidOperationException(
                "Owned cleanup did not observe exit for pid " + process.Id.ToString(CultureInfo.InvariantCulture));
            process.Dispose();
        }
        owned.Clear();
        Directory.Delete(directory, true);
    }

    private void ArmCapsule(string helper)
    {
        var info = new ProcessStartInfo(helper, "watch-parent " + Process.GetCurrentProcess().Id);
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        using (var owner = Process.Start(info))
        {
            var ready = owner.StandardOutput.ReadLine();
            var values = ready == null ? new string[0] : ready.Split(' ');
            if (values.Length != 3 ||
                values[0] != "MCP_JOB_READY" ||
                values[1] != owner.Id.ToString(CultureInfo.InvariantCulture))
                throw new InvalidOperationException("Owned test capsule was not established");
            Console.WriteLine(json.Serialize(new { type = "capsule", lifetime = new {
                protocol = 1, ownerPid = owner.Id, ownerCreationTime = values[2] },
                modelIdentity = new { pid = Process.GetCurrentProcess().Id,
                    creationTime = Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture) } }));
            Console.Out.Flush();
            if (Console.ReadLine() != "GO") throw new InvalidOperationException("Owned capsule observer was not armed");
        }
    }
}

internal sealed class WorkerIdentity
{
    public int pid { get; set; }
    public string creationTime { get; set; }
}

internal static class CachedModelApi
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetProcessId(SafeProcess process);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll")]
    internal static extern uint SetSecurityInfo(IntPtr handle, int objectType, int securityInformation,
        IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);
}
