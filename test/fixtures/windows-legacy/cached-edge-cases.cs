using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web.Script.Serialization;

internal sealed class CachedEdgeCases
{
    internal static CachedEdgeCases Current;
    private readonly LegacyNative native = new LegacyNative();
    private readonly JavaScriptSerializer json = new JavaScriptSerializer();
    private readonly List<Process> owned = new List<Process>();
    private readonly List<SafeProcess> handles = new List<SafeProcess>();
    private readonly List<object> cleanups = new List<object>();
    private Held root, bridge, leaf;
    private string mode = "none";

    private static int Main(string[] args)
    {
        var instance = new CachedEdgeCases();
        Current = instance;
        return instance.Run(args);
    }

    private int Run(string[] args)
    {
        if (args.Length > 0 && args[0] == "worker")
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
        if (args.Length < 1) throw new ArgumentException("Test lifetime helper required");
        ArmCapsule(args[0]);
        bool expectedRed = args.Length == 2 && args[1] == "old-red";
        var results = new List<object>();
        try
        {
            foreach (var scenario in expectedRed ? new[] { "older-root" } :
                new[] { "older-root", "changed-parent", "dead-root", "dead-parent", "changed-birth", "newer-root", "nonroot-older" })
                results.Add(Cached(scenario, expectedRed));
            if (!expectedRed) results.Add(RealDepth());
            Console.WriteLine(json.Serialize(new { expectedRed, results, cleanup = cleanups,
                limits = "Cached-parent reuse is modeled on real owned handles; over-depth chain is actual parentage. No live identities queried." }));
            return 0;
        }
        catch (Exception error)
        {
            Console.WriteLine(json.Serialize(new { error = error.Message, results, cleanup = cleanups }));
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
        var handle = Api.OpenProcess(0x00101001, false, pid);
        native.Require(!handle.IsInvalid);
        handles.Add(handle);
        long created = native.Creation(handle);
        return new Held { Handle = handle, Created = created, Info = new Identity {
            pid = pid, creationTime = created.ToString(CultureInfo.InvariantCulture),
            parentPid = native.Parent(handle), ownerSid = native.Owner(handle), imagePath = native.Image(handle),
            imageSha256 = new string('a', 64), argvSha256 = new string('b', 64) } };
    }

    private object Cached(string scenario, bool expectedRed)
    {
        var directory = Path.Combine(Path.GetTempPath(), "legacy-cached-edge-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var broker = new LegacyProcessBroker();
        try
        {
            mode = "none";
            var first = Hold(Start(directory, 0).Id);
            var second = Hold(Start(directory, 0).Id);
            var third = Hold(Start(directory, 0).Id);
            root = scenario == "newer-root" ? third : first;
            bridge = second;
            leaf = scenario == "newer-root" ? first : third;
            root.Info.parentPid = leaf.Info.pid;
            root.Info.parentCreationTime = null;
            bridge.Info.parentPid = root.Info.pid;
            bridge.Info.parentCreationTime = root.Info.creationTime;
            leaf.Info.parentPid = bridge.Info.pid;
            leaf.Info.parentCreationTime = bridge.Info.creationTime;
            var keep = typeof(Held).GetField("KeepArguments", BindingFlags.Instance | BindingFlags.NonPublic);
            if (keep != null) { keep.SetValue(root, true); keep.SetValue(bridge, true); }
            var marker = typeof(Held).GetField("SelectedRoot", BindingFlags.Instance | BindingFlags.NonPublic);
            if (marker != null)
            {
                marker.SetValue(root, scenario != "nonroot-older");
                marker.SetValue(bridge, true);
            }
            var captured = (List<Held>)Field(broker, "held");
            captured.AddRange(new[] { root, bridge, leaf });
            SetField(broker, "root", directory);
            SetField(broker, "port", 1);
            mode = scenario;
            if (scenario == "dead-root") { native.Require(Api.TerminateProcess(root.Handle, 1)); Api.WaitForSingleObject(root.Handle, 3000); }
            if (scenario == "dead-parent") { native.Require(Api.TerminateProcess(leaf.Handle, 1)); Api.WaitForSingleObject(leaf.Handle, 3000); }
            if (scenario == "changed-birth") root.Created++;
            var reason = "";
            try
            {
                if (scenario == "older-root") Invoke(broker, "CaptureChildren", root, 0);
                else Invoke(broker, "Capture", root.Info.pid, leaf);
            }
            catch (Exception error) { reason = error.Message; }
            if (expectedRed)
            {
                if (reason != "Depth bound") throw new InvalidOperationException("Old cached path did not reproduce Depth bound: " + reason);
                return new { scenario, modeledParentMetadata = true, refused = reason, selectedCount = captured.Count };
            }
            if (scenario != "older-root")
            {
                if (reason == "") throw new InvalidOperationException("Negative cached edge was accepted: " + scenario);
                return new { scenario, modeledParentMetadata = true, refused = reason,
                    excludedRoot = ((List<ExcludedIdentity>)Field(broker, "excluded")).Exists(value => value.pid == root.Info.pid) };
            }
            if (reason != "") throw new InvalidOperationException("Older cached root refused: " + reason);
            if (captured.Count != 3 ||
                root.Info.parentCreationTime != null) throw new InvalidOperationException("Root membership or binding changed");
            var exclusions = (List<ExcludedIdentity>)Field(broker, "excluded");
            if (exclusions.Count != 0) throw new InvalidOperationException("Selected root was excluded");
            var plan = (Plan)Invoke(broker, "MakePlan", root, bridge);
            Invoke(broker, "ValidatePlan", plan);
            bool reusedEdge = (bool)Invoke(broker, "KnownEdge", root, leaf);
            if (reusedEdge) throw new InvalidOperationException("Revalidation did not ignore the false creator edge");
            SetField(broker, "plan", plan);
            var stopped = (Receipt)Invoke(broker, "Stop", root, bridge);
            if (!stopped.legacyRootStopVerified ||
                !stopped.observedDescendantsStopped ||
                stopped.errors.Length != 0) throw new InvalidOperationException("Owned modeled set stop failed");
            return new { scenario, modeledParentMetadata = true, finitePlan = true, selectedCount = captured.Count,
                excludedRoot = false, rootParentBirthUnchanged = true, revalidationSkippedOnlyEdge = true, stopped };
        }
        finally { Cleanup(directory); root = bridge = leaf = null; mode = "none"; }
    }

    private object RealDepth()
    {
        var directory = Path.Combine(Path.GetTempPath(), "legacy-actual-depth-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var broker = new LegacyProcessBroker();
        try
        {
            mode = "none";
            var first = Start(directory, 8);
            var wait = Stopwatch.StartNew();
            while (Directory.GetFiles(directory, "worker-*.json").Length != 9)
            {
                if (wait.ElapsedMilliseconds > 10000) throw new InvalidOperationException("Owned depth chain startup bound");
                Thread.Sleep(20);
            }
            foreach (var file in Directory.GetFiles(directory, "worker-*.json"))
            {
                var identity = json.Deserialize<WorkerIdentity>(File.ReadAllText(file));
                var process = Hold(identity.pid);
                if (process.Created.ToString(CultureInfo.InvariantCulture) != identity.creationTime)
                    throw new InvalidOperationException("Owned depth generation changed");
                if (identity.pid == first.Id) root = process;
            }
            ((List<Held>)Field(broker, "held")).Add(root);
            var snapshotField = typeof(LegacyProcessBroker).GetField("snapshot", BindingFlags.Instance | BindingFlags.NonPublic);
            if (snapshotField != null) Invoke(broker, "RefreshSnapshot");
            var reason = "";
            try { Invoke(broker, "CaptureChildren", root, 0); }
            catch (Exception error) { reason = error.Message; }
            if (reason != "Depth bound") throw new InvalidOperationException("Actual depth8 boundary did not refuse: " + reason);
            foreach (var process in (List<Held>)Field(broker, "held"))
                if (!handles.Contains(process.Handle)) handles.Add(process.Handle);
            return new { scenario = "actual-eight-edge-chain", modeledParentMetadata = false,
                ownedGenerations = 9, refused = reason };
        }
        finally { Cleanup(directory); root = null; }
    }

    internal int? Parent(SafeProcess process)
    {
        if (mode == "none") return null;
        long created = native.Creation(process);
        if (created.ToString(CultureInfo.InvariantCulture) == root.Info.creationTime)
            return mode == "changed-parent" ? bridge.Info.pid : leaf.Info.pid;
        if (created == bridge.Created) return root.Info.pid;
        if (created == leaf.Created) return bridge.Info.pid;
        return null;
    }

    internal List<int> Children(int parent)
    {
        if (mode == "none") return null;
        if (parent == root.Info.pid) return new List<int> { bridge.Info.pid };
        if (parent == bridge.Info.pid) return new List<int> { leaf.Info.pid };
        if (parent == leaf.Info.pid) return new List<int> { root.Info.pid };
        return new List<int>();
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
                native.Require(Api.TerminateProcess(handle, 1));
                native.Require(Api.WaitForSingleObject(handle, 3000) == 0);
            }
            if (identities.Add(key)) cleanups.Add(new { pid, creationTime = created.ToString(CultureInfo.InvariantCulture),
                heldHandleSignaled = !native.Alive(handle) });
            handle.Dispose();
        }
        handles.Clear();
        foreach (var process in owned) process.Dispose();
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
}
