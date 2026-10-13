using System;
using System.Collections.Concurrent;
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
using Microsoft.Win32.SafeHandles;

internal sealed class LegacyNative
{
    internal string Hash(byte[] bytes)
    {
        using (var hash = SHA256.Create())
        {
            return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
    }

    internal string HashFile(string path)
    {
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var hash = SHA256.Create())
        {
            return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
    }

    internal long Creation(SafeProcess process)
    {
        long created;
        long exit;
        long kernel;
        long user;
        Require(Api.GetProcessTimes(process, out created, out exit, out kernel, out user), LegacyFailureApi.GetProcessTimes);
        return created;
    }

    internal bool Alive(SafeProcess process)
    {
        uint result = Api.WaitForSingleObject(process, 0);
        Require(result != 0xffffffff, LegacyFailureApi.WaitForSingleObject);
        return result == 0x102;
    }

    internal string Image(SafeProcess process)
    {
        var value = new StringBuilder(32768);
        int size = value.Capacity;
        Require(Api.QueryFullProcessImageNameW(process, 0, value, ref size), LegacyFailureApi.QueryFullProcessImageName);
        return value.ToString();
    }

    internal string Owner(SafeProcess process)
    {
        SafeProcess token;
        Require(Api.OpenProcessToken(process, 8, out token), LegacyFailureApi.OpenProcessToken);
        using (token)
        {
            int size;
            Api.GetTokenInformation(token, 1, IntPtr.Zero, 0, out size);
            if (size <= 0 ||
                size > 65536) throw new InvalidOperationException("Token bounds");
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                Require(Api.GetTokenInformation(token, 1, buffer, size, out size), LegacyFailureApi.GetTokenInformation);
                return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    internal int Parent(SafeProcess process)
    {
        var information = new Api.BasicInformation();
        int returned;
        int status = Api.NtQueryInformationProcess(process, 0, out information,
            Marshal.SizeOf(information), out returned);
        if (status != 0)
        {
            var error = new Win32Exception(status);
            TagApi(error, LegacyFailureApi.NtQueryInformationProcess);
            throw error;
        }
        return checked((int)information.ParentId.ToInt64());
    }

    internal string[] Arguments(int processId, SafeProcess held)
    {
        using (var search = Search("ProcessId = " + processId.ToString(CultureInfo.InvariantCulture),
            "ProcessId,CreationDate,CommandLine"))
        using (var rows = search.Get())
        {
            if (rows.Count != 1) throw new InvalidOperationException("Process query changed");
            foreach (ManagementObject row in rows)
            using (row)
            {
                var command = row["CommandLine"] as string;
                var date = row["CreationDate"] as string;
                if (string.IsNullOrEmpty(command) ||
                    command.Length > 32768 ||
                    string.IsNullOrEmpty(date)) throw new InvalidOperationException("Process query unavailable");
                long queried = ManagementDateTimeConverter.ToDateTime(date).ToUniversalTime().ToFileTimeUtc();
                if (Math.Abs(queried - Creation(held)) > 10 ||
                    !Alive(held)) throw new InvalidOperationException("Process query generation changed");
                int count;
                var pointer = Api.CommandLineToArgvW(command, out count);
                Require(pointer != IntPtr.Zero);
                try
                {
                    if (count < 1 ||
                        count > 1024) throw new InvalidOperationException("Argument bounds");
                    var args = new string[count];
                    for (int index = 0; index < count; index++)
                        args[index] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, index * IntPtr.Size));
                    return args;
                }
                finally { Api.LocalFree(pointer); }
            }
        }
        throw new InvalidOperationException("Process query missing");
    }

    internal ManagementObjectSearcher Search(string filter, string fields)
    {
        var options = new EnumerationOptions { Timeout = TimeSpan.FromSeconds(2), ReturnImmediately = false };
        return new ManagementObjectSearcher(@"root\cimv2",
            "SELECT " + fields + " FROM Win32_Process WHERE " + filter, options);
    }

    internal int Listener(int port)
    {
        int size = 0;
        uint result = Api.GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 3, 0);
        if (result != 122 ||
            size < 4 ||
            size > 16 * 1024 * 1024)
        {
            var error = new Win32Exception(unchecked((int)result));
            TagApi(error, LegacyFailureApi.GetExtendedTcpTableSize);
            throw error;
        }
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = Api.GetExtendedTcpTable(buffer, ref size, false, 2, 3, 0);
            if (result != 0)
            {
                var error = new Win32Exception(unchecked((int)result));
                TagApi(error, LegacyFailureApi.GetExtendedTcpTableRows);
                throw error;
            }
            int count = Marshal.ReadInt32(buffer);
            if (count < 0 ||
                count > (size - 4) / 24) throw new InvalidOperationException("TCP bounds");
            int found = 0;
            for (int index = 0; index < count; index++)
            {
                var row = IntPtr.Add(buffer, 4 + index * 24);
                int rowPort = (Marshal.ReadByte(row, 8) << 8) | Marshal.ReadByte(row, 9);
                uint address = unchecked((uint)Marshal.ReadInt32(row, 4));
                if (rowPort != port ||
                    (address != 0x0100007f && address != 0)) continue;
                if (address == 0 ||
                    found != 0) throw new InvalidOperationException("Listener ambiguity");
                found = Marshal.ReadInt32(row, 20);
            }
            if (found <= 0) throw new InvalidOperationException("Loopback listener missing");
            return found;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    internal void Require(bool value)
    {
        if (!value) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    internal void Require(bool value, LegacyFailureApi api)
    {
        if (value) return;
        int code = Marshal.GetLastWin32Error();
        var error = new Win32Exception(code);
        TagApi(error, api);
        throw error;
    }

    internal void TagApi(Exception error, LegacyFailureApi api)
    {
        try
        {
            if (!error.Data.Contains("LegacyFailureApi")) error.Data["LegacyFailureApi"] = api;
        }
        catch { /* Diagnostic metadata must never replace the original failure. */ }
    }

    internal void TagFailure(Exception error, LegacyFailureStage substage, int? pid = null,
        long? creationTime = null, int? actualParentPid = null, int? expectedParentPid = null,
        string expectedParentCreationTime = null, bool? alive = null, bool? parentAlive = null,
        bool? ownerMatched = null)
    {
        try
        {
            if (error.Data.Contains("LegacyFailureDetails")) return;
            var api = error.Data["LegacyFailureApi"] is LegacyFailureApi
                ? (LegacyFailureApi)error.Data["LegacyFailureApi"] : LegacyFailureApi.Unknown;
            error.Data["LegacyFailureDetails"] = new LegacyFailureDetails(api, substage, pid, creationTime,
                actualParentPid, expectedParentPid, expectedParentCreationTime, alive, parentAlive, ownerMatched);
        }
        catch { /* Use only previously observed values; no recovery query or fallback. */ }
    }

    internal LegacyFailureDetails FailureDetails(Exception error)
    {
        try
        {
            var details = error.Data["LegacyFailureDetails"] as LegacyFailureDetails;
            if (details != null) return details;
            if (error.Data["LegacyFailureApi"] is LegacyFailureApi)
                return new LegacyFailureDetails((LegacyFailureApi)error.Data["LegacyFailureApi"],
                    LegacyFailureStage.Unknown, null, null, null, null, null, null, null, null);
        }
        catch { /* Reporting cannot change refusal behavior. */ }
        return null;
    }

    internal object Memory()
    {
        var counters = new Api.MemoryCounters();
        uint size = (uint)Marshal.SizeOf(counters);
        if (!Api.GetProcessMemoryInfo(new IntPtr(-1), out counters, size))
            return new { verified = false, nativeError = Marshal.GetLastWin32Error() };
        return new { verified = true, privateBytes = counters.PrivateUsage.ToUInt64(),
            peakPrivateCommitBytes = counters.PeakPagefileUsage.ToUInt64() };
    }
}

internal enum LegacyFailureApi
{
    Unknown, OpenProcessQuery, OpenProcessTerminate, GetProcessTimes, WaitForSingleObject,
    QueryFullProcessImageName, OpenProcessToken, GetTokenInformation, NtQueryInformationProcess,
    GetExtendedTcpTableSize, GetExtendedTcpTableRows, CreateToolhelp32Snapshot,
    FileOpenRead, GetFileInformationByHandle, WmiConnect, WmiQuery, CommandLineToArgv
}

internal enum LegacyFailureStage
{
    Unknown, CaptureOpenQuery, CaptureIdentity, CaptureParent, CaptureParentLiveness, CaptureOwner, CaptureOpenTerminate,
    CaptureImage, CaptureImageFacts, Snapshot, ArgumentConnect,
    ArgumentQuery, ArgumentIdentity
}

[Serializable]
internal sealed class LegacyFailureDetails
{
    public string api { get; private set; }
    public string substage { get; private set; }
    public int? requestedPid { get; private set; }
    public string creationTime { get; private set; }
    public bool generationKnown { get; private set; }
    public int? actualParentPid { get; private set; }
    public int? expectedParentPid { get; private set; }
    public string expectedParentCreationTime { get; private set; }
    public bool? alive { get; private set; }
    public bool? parentAlive { get; private set; }
    public bool? ownerMatched { get; private set; }
    public string observation { get { return "stored-observations-not-fresh-proof"; } }

    internal LegacyFailureDetails(LegacyFailureApi api, LegacyFailureStage substage, int? pid,
        long? creationTime, int? actualParentPid, int? expectedParentPid, string expectedParentCreationTime,
        bool? alive, bool? parentAlive, bool? ownerMatched)
    {
        this.api = api.ToString();
        this.substage = substage.ToString();
        requestedPid = pid;
        this.creationTime = creationTime.HasValue ? creationTime.GetValueOrDefault().ToString(CultureInfo.InvariantCulture) : null;
        generationKnown = creationTime.HasValue;
        this.actualParentPid = actualParentPid;
        this.expectedParentPid = expectedParentPid;
        this.expectedParentCreationTime = expectedParentCreationTime;
        this.alive = alive;
        this.parentAlive = parentAlive;
        this.ownerMatched = ownerMatched;
    }
}

internal sealed class SafeProcess : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeProcess() : base(true) { }
    protected override bool ReleaseHandle() { return Api.CloseHandle(handle); }
}

internal sealed class LegacySnapshot
{
    private readonly LegacyNative diagnostic = new LegacyNative();
    private readonly Dictionary<uint, List<uint>> children = new Dictionary<uint, List<uint>>();
    private readonly Dictionary<uint, uint> parents = new Dictionary<uint, uint>();

    internal void Read(Action check)
    {
        int size = Marshal.SizeOf(typeof(Api.ProcessEntryLayout));
        int pidOffset = Marshal.OffsetOf(typeof(Api.ProcessEntryLayout), "ProcessId").ToInt32();
        int parentOffset = Marshal.OffsetOf(typeof(Api.ProcessEntryLayout), "ParentId").ToInt32();
        if (size != (IntPtr.Size == 8 ? 568 : 556) ||
            pidOffset != 8 ||
            parentOffset != (IntPtr.Size == 8 ? 32 : 24))
            throw new InvalidOperationException("Snapshot schema unavailable");
        var cleared = new byte[size];
        var buffer = Marshal.AllocHGlobal(size);
        SafeSnapshot snapshot = null;
        try
        {
            check();
            snapshot = Api.CreateToolhelp32Snapshot(2, 0);
            if (snapshot.IsInvalid)
            {
                var error = new Win32Exception(Marshal.GetLastWin32Error());
                diagnostic.TagApi(error, LegacyFailureApi.CreateToolhelp32Snapshot);
                diagnostic.TagFailure(error, LegacyFailureStage.Snapshot);
                throw error;
            }
            Marshal.Copy(cleared, 0, buffer, size);
            Marshal.WriteInt32(buffer, size);
            bool found = Api.Process32FirstW(snapshot, buffer);
            if (!found) throw new InvalidOperationException("Snapshot enumeration failed");
            int entries = 0;
            while (found)
            {
                check();
                if (++entries > 16384) throw new InvalidOperationException("Snapshot entry bound");
                if (Marshal.ReadInt32(buffer) != size) throw new InvalidOperationException("Snapshot schema unavailable");
                uint pid = unchecked((uint)Marshal.ReadInt32(buffer, pidOffset));
                uint parent = unchecked((uint)Marshal.ReadInt32(buffer, parentOffset));
                // The API fills other fields too. Never marshal names; retain only PID pairs.
                Marshal.Copy(cleared, 0, buffer, size);
                if (parents.ContainsKey(pid)) throw new InvalidOperationException("Snapshot duplicate entry");
                parents.Add(pid, parent);
                List<uint> group;
                if (!children.TryGetValue(parent, out group))
                {
                    group = new List<uint>();
                    children.Add(parent, group);
                }
                group.Add(pid);
                Marshal.WriteInt32(buffer, size);
                found = Api.Process32NextW(snapshot, buffer);
                if (!found &&
                    Marshal.GetLastWin32Error() != 18) throw new InvalidOperationException("Snapshot enumeration failed");
            }
        }
        finally
        {
            Marshal.Copy(cleared, 0, buffer, size);
            Marshal.FreeHGlobal(buffer);
            if (snapshot != null) snapshot.Dispose();
        }
        if (!snapshot.Closed) throw new InvalidOperationException("Snapshot close failed");
    }

    internal List<int> Children(int parent)
    {
        var result = new List<int>();
        List<uint> group;
        if (children.TryGetValue(checked((uint)parent), out group))
        {
            foreach (uint pid in group)
            {
                if (pid == 0 ||
                    pid > int.MaxValue) throw new InvalidOperationException("Snapshot identity unavailable");
                result.Add((int)pid);
                if (result.Count > 512) throw new InvalidOperationException("Child bound");
            }
        }
        return result;
    }

    internal bool Contains(int pid, int parent)
    {
        uint actual;
        return parents.TryGetValue(checked((uint)pid), out actual) &&
            actual == checked((uint)parent);
    }
}

internal sealed class SafeSnapshot : SafeHandleZeroOrMinusOneIsInvalid
{
    internal bool Closed;
    public SafeSnapshot() : base(true) { }
    protected override bool ReleaseHandle()
    {
        Closed = Api.CloseHandle(handle);
        return Closed;
    }
}

internal sealed class LegacyImageCache : IDisposable
{
    private readonly LegacyNative diagnostic = new LegacyNative();
    private readonly Dictionary<string, LegacyImagePin> files = new Dictionary<string, LegacyImagePin>();
    private readonly Action check;
    internal long Bytes { get; private set; }
    internal int Count { get { return files.Count; } }

    internal LegacyImageCache(Action check) { this.check = check; }

    internal string Hash(string path)
    {
        check();
        FileStream stream;
        try { stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (Exception error) { diagnostic.TagApi(error, LegacyFailureApi.FileOpenRead); throw; }
        bool retained = false;
        try
        {
            Api.FileInformation identity;
            if (!Api.GetFileInformationByHandle(stream.SafeFileHandle, out identity))
            {
                var error = new Win32Exception(Marshal.GetLastWin32Error());
                diagnostic.TagApi(error, LegacyFailureApi.GetFileInformationByHandle);
                throw error;
            }
            ulong number = ((ulong)identity.IndexHigh << 32) | identity.IndexLow;
            if (number == 0) throw new InvalidOperationException("Image file identity unavailable");
            var key = identity.Volume.ToString("x8", CultureInfo.InvariantCulture) + ":" +
                number.ToString("x16", CultureInfo.InvariantCulture);
            LegacyImagePin prior;
            if (files.TryGetValue(key, out prior))
            {
                if (prior.Stream.SafeFileHandle.IsClosed ||
                    prior.Stream.Length != stream.Length) throw new InvalidOperationException("Image file identity changed");
                return prior.Digest;
            }
            if (files.Count >= 64 ||
                stream.Length < 1 ||
                stream.Length > 256L * 1024 * 1024 ||
                Bytes + stream.Length > 512L * 1024 * 1024) throw new InvalidOperationException("Image hash bound");
            Bytes += stream.Length;
            var digest = "";
            using (var hash = SHA256.Create())
                digest = BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            check();
            files.Add(key, new LegacyImagePin { Stream = stream, Digest = digest });
            retained = true;
            return digest;
        }
        finally { if (!retained) stream.Dispose(); }
    }

    public void Dispose()
    {
        foreach (var file in files.Values) file.Stream.Dispose();
        files.Clear();
    }
}

internal sealed class LegacyImagePin
{
    internal FileStream Stream;
    internal string Digest;
}

internal sealed class LegacyArgumentQueries : IDisposable
{
    private readonly Action check;
    private readonly List<LegacyQueryWorker> workers = new List<LegacyQueryWorker>();
    private volatile bool cancelled;
    private int count;
    private int maximum;
    private bool disposed;
    internal int Count { get { return count; } }

    internal LegacyArgumentQueries(Action check) { this.check = check; }

    internal void BeginPhase(int maximum)
    {
        this.maximum = maximum;
        count = 0;
    }

    internal void Read(List<Held> processes, bool capture)
    {
        if (processes.Count == 0) return;
        EnsureWorkers();
        for (int offset = 0; offset < processes.Count; offset += 128)
        {
            Check();
            var wave = new List<LegacyArgumentBatch>();
            try
            {
                for (int index = 0; index < 4 && offset + index * 32 < processes.Count; index++)
                {
                    int start = offset + index * 32;
                    var batch = new LegacyArgumentBatch {
                        Processes = processes.GetRange(start, Math.Min(32, processes.Count - start)), Capture = capture
                    };
                    wave.Add(batch);
                    workers[index].Queue.Add(batch);
                }
                foreach (var batch in wave)
                    while (!batch.Done.Wait(25)) Check();
                foreach (var batch in wave)
                    if (batch.Error != null) throw batch.Error;
                Check();
                if (capture)
                {
                    foreach (var batch in wave)
                    foreach (var result in batch.Results)
                    {
                        result.Process.Info.argvSha256 = result.Digest;
                        result.Process.Arguments = result.Arguments;
                    }
                }
            }
            catch { cancelled = true; Dispose(); throw; }
            finally
            {
                foreach (var batch in wave) batch.Done.Dispose();
            }
        }
    }

    private void EnsureWorkers()
    {
        if (workers.Count != 0) return;
        for (int index = 0; index < 4; index++)
        {
            var worker = new LegacyQueryWorker();
            worker.Thread = new Thread(() =>
            {
                ManagementScope scope = null;
                var native = new LegacyNative();
                var json = new JavaScriptSerializer { MaxJsonLength = 262144, RecursionLimit = 20 };
                try
                {
                    scope = new ManagementScope(@"root\cimv2");
                    scope.Connect();
                }
                catch (Exception error)
                {
                    native.TagApi(error, LegacyFailureApi.WmiConnect);
                    native.TagFailure(error, LegacyFailureStage.ArgumentConnect);
                    worker.Error = error;
                    cancelled = true;
                }
                finally { worker.Ready.Set(); }
                foreach (var batch in worker.Queue.GetConsumingEnumerable())
                {
                    try
                    {
                        Check();
                        if (worker.Error != null) throw worker.Error;
                        Query(scope, native, json, batch);
                    }
                    catch (Exception error)
                    {
                        native.TagFailure(error, LegacyFailureStage.ArgumentQuery);
                        batch.Error = error;
                        cancelled = true;
                    }
                    finally { batch.Done.Set(); }
                }
            });
            worker.Thread.SetApartmentState(ApartmentState.MTA);
            workers.Add(worker);
            worker.Thread.Start();
        }
        foreach (var worker in workers)
        {
            while (!worker.Ready.Wait(25)) Check();
            if (worker.Error != null) throw worker.Error;
        }
    }

    private void Query(ManagementScope scope, LegacyNative native, JavaScriptSerializer json, LegacyArgumentBatch batch)
    {
        if (batch.Processes.Count < 1 ||
            batch.Processes.Count > 32 ||
            Interlocked.Increment(ref count) > maximum) throw new InvalidOperationException("Argument query bound");
        var clauses = new List<string>();
        var expected = new Dictionary<int, Held>();
        foreach (var process in batch.Processes)
        {
            expected.Add(process.Info.pid, process);
            clauses.Add("ProcessId=" + process.Info.pid.ToString(CultureInfo.InvariantCulture));
        }
        var seen = new HashSet<int>();
        var options = new EnumerationOptions { Timeout = TimeSpan.FromSeconds(2), ReturnImmediately = false };
        using (var search = new ManagementObjectSearcher(scope, new ObjectQuery(
            "SELECT ProcessId,CreationDate,CommandLine FROM Win32_Process WHERE " + string.Join(" OR ", clauses)), options))
        using (var rows = QueryRows(search, native))
        {
            foreach (ManagementObject row in rows)
            using (row)
            {
                Check();
                int id = Convert.ToInt32(row["ProcessId"], CultureInfo.InvariantCulture);
                Held process;
                if (!expected.TryGetValue(id, out process) ||
                    !seen.Add(id)) throw new InvalidOperationException("Process query changed");
                try
                {
                    var command = row["CommandLine"] as string;
                    var date = row["CreationDate"] as string;
                    if (string.IsNullOrEmpty(command) ||
                        command.Length > 32768 ||
                        string.IsNullOrEmpty(date)) throw new InvalidOperationException("Process query unavailable");
                    long queried = ManagementDateTimeConverter.ToDateTime(date).ToUniversalTime().ToFileTimeUtc();
                    if (!native.Alive(process.Handle) ||
                        native.Creation(process.Handle) != process.Created ||
                        Math.Abs(queried - process.Created) > 10 ||
                        native.Parent(process.Handle) != process.Info.parentPid ||
                        native.Owner(process.Handle) != process.Info.ownerSid ||
                        !string.Equals(native.Image(process.Handle), process.Info.imagePath, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Process query generation changed");
                    int argumentCount;
                    var pointer = Api.CommandLineToArgvW(command, out argumentCount);
                    native.Require(pointer != IntPtr.Zero, LegacyFailureApi.CommandLineToArgv);
                    try
                    {
                        if (argumentCount < 1 ||
                            argumentCount > 1024) throw new InvalidOperationException("Argument bounds");
                        var arguments = new string[argumentCount];
                        for (int index = 0; index < argumentCount; index++)
                            arguments[index] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, index * IntPtr.Size));
                        var digest = native.Hash(Encoding.UTF8.GetBytes(json.Serialize(arguments)));
                        if (!batch.Capture &&
                            digest != process.Info.argvSha256) throw new InvalidOperationException("Arguments changed");
                        batch.Results.Add(new LegacyArgumentResult { Process = process, Digest = digest,
                            Arguments = batch.Capture && process.KeepArguments ? arguments : null });
                    }
                    finally { Api.LocalFree(pointer); }
                }
                catch (Exception error)
                {
                    native.TagFailure(error, LegacyFailureStage.ArgumentIdentity, process.Info.pid,
                        process.Created, process.Info.parentPid, ownerMatched: true);
                    throw;
                }
            }
        }
        if (seen.Count != expected.Count) throw new InvalidOperationException("Process query changed");
        Check();
    }

    private ManagementObjectCollection QueryRows(ManagementObjectSearcher search, LegacyNative native)
    {
        try { return search.Get(); }
        catch (Exception error)
        {
            native.TagApi(error, LegacyFailureApi.WmiQuery);
            native.TagFailure(error, LegacyFailureStage.ArgumentQuery);
            throw;
        }
    }

    private void Check()
    {
        if (cancelled) throw new InvalidOperationException("Argument query cancelled");
        check();
    }

    public void Dispose()
    {
        if (disposed) return;
        cancelled = true;
        foreach (var worker in workers) worker.Queue.CompleteAdding();
        foreach (var worker in workers) worker.Thread.Join();
        foreach (var worker in workers) { worker.Queue.Dispose(); worker.Ready.Dispose(); }
        disposed = true;
    }
}

internal sealed class LegacyQueryWorker
{
    internal Thread Thread;
    internal Exception Error;
    internal ManualResetEventSlim Ready = new ManualResetEventSlim(false);
    internal BlockingCollection<LegacyArgumentBatch> Queue = new BlockingCollection<LegacyArgumentBatch>(1);
}

internal sealed class LegacyArgumentBatch
{
    internal List<Held> Processes;
    internal bool Capture;
    internal Exception Error;
    internal ManualResetEventSlim Done = new ManualResetEventSlim(false);
    internal List<LegacyArgumentResult> Results = new List<LegacyArgumentResult>();
}

internal sealed class LegacyArgumentResult
{
    internal Held Process;
    internal string Digest;
    internal string[] Arguments;
}

internal static class Api
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct MemoryCounters
    {
        internal uint Size, PageFaultCount;
        internal UIntPtr PeakWorkingSet, WorkingSet, PeakPagedPool, PagedPool, PeakNonpagedPool, NonpagedPool;
        internal UIntPtr PagefileUsage, PeakPagefileUsage, PrivateUsage;
    }
    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessMemoryInfo(IntPtr process, out MemoryCounters counters, uint size);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ProcessEntryLayout
    {
        internal uint Size, Usage, ProcessId;
        internal UIntPtr HeapId;
        internal uint ModuleId, Threads, ParentId;
        internal int Priority;
        internal uint Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260, ArraySubType = UnmanagedType.U2)]
        internal ushort[] IgnoredName;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime { internal uint Low, High; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileInformation
    {
        internal uint Attributes;
        internal FileTime Creation, Access, Write;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeSnapshot CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32FirstW(SafeSnapshot snapshot, IntPtr entry);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32NextW(SafeSnapshot snapshot, IntPtr entry);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicInformation
    {
        internal IntPtr Reserved1, Peb, Reserved2, Reserved3, ProcessId, ParentId;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeProcess OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int id);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(SafeProcess handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessTimes(SafeProcess process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(SafeProcess process, uint flags, StringBuilder name, ref int size);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(SafeProcess process, uint access, out SafeProcess token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(SafeProcess token, int kind, IntPtr info, int size, out int returned);
    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(SafeProcess process, int kind, out BasicInformation info, int size, out int returned);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int kind, uint reserved);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(SafeProcess process, uint code);
}
