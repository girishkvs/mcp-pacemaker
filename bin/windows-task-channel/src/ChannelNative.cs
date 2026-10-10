using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal sealed class ChannelNative
{
    internal void Require(bool result)
    {
        if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    internal ProcessHandle Open(int pid)
    {
        var handle = ChannelApi.OpenProcess(0x101000, false, pid);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return handle;
    }

    internal bool Alive(ProcessHandle handle)
    {
        uint result = ChannelApi.WaitForSingleObject(handle, 0);
        if (result == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
        return result == 0x102;
    }

    internal long Birth(ProcessHandle handle)
    {
        long created, exited, kernel, user;
        Require(ChannelApi.GetProcessTimes(handle, out created, out exited, out kernel, out user));
        return created;
    }

    internal string Image(ProcessHandle handle)
    {
        var name = new StringBuilder(32768);
        int length = name.Capacity;
        Require(ChannelApi.QueryFullProcessImageNameW(handle, 0, name, ref length));
        return name.ToString();
    }

    internal ProcessHandle Token(ProcessHandle process)
    {
        ProcessHandle token;
        Require(ChannelApi.OpenProcessToken(process, 8, out token));
        return token;
    }

    internal T Information<T>(ProcessHandle token, int kind, Func<IntPtr, int, T> read)
    {
        int length;
        ChannelApi.GetTokenInformation(token, kind, IntPtr.Zero, 0, out length);
        if (length < 1 ||
            length > 65536) throw new InvalidOperationException("TOKEN_BOUNDS_" + kind.ToString(CultureInfo.InvariantCulture) +
                "_ERROR_" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
        var memory = Marshal.AllocHGlobal(length);
        try
        {
            int returned;
            Require(ChannelApi.GetTokenInformation(token, kind, memory, length, out returned));
            if (returned > length) throw new InvalidOperationException("TOKEN_CHANGED");
            return read(memory, returned);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    internal string Sid(ProcessHandle token)
    {
        return Information(token, 1, (memory, length) =>
            new SecurityIdentifier(Marshal.ReadIntPtr(memory)).Value);
    }

    internal int Number(ProcessHandle token, int kind)
    {
        return Information(token, kind, (memory, length) =>
        {
            if (length == 1) return (int)Marshal.ReadByte(memory);
            if (length != 4) throw new InvalidOperationException("TOKEN_SCALAR_BOUNDS");
            return Marshal.ReadInt32(memory);
        });
    }

    internal ActorFacts Facts(ProcessHandle process, bool observeThreads, Action checkpoint)
    {
        using (var token = Token(process))
        {
            var threads = "unverified";
            if (observeThreads)
            {
                var observation = ObserveThreads(process, checkpoint);
                if (observation.impersonating) throw new InvalidOperationException("PARENT_THREAD_IMPERSONATING");
                threads = "observed-none";
            }
            bool enabledAdmin = Information(token, 2, (memory, length) =>
            {
                int count = Marshal.ReadInt32(memory);
                int offset = IntPtr.Size == 8 ? 8 : 4;
                int stride = IntPtr.Size == 8 ? 16 : 8;
                if (count < 0 ||
                    count > (length - offset) / stride) throw new InvalidOperationException("TOKEN_GROUP_BOUNDS");
                for (int index = 0; index < count; index++)
                {
                    var row = IntPtr.Add(memory, offset + index * stride);
                    var sid = new SecurityIdentifier(Marshal.ReadIntPtr(row)).Value;
                    int flags = Marshal.ReadInt32(row, IntPtr.Size);
                    if (sid == "S-1-5-32-544")
                        return (flags & 4) != 0 && (flags & 16) == 0;
                }
                return false;
            });
            return new ActorFacts
            {
                ownerSid = Sid(token), sessionId = Number(token, 12),
                elevated = Number(token, 20) != 0, enabledAdministrator = enabledAdmin,
                restricted = ChannelApi.IsTokenRestricted(token) || Number(token, 21) != 0,
                appContainer = Number(token, 29) != 0,
                parentThreadImpersonation = threads,
                parentThreadQueryError = observeThreads ? null : "NOT_OBSERVED_READ_ONLY_ROLE",
                guardThreadImpersonating = ThreadImpersonating(),
                observedAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)
            };
        }
    }

    private long FileTimeValue(ContextApi.FileTime value)
    {
        return ((long)value.high << 32) | value.low;
    }

    internal List<ContextApi.ThreadEntry> CaptureThreads(ProcessHandle parent, Action checkpoint, out long began)
    {
        checkpoint();
        int entrySize = Marshal.SizeOf(typeof(ContextApi.ThreadEntry));
        if ((IntPtr.Size != 4 && IntPtr.Size != 8) ||
            entrySize != (IntPtr.Size == 8 ? 120 : 92))
            throw new ContextObservationException("THREAD_SNAPSHOT_LAYOUT_UNSUPPORTED");
        ContextApi.GetSystemTimePreciseAsFileTime(out began);
        IntPtr snapshot;
        uint status = ContextApi.PssCaptureSnapshot(parent, 0x80, 0, out snapshot);
        if (status != 0) throw new ContextObservationException("THREAD_SNAPSHOT_FAILED_" + status.ToString(CultureInfo.InvariantCulture));
        try
        {
            var information = new ContextApi.ThreadInformation();
            status = ContextApi.PssQuerySnapshot(snapshot, 5, out information, (uint)Marshal.SizeOf(information));
            RequireSnapshotStatus(status);
            if (information.count < 1 ||
                information.count > 128) throw new ContextObservationException("THREAD_SNAPSHOT_BOUNDS");
            IntPtr marker;
            RequireSnapshotStatus(ContextApi.PssWalkMarkerCreate(IntPtr.Zero, out marker));
            try
            {
                var entries = new List<ContextApi.ThreadEntry>();
                while (true)
                {
                    checkpoint();
                    var entry = new ContextApi.ThreadEntry();
                    status = ContextApi.PssWalkSnapshot(snapshot, 3, marker, out entry, (uint)entrySize);
                    if (status == 259) break;
                    RequireSnapshotStatus(status);
                    if (entry.threadId == 0 ||
                        entries.Any(previous => previous.threadId == entry.threadId) ||
                        entries.Count >= 128) throw new ContextObservationException("THREAD_SNAPSHOT_INCOMPLETE");
                    entries.Add(entry);
                }
                if (entries.Count != information.count) throw new ContextObservationException("THREAD_SNAPSHOT_COUNT_CHANGED");
                entries.Sort((first, second) => first.threadId.CompareTo(second.threadId));
                return entries;
            }
            finally { RequireSnapshotStatus(ContextApi.PssWalkMarkerFree(marker)); }
        }
        finally { RequireSnapshotStatus(ContextApi.PssFreeSnapshot(ContextApi.GetCurrentProcess(), snapshot)); }
    }

    private void RequireSnapshotStatus(uint status)
    {
        if (status != 0) throw new ContextObservationException("THREAD_SNAPSHOT_FAILED_" + status.ToString(CultureInfo.InvariantCulture));
    }

    private bool ValidateThread(ContextApi.ThreadEntry entry, ProcessHandle thread, int pid,
        long parentBirth, long began)
    {
        long birth = FileTimeValue(entry.creation);
        long exit = FileTimeValue(entry.exit);
        bool terminated = entry.flags == 1;
        bool validTimes = terminated
            ? parentBirth <= birth && birth < exit && exit < began
            : parentBirth <= birth && birth <= began && exit == 0;
        if ((entry.flags & ~1u) != 0 ||
            !validTimes) throw new ContextObservationException("THREAD_SNAPSHOT_METADATA_INVALID");
        if (entry.processId != pid ||
            ChannelApi.GetProcessIdOfThread(thread) != pid)
            throw new ContextObservationException("THREAD_IDENTITY_CHANGED");
        long heldBirth, heldExit, kernel, user;
        Require(ChannelApi.GetThreadTimes(thread, out heldBirth, out heldExit, out kernel, out user));
        if (heldBirth != birth ||
            heldExit != exit) throw new ContextObservationException("HELD_THREAD_CHANGED_OR_EXITED");
        uint wait = ChannelApi.WaitForSingleObject(thread, 0);
        if (wait == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (wait != (terminated ? 0u : 0x102u))
            throw new ContextObservationException("THREAD_LIVENESS_CHANGED");
        return terminated;
    }

    private bool SameThread(ContextApi.ThreadEntry first, ContextApi.ThreadEntry second)
    {
        return first.threadId == second.threadId &&
            first.processId == second.processId &&
            first.flags == second.flags &&
            FileTimeValue(first.creation) == FileTimeValue(second.creation) &&
            FileTimeValue(first.exit) == FileTimeValue(second.exit);
    }

    internal ThreadObservation ObserveThreads(ProcessHandle process, Action checkpoint)
    {
        int pid = checked((int)ChannelApi.GetProcessId(process));
        if (pid <= 0) throw new InvalidOperationException("PARENT_PID_UNAVAILABLE");
        long began;
        var before = CaptureThreads(process, checkpoint, out began);
        var held = new List<ProcessHandle>();
        bool impersonating = false;
        int liveCount = 0;
        try
        {
            long parentBirth = Birth(process);
            foreach (var entry in before)
            {
                checkpoint();
                var thread = ContextApi.OpenThread(0x100040, false, entry.threadId);
                held.Add(thread);
                Require(!thread.IsInvalid);
                if (!ValidateThread(entry, thread, pid, parentBirth, began))
                {
                    liveCount++;
                    impersonating |= HasThreadToken(thread);
                }
            }
            if (liveCount == 0) throw new ContextObservationException("LIVE_THREAD_SET_EMPTY");
            long secondBegan;
            var after = CaptureThreads(process, checkpoint, out secondBegan);
            if (!before.Select(entry => entry.threadId).SequenceEqual(after.Select(entry => entry.threadId)) ||
                !Alive(process)) throw new ContextObservationException("THREAD_SET_CHANGED");
            for (int index = 0; index < held.Count; index++)
            {
                checkpoint();
                if (!SameThread(before[index], after[index]))
                    throw new ContextObservationException("HELD_THREAD_CHANGED_OR_EXITED");
                var thread = held[index];
                if (!ValidateThread(after[index], thread, pid, parentBirth, began))
                    impersonating |= HasThreadToken(thread);
            }
            return new ThreadObservation { count = before.Count, impersonating = impersonating };
        }
        finally { foreach (var thread in held) thread.Dispose(); }
    }

    internal bool HasThreadToken(ProcessHandle thread)
    {
        ProcessHandle token;
        bool opened = ChannelApi.OpenHeldThreadToken(thread, 8, true, out token);
        int error = Marshal.GetLastWin32Error();
        if (token != null) token.Dispose();
        if (opened) return true;
        if (error != 1008) throw new Win32Exception(error);
        return false;
    }

    internal bool ThreadImpersonating()
    {
        ProcessHandle token;
        bool opened = ChannelApi.OpenThreadToken(ChannelApi.GetCurrentThread(), 8, true, out token);
        int error = Marshal.GetLastWin32Error();
        if (opened)
        {
            token.Dispose();
            return true;
        }
        if (token != null) token.Dispose();
        if (error != 1008) throw new Win32Exception(error);
        return false;
    }

    internal Identity Identity(int pid, ProcessHandle handle)
    {
        using (var token = Token(handle))
        {
            return new Identity
            {
                pid = pid, creationTime = Birth(handle).ToString(CultureInfo.InvariantCulture),
                ownerSid = Sid(token), sessionId = Number(token, 12), imagePath = Image(handle)
            };
        }
    }

    internal ManagementObject ProcessRow(int pid, ProcessHandle held)
    {
        var options = new EnumerationOptions { Timeout = TimeSpan.FromSeconds(2), ReturnImmediately = false };
        using (var search = new ManagementObjectSearcher(@"root\cimv2",
            "SELECT ProcessId,ParentProcessId,CreationDate,CommandLine FROM Win32_Process WHERE ProcessId = " +
                pid.ToString(CultureInfo.InvariantCulture), options))
        using (var rows = search.Get())
        {
            if (rows.Count != 1) throw new InvalidOperationException("PROCESS_ROW_MISSING");
            foreach (ManagementObject row in rows)
            {
                var date = row["CreationDate"] as string;
                if (date == null) throw new InvalidOperationException("PROCESS_DATE_MISSING");
                long creation = ManagementDateTimeConverter.ToDateTime(date).ToUniversalTime().ToFileTimeUtc();
                if (Math.Abs(creation - Birth(held)) > 10 ||
                    !Alive(held)) throw new InvalidOperationException("PROCESS_GENERATION_CHANGED");
                return row;
            }
        }
        throw new InvalidOperationException("PROCESS_ROW_MISSING");
    }

    internal int Parent(int self, ProcessHandle held)
    {
        using (var row = ProcessRow(self, held)) return Convert.ToInt32(row["ParentProcessId"], CultureInfo.InvariantCulture);
    }

    internal string[] Arguments(int pid, ProcessHandle held)
    {
        using (var row = ProcessRow(pid, held))
        {
            var command = row["CommandLine"] as string;
            if (string.IsNullOrEmpty(command) ||
                command.Length > 32768) throw new InvalidOperationException("ARGV_UNAVAILABLE");
            int count;
            var memory = ChannelApi.CommandLineToArgvW(command, out count);
            Require(memory != IntPtr.Zero);
            try
            {
                if (count < 1 ||
                    count > 128) throw new InvalidOperationException("ARGV_BOUNDS");
                var arguments = new string[count];
                for (int index = 0; index < count; index++)
                    arguments[index] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory, index * IntPtr.Size));
                return arguments;
            }
            finally { ChannelApi.LocalFree(memory); }
        }
    }
}

internal sealed class ThreadObservation
{
    internal int count;
    internal bool impersonating;
}

internal sealed class ProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public ProcessHandle() : base(true) { }
    protected override bool ReleaseHandle() { return ChannelApi.CloseHandle(handle); }
}

internal sealed class Identity
{
    public int pid { get; set; }
    public string creationTime { get; set; }
    public string ownerSid { get; set; }
    public int sessionId { get; set; }
    public string imagePath { get; set; }
    public string imageSha256 { get; set; }
    public string argvSha256 { get; set; }
}

internal sealed class ActorFacts
{
    public string ownerSid { get; set; }
    public int sessionId { get; set; }
    public bool elevated { get; set; }
    public bool enabledAdministrator { get; set; }
    public bool restricted { get; set; }
    public bool appContainer { get; set; }
    public bool guardThreadImpersonating { get; set; }
    public string parentThreadImpersonation { get; set; }
    public string parentThreadQueryError { get; set; }
    public string observedAt { get; set; }
}

internal static class ChannelApi
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        internal int length;
        internal IntPtr descriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool inherit;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern ProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(ProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetProcessId(ProcessHandle process);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern ProcessHandle OpenThread(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetProcessIdOfThread(ProcessHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetThreadTimes(ProcessHandle thread, out long birth, out long exit, out long kernel, out long user);
    [DllImport("advapi32.dll", EntryPoint = "OpenThreadToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenHeldThreadToken(ProcessHandle thread, uint access,
        [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out ProcessHandle token);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessTimes(ProcessHandle handle, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(ProcessHandle handle, int flags, StringBuilder name, ref int length);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(ProcessHandle process, uint access, out ProcessHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(ProcessHandle token, int kind, IntPtr memory, int length, out int returned);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsTokenRestricted(ProcessHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenThreadToken(IntPtr thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out ProcessHandle token);
    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentThread();
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode,
        int instances, int outputSize, int inputSize, int timeout, ref SecurityAttributes security);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientSessionId(SafePipeHandle pipe, out uint session);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PeekNamedPipe(SafePipeHandle pipe, IntPtr buffer, uint length,
        IntPtr bytesRead, out uint available, IntPtr bytesLeft);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateDirectoryW(string path, ref SecurityAttributes security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder name, int length, int flags);
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileInformation
    {
        internal uint attributes;
        internal uint creationLow, creationHigh, accessLow, accessHigh, writeLow, writeHigh;
        internal uint volume, sizeHigh, sizeLow, links, indexHigh, indexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
}
