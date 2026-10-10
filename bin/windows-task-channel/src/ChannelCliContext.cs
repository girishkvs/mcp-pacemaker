using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;

internal sealed class ChannelCliContext
{
    private readonly ChannelNative native;
    private readonly Action checkpoint;

    internal ChannelCliContext(ChannelNative nativeApi, Action check)
    {
        native = nativeApi;
        checkpoint = check;
    }

    internal int Parent(ProcessHandle self, int selfPid)
    {
        uint pipeOwner;
        if (!ContextApi.GetNamedPipeServerProcessId(ContextApi.GetStdHandle(-10), out pipeOwner))
            throw new ContextObservationException("CLI_PARENT_PIPE_UNVERIFIED");
        var information = new ContextApi.BasicInformation();
        int size = Marshal.SizeOf(information);
        int returned;
        int status = ContextApi.NtQueryInformationProcess(self, 0, out information, size, out returned);
        bool valid = (IntPtr.Size == 4 || IntPtr.Size == 8) &&
            size == 6 * IntPtr.Size &&
            status == 0 &&
            returned == size &&
            information.processId.ToInt64() == selfPid &&
            information.parentReserved.ToInt64() == pipeOwner &&
            pipeOwner > 0 &&
            pipeOwner <= int.MaxValue &&
            pipeOwner != selfPid;
        if (!valid) throw new ContextObservationException("CLI_PARENT_LAYOUT_OR_BINDING_UNVERIFIED");
        return checked((int)pipeOwner);
    }

    internal ProcessHandle OpenParent(int pid)
    {
        var handle = ChannelApi.OpenProcess(0x101400, false, pid);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new ContextObservationException("CLI_PARENT_QUERY_ACCESS_DENIED");
        }
        return handle;
    }

    internal ContextResult Observe(ProcessHandle parent, Identity identity)
    {
        var result = new ContextResult
        {
            proofScope = "cli-effective-context-snapshot",
            reason = "CONTEXT_UNVERIFIED",
            observation = new ContextObservation
            {
                method = "pss-threads-held-token-query", processAccess = "0x101400",
                captureFlags = "0x80", threadContextFlags = 0, atomicFutureProtection = false
            }
        };
        try
        {
            checkpoint();
            var firstFacts = native.Facts(parent, false, checkpoint);
            result.actorFacts = firstFacts;
            if (firstFacts.ownerSid != identity.ownerSid ||
                firstFacts.sessionId != identity.sessionId) throw new ContextObservationException("PRIMARY_TOKEN_CHANGED");
            if (firstFacts.elevated ||
                firstFacts.enabledAdministrator) throw new ContextObservationException("PRIMARY_CONTEXT_PRIVILEGED");
            if (firstFacts.guardThreadImpersonating) throw new ContextObservationException("GUARD_THREAD_IMPERSONATING");
            var threads = native.ObserveThreads(parent, checkpoint);
            result.observation.threadCount = threads.count;
            if (threads.impersonating) throw new ContextObservationException("THREAD_TOKEN_OBSERVED");
            var finalFacts = native.Facts(parent, false, checkpoint);
            result.actorFacts = finalFacts;
            result.observation.primaryStable = SamePrimary(firstFacts, finalFacts);
            result.observation.completeStableThreadSet = true;
            if (!result.observation.primaryStable) throw new ContextObservationException("PRIMARY_TOKEN_CHANGED");
            finalFacts.parentThreadImpersonation = "observed-none";
            finalFacts.parentThreadQueryError = null;
            result.ordinaryEligible = Eligible(finalFacts, result.observation);
            result.reason = result.ordinaryEligible ? "OBSERVED_NON_ELEVATED_NO_IMPERSONATION" : "CONTEXT_NOT_ORDINARY";
        }
        catch (ContextObservationException error)
        {
            result.reason = error.Message;
            if (result.actorFacts != null)
            {
                result.actorFacts.parentThreadImpersonation = error.Message == "THREAD_TOKEN_OBSERVED"
                    ? "observed-impersonating" : "unverified";
                result.actorFacts.parentThreadQueryError = error.Message;
            }
        }
        catch (Win32Exception error)
        {
            result.reason = "CONTEXT_QUERY_FAILED_" + error.NativeErrorCode.ToString(CultureInfo.InvariantCulture);
        }
        catch (EntryPointNotFoundException) { result.reason = "CONTEXT_API_UNSUPPORTED"; }
        catch (DllNotFoundException) { result.reason = "CONTEXT_API_UNAVAILABLE"; }
        checkpoint();
        result.observation.observedAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        return result;
    }

    internal bool Eligible(ActorFacts facts, ContextObservation observation)
    {
        return facts != null &&
            observation != null &&
            !facts.elevated &&
            !facts.enabledAdministrator &&
            !facts.guardThreadImpersonating &&
            facts.parentThreadImpersonation == "observed-none" &&
            observation.completeStableThreadSet &&
            observation.primaryStable &&
            observation.threadCount > 0 &&
            observation.threadCount <= 128 &&
            !observation.atomicFutureProtection;
    }

    private bool SamePrimary(ActorFacts first, ActorFacts second)
    {
        return first.ownerSid == second.ownerSid &&
            first.sessionId == second.sessionId &&
            first.elevated == second.elevated &&
            first.enabledAdministrator == second.enabledAdministrator &&
            first.restricted == second.restricted &&
            first.appContainer == second.appContainer &&
            first.guardThreadImpersonating == second.guardThreadImpersonating;
    }

}

internal sealed class ContextObservationException : InvalidOperationException
{
    internal ContextObservationException(string reason) : base(reason) { }
}

internal sealed class ContextResult
{
    public string proofScope { get; set; }
    public bool ordinaryEligible { get; set; }
    public string reason { get; set; }
    public ActorFacts actorFacts { get; set; }
    public ContextObservation observation { get; set; }
}

internal sealed class ContextObservation
{
    public string method { get; set; }
    public string processAccess { get; set; }
    public string captureFlags { get; set; }
    public int threadContextFlags { get; set; }
    public int threadCount { get; set; }
    public bool completeStableThreadSet { get; set; }
    public bool primaryStable { get; set; }
    public bool atomicFutureProtection { get; set; }
    public string observedAt { get; set; }
}

internal static class ContextApi
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicInformation
    {
        internal IntPtr reserved1, peb, reserved2, reserved3, processId, parentReserved;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime { internal uint low, high; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ThreadInformation { internal uint count, contextLength; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ThreadEntry
    {
        internal uint exitStatus;
        internal IntPtr teb;
        internal uint processId, threadId;
        internal UIntPtr affinity;
        internal int priority, basePriority;
        internal IntPtr lastArgument;
        internal ushort syscall;
        internal FileTime creation, exit, kernel, user;
        internal IntPtr start;
        internal FileTime capture;
        internal uint flags;
        internal ushort suspendCount, contextSize;
        internal IntPtr context;
    }
    [DllImport("kernel32.dll")] internal static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(ProcessHandle process, int kind, out BasicInformation info, int length, out int returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern ProcessHandle OpenThread(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint tid);
    [DllImport("kernel32.dll")] internal static extern void GetSystemTimePreciseAsFileTime(out long time);
    [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    internal static extern uint PssCaptureSnapshot(ProcessHandle process, uint flags, uint contextFlags, out IntPtr snapshot);
    [DllImport("kernel32.dll")] internal static extern uint PssFreeSnapshot(IntPtr process, IntPtr snapshot);
    [DllImport("kernel32.dll")]
    internal static extern uint PssQuerySnapshot(IntPtr snapshot, int kind, out ThreadInformation information, uint length);
    [DllImport("kernel32.dll")] internal static extern uint PssWalkMarkerCreate(IntPtr allocator, out IntPtr marker);
    [DllImport("kernel32.dll")] internal static extern uint PssWalkMarkerFree(IntPtr marker);
    [DllImport("kernel32.dll")]
    internal static extern uint PssWalkSnapshot(IntPtr snapshot, int kind, IntPtr marker, out ThreadEntry entry, uint length);
}
