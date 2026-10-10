using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal sealed class ProcessLifetimeHelper
{
    private string stage = "arguments";

    private static int Main(string[] args)
    {
        var helper = new ProcessLifetimeHelper();
        if (args.Length > 0 &&
            args[0] == "observe-owner")
        {
            return helper.ObserveOwner(args);
        }

        return helper.Run(args);
    }

    private int Run(string[] args)
    {
        SafeNativeHandle parent = null;
        SafeNativeHandle job = null;
        SafeNativeHandle drainMarker = null;
        try
        {
            int expectedParent = 0;
            bool validRequest = args.Length == 2 &&
                args[0] == "watch-parent" &&
                int.TryParse(args[1], out expectedParent);
            if (!validRequest)
            {
                throw new ArgumentException();
            }

            stage = "parent";
            var current = new IntPtr(-1);
            int parentId = GetParentId();
            if (parentId != expectedParent)
            {
                throw new ArgumentException();
            }
            // A held process handle, not a later PID lookup, owns the lifetime.
            parent = Native.OpenProcess(0x00100000 | 0x1000 | 0x0100 | 0x0001, false, parentId);
            Require(!parent.IsInvalid);
            long parentCreated;
            long selfCreated;
            long unusedExit;
            long unusedKernel;
            long unusedUser;
            Require(Native.GetProcessTimes(parent.DangerousGetHandle(), out parentCreated,
                out unusedExit, out unusedKernel, out unusedUser));
            Require(Native.GetProcessTimes(current, out selfCreated,
                out unusedExit, out unusedKernel, out unusedUser));
            if (parentCreated > selfCreated ||
                Native.WaitForSingleObject(parent, 0) != 0x00000102)
            {
                throw new InvalidOperationException();
            }

            stage = "create-drain-marker";
            Native.SetLastError(0);
            drainMarker = Native.CreateEventW(IntPtr.Zero, true, false,
                DrainEventName(Native.GetCurrentProcessId(), selfCreated));
            int creationError = Marshal.GetLastWin32Error();
            Require(!drainMarker.IsInvalid);
            if (creationError == 183)
            {
                throw new InvalidOperationException();
            }

            stage = "create-job";
            // NULL security attributes make the unnamed job handle non-inheritable.
            // This helper was born before assignment and remains outside this job.
            job = Native.CreateJobObjectW(IntPtr.Zero, null);
            Require(!job.IsInvalid);
            var limits = new Native.ExtendedLimitInformation();
            limits.Basic.LimitFlags = 0x00002000; // KILL_ON_JOB_CLOSE, no breakaway flags.
            Require(Native.SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(limits)));

            stage = "assign";
            Require(Native.AssignProcessToJobObject(job, parent));
            bool member;
            Require(Native.IsProcessInJob(parent, job, out member));
            if (!member)
            {
                throw new InvalidOperationException();
            }

            // The bridge awaits this line before reading config or spawning any work.
            // All subsequent children inherit membership atomically in CreateProcess.
            stage = "ready";
            Console.Out.WriteLine("MCP_JOB_READY " + Native.GetCurrentProcessId() + " " +
                selfCreated.ToString(CultureInfo.InvariantCulture));
            Console.Out.Flush();
            stage = "wait";
            if (Native.WaitForSingleObject(parent, 0xffffffff) != 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            stage = "drain";
            Require(Native.TerminateJobObject(job, 1));
            var deadline = Stopwatch.StartNew();
            while (true)
            {
                var accounting = new Native.BasicAccountingInformation();
                int returned;
                Require(Native.QueryInformationJobObject(job, 1, out accounting,
                    Marshal.SizeOf(accounting), out returned));
                if (accounting.ActiveProcesses == 0)
                {
                    break;
                }

                if (deadline.ElapsedMilliseconds >= 5000)
                {
                    throw new TimeoutException();
                }

                Thread.Sleep(10);
            }

            stage = "mark-drained";
            Require(Native.SetEvent(drainMarker));
            return 0;
        }
        catch (Exception error)
        {
            var native = error as Win32Exception;
            Console.Error.WriteLine("MCP_JOB_ERROR stage=" + stage +
                " type=" + error.GetType().Name +
                (native == null ? "" : " nativeError=" + native.NativeErrorCode));
            return 1;
        }
        finally
        {
            // Closing the only job handle terminates remaining members even when
            // Node could not run its cleanup. Helper failure is also fail-closed.
            if (job != null)
            {
                job.Dispose();
            }

            if (drainMarker != null)
            {
                drainMarker.Dispose();
            }

            if (parent != null)
            {
                parent.Dispose();
            }
        }
    }

    private int ObserveOwner(string[] args)
    {
        SafeNativeHandle owner = null;
        SafeNativeHandle parent = null;
        SafeNativeHandle drainMarker = null;
        try
        {
            int ownerId = 0;
            long expectedCreated = 0;
            bool validRequest = args.Length == 3 &&
                int.TryParse(args[1], out ownerId) &&
                long.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out expectedCreated) &&
                ownerId > 0 &&
                expectedCreated > 0;
            if (!validRequest)
            {
                throw new ArgumentException();
            }

            stage = "observe-parent";
            parent = Native.OpenProcess(0x00100000 | 0x1000, false, GetParentId());
            Require(!parent.IsInvalid);
            long selfCreated = GetCreationTime(new IntPtr(-1));
            if (GetCreationTime(parent.DangerousGetHandle()) > selfCreated ||
                Native.WaitForSingleObject(parent, 0) != 0x00000102)
            {
                throw new InvalidOperationException();
            }

            stage = "observe-owner";
            owner = Native.OpenProcess(0x00100000 | 0x1000, false, ownerId);
            Require(!owner.IsInvalid);
            if (GetCreationTime(owner.DangerousGetHandle()) != expectedCreated ||
                !string.Equals(GetImage(owner.DangerousGetHandle()), GetImage(new IntPtr(-1)),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException();
            }

            stage = "observe-marker";
            drainMarker = Native.OpenEventW(0x00100000, false, DrainEventName((uint)ownerId, expectedCreated));
            Require(!drainMarker.IsInvalid);

            // Both identities and the read-only drain event are held before stop.
            Console.Out.WriteLine("MCP_JOB_OBSERVER_READY");
            Console.Out.Flush();
            var handles = new[] { owner.DangerousGetHandle(), parent.DangerousGetHandle() };
            uint result = Native.WaitForMultipleObjects(2, handles, false, 0xffffffff);
            stage = "observe-exit";
            if (result != 0)
            {
                throw new InvalidOperationException();
            }

            uint code;
            Require(Native.GetExitCodeProcess(owner, out code));
            if (code != 0)
            {
                throw new Win32Exception(unchecked((int)code));
            }

            stage = "verify-drain";
            uint drainState = Native.WaitForSingleObject(drainMarker, 0);
            if (drainState == 0xffffffff)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (drainState != 0)
            {
                throw new Win32Exception(unchecked((int)drainState));
            }

            // Exit zero alone is not proof: even TerminateProcess(..., 0) must
            // not pass without the event set after actual zero job accounting.
            Console.Out.WriteLine("MCP_JOB_DRAINED");
            Console.Out.Flush();
            return 0;
        }
        catch (Exception error)
        {
            var native = error as Win32Exception;
            Console.Error.WriteLine("MCP_JOB_ERROR stage=" + stage +
                " type=" + error.GetType().Name +
                (native == null ? "" : " nativeError=" + native.NativeErrorCode));
            return 1;
        }
        finally
        {
            if (drainMarker != null)
            {
                drainMarker.Dispose();
            }

            if (owner != null)
            {
                owner.Dispose();
            }

            if (parent != null)
            {
                parent.Dispose();
            }
        }
    }

    private int GetParentId()
    {
        var basic = new Native.ProcessBasicInformation();
        int returned;
        int status = Native.NtQueryInformationProcess(
            new IntPtr(-1), 0, out basic, Marshal.SizeOf(basic), out returned);
        if (status != 0)
        {
            throw new Win32Exception(status);
        }

        return checked((int)basic.ParentId.ToInt64());
    }

    private long GetCreationTime(IntPtr process)
    {
        long created;
        long exit;
        long kernel;
        long user;
        Require(Native.GetProcessTimes(process, out created, out exit, out kernel, out user));
        return created;
    }

    private string GetImage(IntPtr process)
    {
        var name = new StringBuilder(32768);
        int length = name.Capacity;
        Require(Native.QueryFullProcessImageNameW(process, 0, name, ref length));
        return name.ToString();
    }

    private string DrainEventName(uint processId, long creation)
    {
        return "Local\\mcp-pacemaker-drained-v1-" +
            processId.ToString(CultureInfo.InvariantCulture) + "-" +
            creation.ToString(CultureInfo.InvariantCulture);
    }

    private void Require(bool succeeded)
    {
        if (!succeeded)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}

internal sealed class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeNativeHandle() : base(true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return Native.CloseHandle(handle);
    }
}

internal static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessBasicInformation
    {
        internal IntPtr Reserved1;
        internal IntPtr Peb;
        internal IntPtr Reserved2;
        internal IntPtr Reserved3;
        internal IntPtr ProcessId;
        internal IntPtr ParentId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicLimitInformation
    {
        internal long ProcessTime;
        internal long JobTime;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSet;
        internal UIntPtr MaximumWorkingSet;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        internal ulong ReadOperations;
        internal ulong WriteOperations;
        internal ulong OtherOperations;
        internal ulong ReadBytes;
        internal ulong WriteBytes;
        internal ulong OtherBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtendedLimitInformation
    {
        internal BasicLimitInformation Basic;
        internal IoCounters Io;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemory;
        internal UIntPtr PeakJobMemory;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicAccountingInformation
    {
        internal long UserTime;
        internal long KernelTime;
        internal long PeriodUserTime;
        internal long PeriodKernelTime;
        internal uint PageFaults;
        internal uint TotalProcesses;
        internal uint ActiveProcesses;
        internal uint TerminatedProcesses;
    }

    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(IntPtr process, int informationClass,
        out ProcessBasicInformation information, int length, out int returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeNativeHandle OpenProcess(uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessTimes(IntPtr process, out long creation,
        out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeNativeHandle CreateJobObjectW(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(SafeNativeHandle job, int informationClass,
        ref ExtendedLimitInformation information, int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(SafeNativeHandle job, SafeNativeHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsProcessInJob(SafeNativeHandle process, SafeNativeHandle job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(SafeNativeHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForMultipleObjects(uint count, IntPtr[] handles,
        [MarshalAs(UnmanagedType.Bool)] bool waitAll, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(SafeNativeHandle process, out uint code);

    [DllImport("kernel32.dll")]
    internal static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags,
        StringBuilder name, ref int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(SafeNativeHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(SafeNativeHandle job, int informationClass,
        out BasicAccountingInformation information, int length, out int returned);

    [DllImport("kernel32.dll")]
    internal static extern void SetLastError(uint code);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeNativeHandle CreateEventW(IntPtr attributes,
        [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState, string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeNativeHandle OpenEventW(uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetEvent(SafeNativeHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
}
