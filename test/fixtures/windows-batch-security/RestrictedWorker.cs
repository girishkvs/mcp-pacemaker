using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public sealed class RestrictedWorker
{
    /// <summary>Runs the audit worker with a medium-integrity restricted token and an owned process-tree deadline.</summary>
    /// <param name="executable">Absolute Node executable path.</param>
    /// <param name="worker">Absolute normal-worker.mjs path.</param>
    /// <param name="directory">Owned audit fixture directory.</param>
    /// <param name="helper">Absolute packaged helper executable path.</param>
    /// <param name="timeoutMilliseconds">Maximum child lifetime.</param>
    /// <returns>The worker's exit code.</returns>
    public uint Run(string executable, string worker, string directory, string helper, uint timeoutMilliseconds)
    {
        foreach (var path in new[] { executable, worker, directory, helper })
        {
            if (!Path.IsPathRooted(path) ||
                path.IndexOf('"') >= 0 ||
                !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Absolute canonical fixture paths required.");
            }
        }

        bool ownedDirectory = new DirectoryInfo(directory).Name.StartsWith(
            "mcp-batch-audit-oracle-", StringComparison.Ordinal);
        bool validInputs = ownedDirectory &&
            Directory.Exists(directory) &&
            Path.GetFileName(worker) == "normal-worker.mjs" &&
            File.Exists(executable) &&
            File.Exists(worker) &&
            File.Exists(helper) &&
            timeoutMilliseconds > 0 &&
            timeoutMilliseconds <= 120000;
        if (!validInputs)
        {
            throw new ArgumentException("Invalid owned audit-worker inputs.");
        }

        SafeAccessTokenHandle original;
        if (!OpenProcessToken(GetCurrentProcess(), 0x8b, out original))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken");
        }

        using (original)
        {
            SafeAccessTokenHandle restricted;
            if (!CreateRestrictedToken(original, 5, 0, IntPtr.Zero, 0, IntPtr.Zero,
                0, IntPtr.Zero, out restricted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken");
            }

            using (restricted)
            using (var identity = WindowsIdentity.GetCurrent())
            {
                if (identity.IsSystem ||
                    identity.IsAnonymous ||
                    identity.IsGuest)
                {
                    throw new InvalidOperationException("A normal caller identity is required.");
                }

                this.SetSid(restricted, 4, identity.User, false);
                this.SetSid(restricted, 5, identity.User, false);
                this.SetSid(restricted, 25, new SecurityIdentifier("S-1-16-8192"), true);
                using (var childIdentity = new WindowsIdentity(restricted.DangerousGetHandle()))
                {
                    if (!identity.User.Equals(childIdentity.User) ||
                        new WindowsPrincipal(childIdentity).IsInRole(WindowsBuiltInRole.Administrator))
                    {
                        throw new InvalidOperationException("Restricted worker identity is not ordinary.");
                    }
                }

                using (var job = CreateJobObject(IntPtr.Zero, null))
                {
                    if (job.IsInvalid)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Create audit-worker job");
                    }

                    var limits = new ExtendedLimitInformation();
                    limits.Basic.LimitFlags = 0x2000;
                    if (!SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(typeof(ExtendedLimitInformation))))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Set audit-worker job limits");
                    }

                    var startup = new StartupInfo();
                    startup.Size = Marshal.SizeOf(typeof(StartupInfo));
                    var command = new StringBuilder(string.Format("\"{0}\" \"{1}\" \"{2}\" \"{3}\"",
                        executable, worker, directory, helper));
                    ProcessInformation child;
                    if (!CreateProcessAsUser(restricted, executable, command, IntPtr.Zero,
                        IntPtr.Zero, false, 0x08000004, IntPtr.Zero, directory, ref startup, out child))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser");
                    }

                    try
                    {
                        // Associate the suspended child before any worker code can start descendants.
                        if (!AssignProcessToJobObject(job, child.Process))
                        {
                            int error = Marshal.GetLastWin32Error();
                            if (!TerminateProcess(child.Process, 99))
                            {
                                throw new Win32Exception(Marshal.GetLastWin32Error(), "Stop unassigned audit worker");
                            }

                            throw new Win32Exception(error, "Assign audit worker to owned job");
                        }

                        if (ResumeThread(child.Thread) == uint.MaxValue)
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "Resume audit worker");
                        }

                        uint wait = WaitForSingleObject(child.Process, timeoutMilliseconds);
                        if (wait == 258)
                        {
                            throw new TimeoutException("Restricted audit worker exceeded its deadline.");
                        }

                        if (wait != 0)
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject");
                        }

                        uint exitCode;
                        if (!GetExitCodeProcess(child.Process, out exitCode))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess");
                        }

                        return exitCode;
                    }
                    finally
                    {
                        try
                        {
                            this.StopOwnedJob(job);
                        }
                        finally
                        {
                            CloseHandle(child.Thread);
                            CloseHandle(child.Process);
                        }
                    }
                }
            }
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle original, uint flags,
        uint disabledCount, IntPtr disabled, uint privilegeCount, IntPtr privileges,
        uint restrictedCount, IntPtr restrictedSids, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        IntPtr information, int length);

    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string application,
        StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inherit,
        uint flags, IntPtr environment, string directory, ref StartupInfo startup,
        out ProcessInformation process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr security, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass,
        ref ExtendedLimitInformation information, int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int informationClass,
        out BasicAccountingInformation information, int length, IntPtr returnedLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private void StopOwnedJob(SafeFileHandle job)
    {
        if (!TerminateJobObject(job, 99))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Terminate owned audit job");
        }

        var watch = Stopwatch.StartNew();
        for (;;)
        {
            BasicAccountingInformation information;
            if (!QueryInformationJobObject(job, 1, out information,
                Marshal.SizeOf(typeof(BasicAccountingInformation)), IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Query owned audit job");
            }

            if (information.ActiveProcesses == 0)
            {
                return;
            }

            if (watch.ElapsedMilliseconds >= 5000)
            {
                throw new TimeoutException("Owned audit descendants did not exit.");
            }

            Thread.Sleep(10);
        }
    }

    private void SetSid(SafeAccessTokenHandle token, int informationClass,
        SecurityIdentifier sid, bool integrity)
    {
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        int header = integrity ? Marshal.SizeOf(typeof(SidAndAttributes)) : IntPtr.Size;
        var buffer = Marshal.AllocHGlobal(header + bytes.Length);
        try
        {
            var sidPointer = IntPtr.Add(buffer, header);
            Marshal.Copy(bytes, 0, sidPointer, bytes.Length);
            if (integrity)
            {
                Marshal.StructureToPtr(new SidAndAttributes { Sid = sidPointer, Attributes = 0x20 }, buffer, false);
            }
            else
            {
                Marshal.WriteIntPtr(buffer, sidPointer);
            }

            if (!SetTokenInformation(token, informationClass, buffer, header + bytes.Length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetTokenInformation " + informationClass);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string Reserved;
        public string Desktop;
        public string Title;
        public uint X;
        public uint Y;
        public uint Width;
        public uint Height;
        public uint ConsoleWidth;
        public uint ConsoleHeight;
        public uint Fill;
        public uint Flags;
        public ushort Show;
        public ushort ReservedLength;
        public IntPtr ReservedPointer;
        public IntPtr Input;
        public IntPtr Output;
        public IntPtr Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long ProcessTime;
        public long JobTime;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSet;
        public UIntPtr MaximumWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperations;
        public ulong WriteOperations;
        public ulong OtherOperations;
        public ulong ReadBytes;
        public ulong WriteBytes;
        public ulong OtherBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        public BasicLimitInformation Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemory;
        public UIntPtr PeakJobMemory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicAccountingInformation
    {
        public long UserTime;
        public long KernelTime;
        public long PeriodUserTime;
        public long PeriodKernelTime;
        public uint PageFaults;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TerminatedProcesses;
    }
}
