using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web.Script.Serialization;

internal sealed class ThreadLifecycleHost
{
    private static int Main(string[] arguments)
    {
        return new ThreadLifecycleHost().Run(arguments);
    }

    private int Run(string[] arguments)
    {
        if (arguments.Length != 4) return 2;
        uint tid = 0;
        var started = new ManualResetEvent(false);
        var release = new ManualResetEvent(false);
        var completed = new ManualResetEvent(false);
        var thread = new Thread(() =>
        {
            tid = GetCurrentThreadId();
            started.Set();
            release.WaitOne(30000);
        });
        thread.Start();
        if (!started.WaitOne(5000)) throw new InvalidOperationException("OWNED_THREAD_START_FAILED");
        IntPtr held = OpenThread(0x100040, false, tid);
        if (held == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        Thread watcher = null;
        try
        {
            if (arguments[2] == "ended")
            {
                release.Set();
                if (!thread.Join(5000)) throw new InvalidOperationException("OWNED_THREAD_END_FAILED");
            }
            else if (arguments[2] == "live")
            {
                watcher = new Thread(() =>
                {
                    var clock = Stopwatch.StartNew();
                    while (!File.Exists(arguments[3] + ".entered") &&
                        clock.ElapsedMilliseconds < 15000) Thread.Sleep(10);
                    if (File.Exists(arguments[3] + ".entered"))
                    {
                        release.Set();
                        if (thread.Join(5000)) File.WriteAllText(arguments[3] + ".ended", "owned-thread-ended");
                    }
                    completed.WaitOne(30000);
                });
                watcher.Start();
            }
            else throw new InvalidOperationException("OWNED_MODE_INVALID");
            long birth, exit, kernel, user;
            if (!GetThreadTimes(held, out birth, out exit, out kernel, out user))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            uint beforeWait = WaitForSingleObject(held, 0);
            var start = new ProcessStartInfo(arguments[0])
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            var clockQuery = Stopwatch.StartNew();
            using (var guard = Process.Start(start))
            {
                guard.StandardInput.Write("{\"action\":\"" + arguments[1] + "\"}\n");
                guard.StandardInput.Flush();
                var output = guard.StandardOutput.ReadToEnd();
                var error = guard.StandardError.ReadToEnd();
                guard.WaitForExit();
                var self = Process.GetCurrentProcess();
                Console.WriteLine(new JavaScriptSerializer().Serialize(new
                {
                    qualification = "actual-owned-thread-kept-by-query-synchronize-handle",
                    host = new { pid = self.Id, creationTime = self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() },
                    tid, beforeWait, birth = birth.ToString(), exit = exit.ToString(),
                    heldThroughGuardExit = true, guardExit = guard.ExitCode, output, error,
                    elapsedMs = clockQuery.ElapsedMilliseconds, mode = arguments[2], role = arguments[1]
                }));
            }
            return 0;
        }
        finally
        {
            release.Set();
            completed.Set();
            thread.Join(5000);
            if (watcher != null) watcher.Join(5000);
            CloseHandle(held);
            started.Dispose();
            release.Dispose();
            completed.Dispose();
        }
    }

    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadTimes(IntPtr thread, out long birth, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}
