using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

internal sealed class TerminateOwned
{
    private static int Main(string[] args)
    {
        return new TerminateOwned().Run(args);
    }

    private int Run(string[] args)
    {
        try
        {
            int processId = int.Parse(args[0], CultureInfo.InvariantCulture);
            long expected = long.Parse(args[1], CultureInfo.InvariantCulture);
            using (var process = Process.GetProcessById(processId))
            {
                var handle = process.Handle;
                long created;
                long exit;
                long kernel;
                long user;
                if (!GetProcessTimes(handle, out created, out exit, out kernel, out user) ||
                    created != expected)
                {
                    throw new InvalidOperationException("Owned process creation identity mismatch");
                }

                if (!TerminateProcess(handle, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!process.WaitForExit(3000))
                {
                    throw new TimeoutException();
                }
            }

            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.GetType().Name);
            return 1;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out long created,
        out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
}
