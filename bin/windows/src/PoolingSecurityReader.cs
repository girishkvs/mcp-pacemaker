using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

public sealed class PoolingSecurityReader
{
    private const uint ReadControlSections = 0x1f7;

    /// <summary>Reads native owner, DACL and non-audit security sections.</summary>
    /// <param name="path">File whose descriptor is queried.</param>
    /// <returns>The unfiltered sections in canonical binary form.</returns>
    public byte[] ReadControlDescriptor(string path)
    {
        var descriptor = IntPtr.Zero;
        try
        {
            uint status = GetNamedSecurityInfo(path, 1, ReadControlSections,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out descriptor);
            if (status != 0)
            {
                throw new Win32Exception((int)status);
            }

            var native = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, native, 0, native.Length);
            var raw = new RawSecurityDescriptor(native, 0);
            var canonical = new byte[raw.BinaryLength];
            raw.GetBinaryForm(canonical, 0);
            return canonical;
        }
        finally
        {
            if (descriptor != IntPtr.Zero)
            {
                LocalFree(descriptor);
            }
        }
    }

    [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
    private static extern uint GetNamedSecurityInfo(string path, uint objectType, uint sections,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
