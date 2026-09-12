using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class FixturePolicy
{
    /// <summary>Applies a raw DACL to an isolated synthetic fixture without ACE inheritance conversion.</summary>
    /// <param name="path">Owned test file.</param>
    /// <param name="descriptor">Self-relative security descriptor.</param>
    public void SetDacl(string path, byte[] descriptor)
    {
        using (var handle = CreateFile(path, 0x40000, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
        {
            if (handle.IsInvalid ||
                !SetKernelObjectSecurity(handle, 4, descriptor))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }

    /// <summary>Sets only the mandatory label on an isolated synthetic fixture.</summary>
    /// <param name="path">Owned test file.</param>
    /// <param name="sddl">Descriptor containing the test label.</param>
    public void SetLabel(string path, string sddl)
    {
        this.SetNonAuditPolicy(path, sddl, 0x10);
    }

    /// <summary>Sets a selected non-audit policy section on an isolated synthetic fixture.</summary>
    /// <param name="path">Owned test file.</param>
    /// <param name="sddl">Descriptor containing the test policy.</param>
    /// <param name="sections">Native security information mask.</param>
    public void SetNonAuditPolicy(string path, string sddl, uint sections)
    {
        IntPtr descriptor;
        uint length;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out length))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            bool present, defaulted;
            IntPtr sacl;
            if (!GetSecurityDescriptorSacl(descriptor, out present, out sacl, out defaulted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            uint error = SetNamedSecurityInfo(path, 1, sections, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            if (error != 0)
            {
                throw new Win32Exception((int)error);
            }
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint attributes, IntPtr template);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint sections, byte[] descriptor);

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl,
        uint revision, out IntPtr descriptor, out uint length);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor, out bool present,
        out IntPtr sacl, out bool defaulted);

    [DllImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
    private static extern uint SetNamedSecurityInfo(string path, uint type, uint sections,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
