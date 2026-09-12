using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

internal sealed class PoolingNativeFiles
{
    private const int MaximumFileSize = 1024 * 1024;
    private const int MaximumRequestSize = 1400000;
    private const uint ReadAccess = 0x20001;
    private const uint WriteData = 2;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint DaclProtected = 0x1000;
    private const ControlFlags SupportedDescriptorControl =
        ControlFlags.SelfRelative |
        ControlFlags.DiscretionaryAclPresent |
        ControlFlags.DiscretionaryAclProtected |
        ControlFlags.DiscretionaryAclAutoInherited |
        ControlFlags.SystemAclPresent |
        ControlFlags.SystemAclProtected |
        ControlFlags.SystemAclAutoInherited;
    private readonly UTF8Encoding utf8 = new UTF8Encoding(false, true);
    private readonly JavaScriptSerializer json = new JavaScriptSerializer
    {
        MaxJsonLength = MaximumRequestSize,
        RecursionLimit = 8,
    };

    /// <summary>Runs one bounded native file operation.</summary>
    /// <param name="action">inspect-access, stage, or move-no-replace.</param>
    /// <param name="sourcePath">Source file path.</param>
    /// <returns>A JSON identity, revision, security fingerprint, and size.</returns>
    public string Run(string action, string sourcePath)
    {
        if (action == "inspect-access")
        {
            using (var handle = this.Open(sourcePath, ReadAccess, 1))
            {
                return this.json.Serialize(this.Snapshot(handle).Result);
            }
        }

        var destination = Environment.GetEnvironmentVariable("MCP_POOL_TEMP");
        if (string.IsNullOrEmpty(destination))
        {
            throw new ArgumentException();
        }

        var request = this.ReadRequest(action == "stage");
        if (action == "stage")
        {
            return this.json.Serialize(this.Stage(sourcePath, destination, request));
        }

        if (action == "move-no-replace")
        {
            return this.json.Serialize(this.Move(sourcePath, destination, request));
        }

        throw new ArgumentException();
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint attributes, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle ReOpenFile(SafeFileHandle handle, uint access, uint share, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(SafeFileHandle handle, long distance, out long position, uint method);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle handle, byte[] bytes, uint count, out uint read, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(SafeFileHandle handle, byte[] bytes, uint count, out uint written, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushFileBuffers(SafeFileHandle handle);

    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string source, string destination, uint flags);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint sections,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorControl(IntPtr descriptor, out ushort control, out uint revision);

    [DllImport("advapi32.dll")]
    private static extern uint GetLengthSid(IntPtr sid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    private Request ReadRequest(bool stage)
    {
        using (var input = Console.OpenStandardInput())
        using (var buffer = new MemoryStream())
        {
            var chunk = new byte[4096];
            int count;
            while ((count = input.Read(chunk, 0, chunk.Length)) != 0)
            {
                if (buffer.Length + count > MaximumRequestSize)
                {
                    throw new ArgumentException();
                }

                buffer.Write(chunk, 0, count);
            }

            var root = this.json.DeserializeObject(this.utf8.GetString(buffer.ToArray())) as Dictionary<string, object>;
            if (root == null ||
                root.Count != (stage ? 2 : 1) ||
                !root.ContainsKey("expected"))
            {
                throw new ArgumentException();
            }

            var expected = root["expected"] as Dictionary<string, object>;
            if (expected == null ||
                expected.Count != 3)
            {
                throw new ArgumentException();
            }

            var request = new Request
            {
                Identity = this.RequiredString(expected, "identity"),
                Revision = this.RequiredString(expected, "revision"),
                Security = this.RequiredString(expected, "security"),
            };
            if (!this.IsHexHash(request.Revision) ||
                !this.IsHexHash(request.Security) ||
                request.Identity.Length > 80)
            {
                throw new ArgumentException();
            }

            if (stage)
            {
                var encoded = this.RequiredString(root, "bytes", true);
                request.Bytes = Convert.FromBase64String(encoded);
                if (request.Bytes.Length > MaximumFileSize ||
                    Convert.ToBase64String(request.Bytes) != encoded)
                {
                    throw new ArgumentException();
                }

                this.utf8.GetString(request.Bytes);
            }

            return request;
        }
    }

    private string RequiredString(Dictionary<string, object> value, string name, bool allowEmpty = false)
    {
        object item;
        if (!value.TryGetValue(name, out item))
        {
            throw new ArgumentException();
        }

        var text = item as string;
        if (text == null ||
            (!allowEmpty && text.Length == 0))
        {
            throw new ArgumentException();
        }

        return text;
    }

    private bool IsHexHash(string value)
    {
        if (value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
        {
            bool hexadecimal = (character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f');
            if (!hexadecimal)
            {
                return false;
            }
        }

        return true;
    }

    private Dictionary<string, object> Stage(string source, string destination, Request request)
    {
        // A parent DeleteChild grant must not bypass source data-write denial.
        using (var sourceHandle = this.Open(source, ReadAccess | WriteData, 1))
        {
            var original = this.Snapshot(sourceHandle);
            this.CheckExpected(original, request);
            var accepted = original.Security;
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var creator = identity.User;
                var sourceOwner = new SecurityIdentifier(accepted.Owner, 0);
                bool retainsOwner = sourceOwner.Equals(creator) ||
                    sourceOwner.Equals(identity.Owner);
                if (!retainsOwner)
                {
                    this.CheckSimpleOwnerChange(accepted);
                    using (var authority = ReOpenFile(sourceHandle, 0x60000, 7, 0))
                    {
                        this.CheckHandle(authority);
                    }

                    accepted.Owner = new byte[creator.BinaryLength];
                    creator.GetBinaryForm(accepted.Owner, 0);
                }
            }

            using (var candidate = this.Create(destination, accepted, original.Attributes))
            {
                var empty = this.Snapshot(candidate);
                var expectedSecurity = this.SecurityHash(accepted, original.Attributes);
                if (empty.Size != 0 ||
                    empty.Fingerprint != expectedSecurity)
                {
                    throw new PoolingPolicyException();
                }

                // The owned handle denies other writers/deleters until verification completes.
                this.CheckExpected(this.Snapshot(sourceHandle), request);
                this.Write(candidate, request.Bytes);
                var written = this.Snapshot(candidate);
                if (written.Fingerprint != expectedSecurity ||
                    written.Revision != this.Hash(request.Bytes))
                {
                    throw new PoolingConflictException();
                }

                this.CheckExpected(this.Snapshot(sourceHandle), request);
                return written.Result;
            }
        }
    }

    private Dictionary<string, object> Move(string source, string destination, Request request)
    {
        using (var handle = this.Open(source, ReadAccess, 5))
        {
            var original = this.Snapshot(handle);
            this.CheckExpected(original, request);
            this.Require(MoveFileEx(source, destination, 0));
            using (var moved = this.Open(destination, ReadAccess, 5))
            {
                var result = this.Snapshot(moved);
                this.CheckExpected(result, request);
                this.CheckExpected(this.Snapshot(handle), request);
                return result.Result;
            }
        }
    }

    private void CheckExpected(SnapshotState state, Request expected)
    {
        if (state.Identity != expected.Identity ||
            state.Revision != expected.Revision ||
            state.Fingerprint != expected.Security)
        {
            throw new PoolingConflictException();
        }
    }

    private SafeFileHandle Open(string path, uint access, uint share)
    {
        var handle = CreateFile(path, access, share, IntPtr.Zero, 3, OpenReparsePoint, IntPtr.Zero);
        this.CheckHandle(handle);
        return handle;
    }

    private void CheckHandle(SafeFileHandle handle)
    {
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }
    }

    private void Require(bool success)
    {
        if (!success)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    private SnapshotState Snapshot(SafeFileHandle handle)
    {
        FileInformation info;
        this.Require(GetFileInformationByHandle(handle, out info));
        bool regular = GetFileType(handle) == 1 &&
            info.Links == 1 &&
            info.SizeHigh == 0 &&
            info.SizeLow <= MaximumFileSize &&
            (info.Attributes & ~0xa0U) == 0;
        if (!regular)
        {
            throw new PoolingPolicyException();
        }

        var security = this.ReadSecurity(handle);
        this.CheckPolicy(security);
        var content = this.Read(handle);
        FileInformation after;
        this.Require(GetFileInformationByHandle(handle, out after));
        var fingerprint = this.SecurityHash(security, info.Attributes);
        bool changedWhileReading = after.SizeHigh != 0 ||
            after.SizeLow != content.Length ||
            after.SizeLow != info.SizeLow ||
            after.Links != 1 ||
            after.Attributes != info.Attributes ||
            after.WriteTimeHigh != info.WriteTimeHigh ||
            after.WriteTimeLow != info.WriteTimeLow ||
            this.SecurityHash(this.ReadSecurity(handle), after.Attributes) != fingerprint;
        if (changedWhileReading)
        {
            throw new PoolingConflictException();
        }

        return new SnapshotState
        {
            Identity = string.Format(CultureInfo.InvariantCulture, "{0:x8}:{1:x8}{2:x8}",
                info.Volume, info.IndexHigh, info.IndexLow),
            Revision = this.Hash(content),
            Fingerprint = fingerprint,
            Security = security,
            Attributes = info.Attributes,
            Size = content.Length,
        };
    }

    private byte[] Read(SafeFileHandle handle)
    {
        long position;
        this.Require(SetFilePointerEx(handle, 0, out position, 0));
        using (var buffer = new MemoryStream())
        {
            var chunk = new byte[4096];
            while (true)
            {
                uint read;
                this.Require(ReadFile(handle, chunk, (uint)chunk.Length, out read, IntPtr.Zero));
                if (read == 0)
                {
                    return buffer.ToArray();
                }

                if (buffer.Length + read > MaximumFileSize)
                {
                    throw new PoolingPolicyException();
                }

                buffer.Write(chunk, 0, (int)read);
            }
        }
    }

    private void Write(SafeFileHandle handle, byte[] bytes)
    {
        long position;
        this.Require(SetFilePointerEx(handle, 0, out position, 0));
        uint written;
        this.Require(WriteFile(handle, bytes, (uint)bytes.Length, out written, IntPtr.Zero));
        if (written != bytes.Length)
        {
            throw new IOException();
        }

        this.Require(FlushFileBuffers(handle));
    }

    private SecurityState ReadSecurity(SafeFileHandle handle)
    {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint status = GetSecurityInfo(handle, 1, 0x1f7, out owner, out group, out dacl, out sacl, out descriptor);
        if (status != 0)
        {
            throw new Win32Exception((int)status);
        }

        try
        {
            ushort control;
            uint revision;
            this.Require(GetSecurityDescriptorControl(descriptor, out control, out revision));
            return new SecurityState
            {
                Owner = this.CopySid(owner),
                Group = this.CopySid(group),
                Dacl = this.CopyAcl(dacl),
                Labels = this.CopyAcl(sacl),
                Control = control,
            };
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    private byte[] CopySid(IntPtr sid)
    {
        if (sid == IntPtr.Zero)
        {
            throw new PoolingPolicyException();
        }

        var bytes = new byte[GetLengthSid(sid)];
        Marshal.Copy(sid, bytes, 0, bytes.Length);
        return bytes;
    }

    private byte[] CopyAcl(IntPtr acl)
    {
        if (acl == IntPtr.Zero)
        {
            return null;
        }

        int length = (ushort)Marshal.ReadInt16(acl, 2);
        var bytes = new byte[length];
        Marshal.Copy(acl, bytes, 0, bytes.Length);
        return bytes;
    }

    private void CheckPolicy(SecurityState state)
    {
        bool supportedDaclControl = (state.Control & 4) != 0 &&
            (state.Control & ~(ushort)SupportedDescriptorControl) == 0;
        if (state.Dacl == null ||
            !supportedDaclControl)
        {
            throw new PoolingPolicyException();
        }

        var dacl = new RawAcl(state.Dacl, 0);
        foreach (GenericAce ace in dacl)
        {
            var common = ace as CommonAce;
            bool supported = common != null &&
                !common.IsCallback &&
                (common.AceQualifier == AceQualifier.AccessAllowed ||
                 common.AceQualifier == AceQualifier.AccessDenied);
            if (!supported)
            {
                throw new PoolingPolicyException();
            }
        }

        if (state.Labels == null)
        {
            return;
        }

        var labels = new RawAcl(state.Labels, 0);
        if (labels.Count > 1)
        {
            throw new PoolingPolicyException();
        }

        foreach (GenericAce ace in labels)
        {
            var bytes = new byte[ace.BinaryLength];
            ace.GetBinaryForm(bytes, 0);
            if ((int)ace.AceType != 17 ||
                bytes.Length != 20)
            {
                throw new PoolingPolicyException();
            }

            var sid = new SecurityIdentifier(bytes, 8).Value;
            int mask = BitConverter.ToInt32(bytes, 4);
            bool supported = (sid == "S-1-16-4096" || sid == "S-1-16-8192") &&
                mask > 0 &&
                (mask & ~7) == 0 &&
                (ace.AceFlags & ~AceFlags.Inherited) == 0;
            if (!supported)
            {
                throw new PoolingPolicyException();
            }
        }
    }

    private void CheckSimpleOwnerChange(SecurityState state)
    {
        foreach (GenericAce ace in new RawAcl(state.Dacl, 0))
        {
            var common = ace as CommonAce;
            bool simple = common != null &&
                !common.IsCallback &&
                common.AceQualifier == AceQualifier.AccessAllowed &&
                !common.SecurityIdentifier.Value.StartsWith("S-1-3-", StringComparison.Ordinal);
            if (!simple)
            {
                throw new PoolingPolicyException();
            }
        }
    }

    private SafeFileHandle Create(string path, SecurityState security, uint attributes)
    {
        var owner = new SecurityIdentifier(security.Owner, 0);
        var group = new SecurityIdentifier(security.Group, 0);
        var flags = ControlFlags.DiscretionaryAclPresent |
            ControlFlags.SelfRelative |
            (ControlFlags)(security.Control & DaclProtected);
        var labels = security.Labels == null ? null : new RawAcl(security.Labels, 0);
        if (security.Labels != null)
        {
            // Default the audit portion so Windows inherits folder rules alongside the supplied label.
            flags |= ControlFlags.SystemAclPresent | ControlFlags.SystemAclDefaulted;
        }

        // SACL protection would suppress the destination folder's inherited auditing.
        var descriptor = new RawSecurityDescriptor(flags, owner, group, labels, new RawAcl(security.Dacl, 0));
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        var nativeAttributes = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityAttributes)));
        try
        {
            var value = new SecurityAttributes
            {
                Length = Marshal.SizeOf(typeof(SecurityAttributes)),
                Descriptor = pinned.AddrOfPinnedObject(),
                Inherit = 0,
            };
            Marshal.StructureToPtr(value, nativeAttributes, false);
            var handle = CreateFile(path, ReadAccess | WriteData, 1, nativeAttributes, 1, attributes, IntPtr.Zero);
            this.CheckHandle(handle);
            return handle;
        }
        finally
        {
            Marshal.FreeHGlobal(nativeAttributes);
            pinned.Free();
        }
    }

    private string SecurityHash(SecurityState security, uint attributes)
    {
        using (var buffer = new MemoryStream())
        using (var writer = new BinaryWriter(buffer))
        {
            writer.Write("mcp-access-v1");
            this.WritePart(writer, security.Owner);
            this.WritePart(writer, security.Group);
            writer.Write((uint)(security.Control & DaclProtected));
            this.WritePart(writer, security.Dacl);
            this.WritePart(writer, security.Labels);
            writer.Write(attributes);
            writer.Flush();
            return this.Hash(buffer.ToArray());
        }
    }

    private void WritePart(BinaryWriter writer, byte[] bytes)
    {
        writer.Write(bytes == null ? -1 : bytes.Length);
        if (bytes != null)
        {
            writer.Write(bytes);
        }
    }

    private string Hash(byte[] bytes)
    {
        using (var hash = SHA256.Create())
        {
            return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr Descriptor;
        public int Inherit;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint AccessTimeLow;
        public uint AccessTimeHigh;
        public uint WriteTimeLow;
        public uint WriteTimeHigh;
        public uint Volume;
        public uint SizeHigh;
        public uint SizeLow;
        public uint Links;
        public uint IndexHigh;
        public uint IndexLow;
    }

    private sealed class Request
    {
        public string Identity { get; set; }
        public string Revision { get; set; }
        public string Security { get; set; }
        public byte[] Bytes { get; set; }
    }

    private sealed class SecurityState
    {
        public byte[] Owner { get; set; }
        public byte[] Group { get; set; }
        public byte[] Dacl { get; set; }
        public byte[] Labels { get; set; }
        public ushort Control { get; set; }
    }

    private sealed class SnapshotState
    {
        public string Identity { get; set; }
        public string Revision { get; set; }
        public string Fingerprint { get; set; }
        public SecurityState Security { get; set; }
        public uint Attributes { get; set; }
        public int Size { get; set; }

        public Dictionary<string, object> Result
        {
            get
            {
                return new Dictionary<string, object>
                {
                    { "identity", this.Identity },
                    { "revision", this.Revision },
                    { "security", this.Fingerprint },
                    { "size", this.Size },
                };
            }
        }
    }
}

internal sealed class PoolingConflictException : Exception
{
}

internal sealed class PoolingPolicyException : Exception
{
}
