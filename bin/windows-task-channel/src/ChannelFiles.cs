using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal sealed class ChannelFiles : IDisposable
{
    private readonly ChannelNative native = new ChannelNative();
    private readonly List<IDisposable> held = new List<IDisposable>();
    private readonly string actor;
    private readonly HashSet<string> trusted;
    private readonly Action checkpoint;

    internal ChannelFiles(string actorSid, Action check = null)
    {
        checkpoint = check;
        actor = actorSid;
        trusted = new HashSet<string>(StringComparer.Ordinal)
        {
            actor, "S-1-5-18", "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        };
    }

    internal string PathValue(string path)
    {
        bool absolute = path != null &&
            path.Length > 3 &&
            char.IsLetter(path[0]) &&
            path[1] == ':' &&
            (path[2] == '\\' || path[2] == '/');
        if (!absolute ||
            path.IndexOf(':', 2) >= 0 ||
            path.IndexOf('\0') >= 0) throw new InvalidOperationException("LOCAL_ABSOLUTE_PATH_REQUIRED");
        return Path.GetFullPath(path);
    }

    internal string Digest(byte[] bytes)
    {
        using (var hash = SHA256.Create())
            return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
    }

    internal string Hash(Stream stream)
    {
        stream.Position = 0;
        using (var hash = SHA256.Create())
        {
            var digest = BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            stream.Position = 0;
            return digest;
        }
    }

    internal void Security(string path, bool directory, bool fullWrite)
    {
        FileSystemSecurity descriptor = directory
            ? (FileSystemSecurity)Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access)
            : File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
        var owner = descriptor.GetOwner(typeof(SecurityIdentifier)).Value;
        if (!trusted.Contains(owner)) throw new InvalidOperationException("UNTRUSTED_PATH_OWNER");
        var binary = new RawSecurityDescriptor(descriptor.GetSecurityDescriptorBinaryForm(), 0);
        if (binary.DiscretionaryAcl == null) throw new InvalidOperationException("NULL_PATH_DACL");
        int dangerous = 0x10000 | 0x40000 | 0x80000 | 0x40;
        if (fullWrite) dangerous |= 2 | 4 | 0x10 | 0x100;
        foreach (GenericAce ace in binary.DiscretionaryAcl)
        {
            if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
            var common = ace as CommonAce;
            if (common == null ||
                common.IsCallback) throw new InvalidOperationException("UNSUPPORTED_PATH_ACE");
            if (common.AceQualifier != AceQualifier.AccessAllowed) continue;
            int mask = common.AccessMask;
            bool writable = (mask & dangerous) != 0 ||
                (mask & unchecked((int)0x50000000)) != 0;
            if (writable &&
                !trusted.Contains(common.SecurityIdentifier.Value))
                throw new InvalidOperationException("UNTRUSTED_PATH_WRITER");
        }
    }

    internal string Owner(string path)
    {
        return File.GetAccessControl(path, AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)).Value;
    }

    internal void Chain(string path, bool protectWriters)
    {
        var full = PathValue(path);
        var paths = new List<string>();
        var current = full;
        while (current != null)
        {
            paths.Add(current);
            current = Path.GetDirectoryName(current);
        }
        paths.Reverse();
        foreach (var item in paths)
        {
            HoldPath(item, protectWriters, item == full);
        }
    }

    internal bool HoldPath(string path, bool protectWriters, bool fullWrite)
    {
        if (checkpoint != null) checkpoint();
        var security = new ChannelApi.SecurityAttributes { length = Marshal.SizeOf(typeof(ChannelApi.SecurityAttributes)) };
        var handle = ChannelApi.CreateFileW(path, 0x20080, 3, ref security, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new InvalidOperationException("PATH_HOLD_DENIED");
        }
        held.Add(handle);
        ChannelApi.FileInformation information;
        native.Require(ChannelApi.GetFileInformationByHandle(handle, out information));
        if ((information.attributes & 0x400) != 0) throw new InvalidOperationException("REPARSE_PATH_REFUSED");
        bool directory = (information.attributes & 0x10) != 0;
        if (protectWriters) Security(path, directory, fullWrite || !directory);
        if (checkpoint != null) checkpoint();
        return directory;
    }

    internal FileStream HoldFile(string path, bool protectWriters)
    {
        path = PathValue(path);
        Chain(path, protectWriters);
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        held.Add(stream);
        return stream;
    }

    internal string Canonical(FileStream stream)
    {
        var text = new StringBuilder(32768);
        uint length = ChannelApi.GetFinalPathNameByHandleW(stream.SafeFileHandle, text, text.Capacity, 0);
        if (length < 1 ||
            length >= text.Capacity) throw new InvalidOperationException("CANONICAL_PATH_UNAVAILABLE");
        var path = text.ToString();
        if (!path.StartsWith(@"\\?\", StringComparison.Ordinal)) throw new InvalidOperationException("CANONICAL_PATH_UNSUPPORTED");
        return PathValue(path.Substring(4));
    }

    internal T WithDescriptor<T>(string targetSid, bool directory, Func<ChannelApi.SecurityAttributes, T> action, bool pipe = false)
    {
        var target = new SecurityIdentifier(targetSid).Value;
        var rights = pipe ? "0x12019f" : directory ? "0x1200a9" : "0x120089";
        var inherit = directory ? "OICI" : "";
        var sddl = "O:" + actor + "G:" + actor + "D:P(A;" + inherit + ";FA;;;" + actor +
            ")(A;" + inherit + ";FA;;;SY)";
        if (target != actor) sddl += "(A;" + inherit + ";" + rights + ";;;" + target + ")";
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        var memory = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, memory, bytes.Length);
            return action(new ChannelApi.SecurityAttributes
            {
                length = Marshal.SizeOf(typeof(ChannelApi.SecurityAttributes)),
                descriptor = memory, inherit = false
            });
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    internal void CreateDirectory(string path, string targetSid)
    {
        WithDescriptor(targetSid, true, security =>
        {
            native.Require(ChannelApi.CreateDirectoryW(path, ref security));
            return true;
        });
    }

    internal FileStream CreateManifest(string path, string targetSid, byte[] bytes)
    {
        var handle = WithDescriptor(targetSid, false, security =>
            ChannelApi.CreateFileW(path, 0xC0000000, 1, ref security, 1, 0x80, IntPtr.Zero));
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new InvalidOperationException("MANIFEST_CREATE_DENIED");
        }
        using (var stream = new FileStream(handle, FileAccess.ReadWrite))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
        }
        return HoldFile(path, true);
    }

    internal Dictionary<string, object> InspectRoot(string root)
    {
        root = PathValue(root);
        Chain(root, true);
        int directories = 0, files = 0;
        var pending = new Queue<string>();
        pending.Enqueue(root);
        while (pending.Count != 0)
        {
            if (checkpoint != null) checkpoint();
            var directory = pending.Dequeue();
            if (++directories > 2048) throw new InvalidOperationException("CODE_DIRECTORY_BOUND");
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                bool isDirectory = HoldPath(path, true, true);
                if (isDirectory) pending.Enqueue(path);
                else if (++files > 16384) throw new InvalidOperationException("CODE_FILE_BOUND");
            }
            if (checkpoint != null) checkpoint();
        }
        return new Dictionary<string, object>
        {
            { "root", root }, { "directories", directories }, { "files", files },
            { "protection", "observed-owner-and-allow-writers" }, { "loadedCodeAttestation", false }
        };
    }

    public void Dispose()
    {
        for (int index = held.Count - 1; index >= 0; index--) held[index].Dispose();
        held.Clear();
    }
}
