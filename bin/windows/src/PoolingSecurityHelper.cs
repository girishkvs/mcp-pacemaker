using System;
using System.ComponentModel;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;

public sealed class PoolingSecurityHelper
{
    private readonly PoolingSecurityReader nativeReader = new PoolingSecurityReader();
    private readonly AccessControlSections sections =
        AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group;

    /// <summary>Inspects or preserves Windows file security.</summary>
    /// <param name="args">One action: inspect or copy. File paths come from MCP_POOL environment variables.</param>
    /// <returns>Zero on success, three on a source security conflict, or one on failure.</returns>
    public static int Main(string[] args)
    {
        return new PoolingSecurityHelper().Run(args);
    }

    /// <summary>Runs a security operation without changing file contents.</summary>
    /// <param name="args">One action: inspect or copy.</param>
    /// <returns>Zero on success, three on a source security conflict, or one on failure.</returns>
    public int Run(string[] args)
    {
        try
        {
            if (args.Length != 1)
            {
                throw new ArgumentException();
            }

            var sourcePath = this.RequiredEnvironment("MCP_POOL_SOURCE");
            if (args[0] == "inspect")
            {
                Console.WriteLine(this.ReadSecurity(sourcePath).Fingerprint);
                return 0;
            }

            if (args[0] == "copy")
            {
                return this.CopySecurity(sourcePath);
            }

            throw new ArgumentException();
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("MCPERR type=" + error.GetType().Name);
            var nativeError = error as Win32Exception;
            if (nativeError != null)
            {
                Console.Error.WriteLine("MCPERR nativeError=" + nativeError.NativeErrorCode);
            }

            return 1;
        }
    }

    private string RequiredEnvironment(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException();
        }

        return value;
    }

    private SecurityState ReadSecurity(string path)
    {
        var acl = File.GetAccessControl(path);
        var descriptor = acl.GetSecurityDescriptorSddlForm(this.sections);
        var native = this.nativeReader.ReadControlDescriptor(path);
        bool complete = true;
        var audit = new byte[0];
        try
        {
            audit = this.ReadAudit(path);
        }
        catch (PrivilegeNotHeldException)
        {
            complete = false;
        }
        catch (UnauthorizedAccessException)
        {
            complete = false;
        }

        int attributes = (int)File.GetAttributes(path);
        using (var hash = SHA256.Create())
        using (var buffer = new MemoryStream())
        using (var writer = new BinaryWriter(buffer))
        {
            writer.Write(native.Length);
            writer.Write(native);
            writer.Write(audit.Length);
            writer.Write(audit);
            writer.Write(attributes);
            writer.Flush();
            var scope = complete ? "F:" : "P:";
            return new SecurityState
            {
                Descriptor = descriptor,
                Fingerprint = scope + Convert.ToBase64String(hash.ComputeHash(buffer.ToArray())),
            };
        }
    }

    private byte[] ReadAudit(string path)
    {
        return File.GetAccessControl(path, AccessControlSections.Audit).GetSecurityDescriptorBinaryForm();
    }

    private int CopySecurity(string sourcePath)
    {
        var expectedFingerprint = this.RequiredEnvironment("MCP_POOL_SECURITY");
        var source = this.ReadSecurity(sourcePath);
        if (!string.Equals(source.Fingerprint, expectedFingerprint, StringComparison.Ordinal))
        {
            return 3;
        }

        var paths = new[]
        {
            this.RequiredEnvironment("MCP_POOL_TEMP"),
            this.RequiredEnvironment("MCP_POOL_BACKUP"),
        };
        foreach (var path in paths)
        {
            var actual = File.GetAccessControl(path);
            if (!string.Equals(actual.GetSecurityDescriptorSddlForm(this.sections),
                source.Descriptor, StringComparison.Ordinal))
            {
                var copy = new FileSecurity();
                copy.SetSecurityDescriptorSddlForm(source.Descriptor, this.sections);
                File.SetAccessControl(path, copy);
                actual = File.GetAccessControl(path);
            }

            if (!string.Equals(actual.GetSecurityDescriptorSddlForm(this.sections),
                source.Descriptor, StringComparison.Ordinal))
            {
                throw new InvalidOperationException();
            }

            if (!string.Equals(this.ReadSecurity(path).Fingerprint,
                expectedFingerprint, StringComparison.Ordinal))
            {
                throw new InvalidOperationException();
            }
        }

        return string.Equals(this.ReadSecurity(sourcePath).Fingerprint,
            expectedFingerprint, StringComparison.Ordinal) ? 0 : 3;
    }

    private sealed class SecurityState
    {
        public string Descriptor { get; set; }

        public string Fingerprint { get; set; }
    }
}
