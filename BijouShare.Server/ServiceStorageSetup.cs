using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Server;

internal static class ServiceStorageSetup
{
    private const string DirectoryAcl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)";
    private const uint ReadControl = 0x20000, WriteDac = 0x40000, ReadAttributes = 0x80;
    private const uint WriteRights = (uint)(FileSystemRights.Write | FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)
        | 0x10000000 | 0x40000000; // GENERIC_ALL and GENERIC_WRITE

    // Deferred MSI action running as SYSTEM. This entry point accepts no caller-selected path.
    internal static void Prepare()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem)
            throw new UnauthorizedAccessException("Server storage preparation requires the Windows Installer service.");
        var common = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var ancestors = new Stack<DirectoryInfo>();
        for (var dir = common; dir is not null; dir = dir.Parent)
            ancestors.Push(dir);
        var handles = new Stack<SafeFileHandle>();
        try
        {
            foreach (var dir in ancestors)
                handles.Push(OpenDirectory(dir));
            var descriptor = new DirectorySecurity();
            descriptor.SetSecurityDescriptorSddlForm(DirectoryAcl);
            var directory = common;
            foreach (var name in new[] { "BijouShare", "Server" })
            {
                directory = new DirectoryInfo(Path.Combine(directory.FullName, name));
                // New directories receive the protected ACL in the create operation itself.
                directory.Create(descriptor);
                var handle = OpenDirectory(directory, ReadAttributes | ReadControl | WriteDac);
                handles.Push(handle);
                if (!IsTrusted(ReadSecurity(handle)))
                    throw new UnauthorizedAccessException($"Secure the owner and write permissions of {directory.FullName} before installing BijouShare Server.");
                // Use the verified open object. A path lookup to set permissions could follow a substituted link.
                if (!SetKernelObjectSecurity(handle, 0x80000004, descriptor.GetSecurityDescriptorBinaryForm()))
                    throw WindowsError("Could not secure the server data directory");
            }
        }
        finally
        {
            foreach (var handle in handles)
                handle.Dispose();
        }
    }

    internal static bool IsTrusted(RawSecurityDescriptor descriptor, IReadOnlySet<SecurityIdentifier>? directAdministrators = null)
    {
        static bool Trusted(SecurityIdentifier? sid) => sid is not null &&
            (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
             sid.IsWellKnown(WellKnownSidType.LocalServiceSid));
        if (!Trusted(descriptor.Owner) || descriptor.DiscretionaryAcl is not { } acl)
            return false;
        foreach (GenericAce ace in acl)
        {
            if (ace is not QualifiedAce entry)
                return false;
            if (entry.AceQualifier != AceQualifier.AccessAllowed || ((uint)entry.AccessMask & WriteRights) == 0 ||
                Trusted(entry.SecurityIdentifier))
                continue;
            // The creator-owner placeholder applies only to new children created by the permitted writers.
            if (entry.SecurityIdentifier.IsWellKnown(WellKnownSidType.CreatorOwnerSid) && (entry.AceFlags & AceFlags.InheritOnly) != 0)
                continue;
            // Earlier interactive setup granted the initializing administrator an explicit
            // ACE. Confirm the account is still a direct local administrator before replacing it.
            var sid = entry.SecurityIdentifier;
            if ((entry.AceFlags & AceFlags.Inherited) == 0 &&
                (sid.Value.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.Value.StartsWith("S-1-12-1-", StringComparison.Ordinal)))
            {
                directAdministrators ??= ReadDirectAdministrators();
                if (directAdministrators.Contains(sid))
                    continue;
            }
            return false;
        }
        return true;
    }

    internal static SafeFileHandle OpenDirectory(DirectoryInfo directory, uint access = ReadAttributes)
    {
        // Metadata-only opens do not enforce delete sharing. Request directory data
        // access so Windows rejects a rename while these path components are pinned.
        const uint listDirectory = 0x0001;
        var handle = CreateFile(directory.FullName, access | listDirectory, FileShare.ReadWrite, IntPtr.Zero, 3,
            0x02200000, IntPtr.Zero); // OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT, no delete sharing
        if (handle.IsInvalid)
        {
            var error = WindowsError($"Could not open {directory.FullName}");
            handle.Dispose();
            throw error;
        }
        if (!GetFileInformationByHandleEx(handle, 9, out var info, 8))
        {
            var error = WindowsError($"Could not inspect {directory.FullName}");
            handle.Dispose();
            throw error;
        }
        if ((info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
        {
            handle.Dispose();
            throw new InvalidDataException($"The server data path requires ordinary local directories: {directory.FullName}");
        }
        return handle;
    }

    private static HashSet<SecurityIdentifier> ReadDirectAdministrators()
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        string account;
        try { account = ((NTAccount)administrators.Translate(typeof(NTAccount))).Value; }
        catch (IdentityNotMappedException error)
        {
            throw new IOException("Windows could not identify the local Administrators group.", error);
        }
        var groupName = account[(account.LastIndexOf('\\') + 1)..];
        var result = new HashSet<SecurityIdentifier>();
        nuint resume = 0;
        const uint moreData = 234;
        uint status;
        do
        {
            // Level 0 returns SID pointers, including unresolved domain members, without
            // relying on display names or requiring a domain controller for account lookups.
            status = NetLocalGroupGetMembers(null, groupName, 0, out var buffer, 65536, out var count, out _, ref resume);
            try
            {
                if (status != 0 && status != moreData)
                    throw new IOException("Windows could not verify local Administrators group membership.", new Win32Exception((int)status));
                if (status == moreData && count == 0)
                    throw new IOException("Windows returned an incomplete list of local administrators.");
                for (var i = 0; i < count; i++)
                    result.Add(new SecurityIdentifier(Marshal.ReadIntPtr(buffer, checked(i * IntPtr.Size))));
            }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
        } while (status == moreData);
        return result;
    }

    private static RawSecurityDescriptor ReadSecurity(SafeFileHandle directory)
    {
        var error = GetSecurityInfo(directory, 1, 5, out _, out _, out _, out _, out var security);
        if (error != 0)
            throw new IOException("Could not inspect the server data directory permissions.", new Win32Exception((int)error));
        try
        {
            var bytes = new byte[GetSecurityDescriptorLength(security)];
            Marshal.Copy(security, bytes, 0, bytes.Length);
            return new RawSecurityDescriptor(bytes, 0);
        }
        finally { LocalFree(security); }
    }

    private static IOException WindowsError(string message) => new(message, new Win32Exception(Marshal.GetLastWin32Error()));

    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTagInfo { public FileAttributes Attributes; public uint ReparseTag; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, FileShare share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out AttributeTagInfo info, uint size);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle file, int type, uint flags, out IntPtr owner, out IntPtr group,
        out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle file, uint flags, byte[] descriptor);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetLocalGroupGetMembers(string? server, string group, uint level, out IntPtr buffer,
        uint maxLength, out int entriesRead, out uint totalEntries, ref nuint resume);
    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
