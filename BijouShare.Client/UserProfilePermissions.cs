using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using BijouShare.Shared;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

internal static partial class UserProfileStorage
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier InstallerSid = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static StorageLease Acquire(string directory)
    {
        RequireHomeDirectory(directory);
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new UnauthorizedAccessException("The Windows user SID is unavailable.");
        if (!Path.GetFileName(directory).Equals(".bijoushare", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The profile must belong to the signed-in Windows user.");
        var root = new DirectoryInfo(directory);
        var driveRoot = Path.GetPathRoot(root.FullName)!;
        if (driveRoot.StartsWith(@"\\", StringComparison.Ordinal) ||
            new DriveInfo(driveRoot) is not { DriveType: not DriveType.Network, DriveFormat: "NTFS" or "ReFS" })
            throw new IOException("Use a local NTFS or ReFS directory for the private client profile.");

        var security = new DirectorySecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(true, false);
        foreach (var trustee in new[] { user, SystemSid })
            security.AddAccessRule(new FileSystemAccessRule(trustee, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

        PrepareParents(root.Parent!, user, security);
        if (!root.Exists)
            root.Create(security);
        CheckExistingProfile(root.FullName, user);
        // SetKernelObjectSecurity modifies only the object referenced by the handle.
        // Recursive Set-Acl on a directory would also touch unvalidated descendants.
        var fileAcl = new RawSecurityDescriptor($"O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)");
        var directoryAcl = new RawSecurityDescriptor($"O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)");
        RepairTree(root.FullName, user, fileAcl, directoryAcl);
        return StorageLease.LockDirectory(directory);
    }

    private static void PrepareParents(DirectoryInfo directory, SecurityIdentifier user, DirectorySecurity newDirectoryAcl)
    {
        if (directory.Parent is { } parent)
            PrepareParents(parent, user, newDirectoryAcl);
        if (!directory.Exists)
        {
            directory.Create(newDirectoryAcl);
            directory.Refresh();
        }
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("A client profile path cannot cross a reparse point.");
        var acl = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!Trusted(owner, user))
            throw new UnauthorizedAccessException($"Untrusted owner of profile ancestor {directory.FullName}. Choose a private location.");
        const FileSystemRights replace = FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;
        foreach (FileSystemAccessRule ace in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (ace.AccessControlType == AccessControlType.Allow && !ace.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) &&
                (ace.FileSystemRights & replace) != 0 && !Trusted((SecurityIdentifier)ace.IdentityReference, user))
                throw new UnauthorizedAccessException($"Another account can replace a profile ancestor at {directory.FullName}. Choose a private location.");
    }

    private static bool Trusted(SecurityIdentifier? sid, SecurityIdentifier user) =>
        sid == user || sid == SystemSid || sid == AdminSid || sid == InstallerSid;

    private static void CheckExistingProfile(string root, SecurityIdentifier user)
    {
        using var directory = Open(root, 0x20000);
        Inspect(directory, root, user);
        var path = Path.Combine(root, "client.json");
        try { _ = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        using var item = Open(path, 0x80020000); // GENERIC_READ | READ_CONTROL
        if (Inspect(item, path, user).IsDirectory)
            throw new InvalidDataException("The client profile must be a file.");
        using var input = new FileStream(item, FileAccess.Read);
        ClientSettings.RequireCurrentFormat(input);
    }

    private static (bool IsDirectory, RawSecurityDescriptor Acl) Inspect(SafeFileHandle item, string path, SecurityIdentifier user)
    {
        if (!GetFileInformationByHandle(item, out var info))
            throw NativeError(path);
        var isDirectory = info.Attributes.HasFlag(FileAttributes.Directory);
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || !isDirectory && info.Links != 1)
            throw new UnauthorizedAccessException($"Private profile contains a link at {path}.");
        var current = ReadSecurity(item, path);
        if (!Trusted(current.Owner, user))
            throw new UnauthorizedAccessException($"Private profile item has an untrusted owner at {path}.");
        return (isDirectory, current);
    }

    private static void RepairTree(string path, SecurityIdentifier user, RawSecurityDescriptor fileAcl, RawSecurityDescriptor directoryAcl)
    {
        const uint readControl = 0x20000, writeDacl = 0x40000, writeOwner = 0x80000;
        using var item = Open(path, readControl);
        var (isDirectory, current) = Inspect(item, path, user);
        var desired = isDirectory ? directoryAcl : fileAcl;
        var sections = AccessControlSections.Owner | AccessControlSections.Access;
        if (current.GetSddlForm(sections) != desired.GetSddlForm(sections))
        {
            bool changeOwner = current.Owner != user;
            using var writable = Open(path, writeDacl | (changeOwner ? writeOwner : 0));
            var bytes = new byte[desired.BinaryLength];
            desired.GetBinaryForm(bytes, 0);
            if (!SetKernelObjectSecurity(writable, DaclSecurity | (changeOwner ? OwnerSecurity : 0), bytes))
                throw NativeError(path);
            if (ReadSecurity(item, path).GetSddlForm(sections) != desired.GetSddlForm(sections))
                throw new UnauthorizedAccessException($"Cannot enforce private permissions on {path}.");
        }
        if (isDirectory)
            foreach (var child in Directory.EnumerateFileSystemEntries(path))
                RepairTree(child, user, fileAcl, directoryAcl);
    }

    private const uint OwnerSecurity = 1, DaclSecurity = 4;
    private static RawSecurityDescriptor ReadSecurity(SafeFileHandle handle, string path)
    {
        const uint parts = OwnerSecurity | DaclSecurity;
        GetKernelObjectSecurity(handle, parts, null, 0, out var length);
        if (length == 0)
            throw NativeError(path);
        var bytes = new byte[length];
        if (!GetKernelObjectSecurity(handle, parts, bytes, length, out _))
            throw NativeError(path);
        return new RawSecurityDescriptor(bytes, 0);
    }

    private static SafeFileHandle Open(string path, uint access)
    {
        // Pin the object against rename/deletion and inspect the link itself.
        var handle = CreateFile(path, access, FileShare.ReadWrite, 0, FileMode.Open, 0x02200000, 0);
        if (!handle.IsInvalid)
            return handle;
        var error = NativeError(path);
        handle.Dispose();
        throw error;
    }

    private static IOException NativeError(string path) =>
        new($"Cannot secure private profile item {path}.", new Win32Exception(Marshal.GetLastPInvokeError()));

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public FileAttributes Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, FileShare share, nint security,
        FileMode mode, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint parts, [Out] byte[]? bytes, uint length, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint parts, byte[] bytes);
}
