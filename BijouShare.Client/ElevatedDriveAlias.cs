using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

// Drive letters live in the owner's logon namespace. Mount Manager supplies the volume name Windows uses for elevation.
internal static class ElevatedDriveAlias
{
    internal sealed class DriveLetterInUseException(string name) : IOException($"Drive {name} is already in use in this Windows logon.");

    internal static bool HasLinkedElevation
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return LinkedAdministratorLogon(identity).HasValue;
        }
    }

    internal static long? LinkedAdministratorLogon(WindowsIdentity owner)
    {
        if (!GetTokenInt(owner.AccessToken, 18 /* TokenElevationType */, out var ownerType) || ownerType != 3)
            return null;
        using var linked = OpenLinkedToken(owner.AccessToken);
        if (linked is null) return null;
        using var administrator = new WindowsIdentity(linked.DangerousGetHandle());
        if (administrator.User != owner.User || !GetTokenInt(linked, 18, out var type) || type != 2 ||
            !GetTokenInt(owner.AccessToken, 12 /* TokenSessionId */, out var ownerSession) || ownerSession == 0 ||
            !GetTokenInt(linked, 12, out var linkedSession) || linkedSession != ownerSession ||
            !GetStatistics(linked, 10 /* TokenStatistics */, out var statistics, Marshal.SizeOf<TokenStatistics>(), out _))
            return null;
        return statistics.AuthenticationId;
    }

    internal static SafeAccessTokenHandle? OpenLinkedToken(SafeAccessTokenHandle token) =>
        GetLinkedToken(token, 19 /* TokenLinkedToken */, out var linked, IntPtr.Size, out _) ? new(linked) : null;

    internal static IDisposable MountPrivateLetter(string mountPoint, string directory, SafeFileHandle witnessedRoot)
    {
        var mount = ClientSettings.NormalizeMountPoint(mountPoint);
        using var impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
        using var owner = WindowsIdentity.GetCurrent();
        if (impersonation is not null || owner.IsSystem || owner.User is null ||
            !GetTokenInt(owner.AccessToken, 12 /* TokenSessionId */, out var session) || session <= 0)
            throw new UnauthorizedAccessException("Mount the drive in its owner's Windows sign-in session.");
        if (!Path.IsPathFullyQualified(directory))
            throw new ArgumentException("The private mount directory must be an absolute path.", nameof(directory));
        var target = VerifyMount(witnessedRoot, mount, session, Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)));
        return CreateTemporaryLink(mount[..2], target, session, AuthenticationId(owner.AccessToken));
    }

    internal static IDisposable Create(string mountPoint, int workerPid, long remoteRootHandle)
    {
        mountPoint = ClientSettings.NormalizeMountPoint(mountPoint);
        ValidateAttestation(workerPid, remoteRootHandle);
        using var impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
        using var self = WindowsIdentity.GetCurrent();
        if (impersonation != null || self.IsSystem || !GetTokenInt(self.AccessToken, 18, out var selfType) || selfType != 2)
            throw new UnauthorizedAccessException("Approve Windows elevation with the account that owns this drive.");
        using var linked = OpenLinkedToken(self.AccessToken) ?? throw Error("Cannot identify the linked Windows session.");
        using var limitedIdentity = new WindowsIdentity(linked.DangerousGetHandle());
        using var process = OpenWorker(workerPid);
        if (!OpenProcessToken(process, 8 /* TOKEN_QUERY */, out var worker))
            throw Error("Cannot verify the client worker's logon session.");
        using (worker)
        using (var owner = new WindowsIdentity(worker.DangerousGetHandle()))
        {
            var selfLogon = AuthenticationId(self.AccessToken);
            var limitedLogon = AuthenticationId(linked);
            if (self.User is null || limitedIdentity.User != self.User || owner.User != self.User ||
                !GetTokenInt(self.AccessToken, 12 /* TokenSessionId */, out var session) || session == 0 ||
                !GetTokenInt(linked, 12, out var linkedSession) || linkedSession != session ||
                !GetTokenInt(worker, 12, out var workerSession) || workerSession != session ||
                !GetTokenInt(linked, 18, out var limitedType) || limitedType != 3 ||
                !GetTokenInt(worker, 18, out var workerType) || workerType != 3 ||
                selfLogon == limitedLogon || AuthenticationId(worker) != limitedLogon)
                throw new UnauthorizedAccessException("The drive belongs to a different Windows logon. Use the drive owner's linked administrator session.");
            using var root = DuplicateRoot(process, remoteRootHandle);
            var target = VerifiedRoot(root, mountPoint, session);
            return CreateTemporaryLink(mountPoint[..2], target, session, selfLogon);
        }
    }

    internal static IDisposable RestoreRegistered(char letter, int pid, long rootHandle, Guid grant, SecurityIdentifier peerSid, long peerLogon)
    {
        if (letter is < 'A' or > 'Z' || grant == Guid.Empty)
            throw new InvalidDataException("Invalid saved drive approval.");
        ValidateAttestation(pid, rootHandle);
        using var impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
        using var self = WindowsIdentity.GetCurrent();
        if (impersonation is not null || !self.IsSystem || !MountAliasPipe.IsInstalledClient ||
            !GetTokenInt(self.AccessToken, 12 /* TokenSessionId */, out var serviceSession) || serviceSession != 0)
            throw new UnauthorizedAccessException("Saved drive approval requires the installed Windows service.");

        using var process = OpenWorker(pid);
        if (!OpenProcessToken(process, 8 /* TOKEN_QUERY */, out var worker))
            throw Error("Cannot verify the client worker's logon session.");
        using (worker)
        using (var owner = new WindowsIdentity(worker.DangerousGetHandle()))
        {
            if (owner.User is not { } sid || sid != peerSid || AuthenticationId(worker) != peerLogon ||
                !GetTokenInt(worker, 12 /* TokenSessionId */, out var session) || session <= 0 ||
                LinkedAdministratorLogon(owner) is not { } elevatedLogon || elevatedLogon == peerLogon)
                throw new UnauthorizedAccessException("The drive request must come from its owner's paired Windows logon.");
            if (!ElevatedDriveConsent.IsApproved(sid, letter, grant))
                throw new UnauthorizedAccessException("The saved drive approval is no longer valid.");

            string name = letter + ":";
            using var root = DuplicateRoot(process, rootHandle);
            string target = VerifyMountForOwner(root, name, session, null, OwnerProfile(worker));
            // Pin the normal sign-in's actual letter as well as the volume. The service's
            // own device map cannot identify which volume either user logon sees.
            using var ownerLetter = OpenMatchingLetter(name, target, session, peerLogon);
            var link = CreateLogonLink(name, target, session, elevatedLogon);
            try
            {
                if (!ElevatedDriveConsent.IsApproved(sid, letter, grant))
                    throw new UnauthorizedAccessException("The saved drive approval was revoked.");
                return link;
            }
            catch { link.Dispose(); throw; }
        }
    }

    private static void ValidateAttestation(int pid, long rootHandle)
    {
        if (pid <= 0 || pid == Environment.ProcessId || rootHandle <= 0 ||
            rootHandle > uint.MaxValue || (rootHandle & 3) != 0)
            throw new InvalidDataException("Invalid mount attestation.");
    }

    private static SafeProcessHandle OpenWorker(int pid)
    {
        var process = OpenProcess(0x1040 /* PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE */, false, pid);
        try
        {
            if (process.IsInvalid) throw Error("Cannot verify the client worker.");
            var image = new StringBuilder(32768);
            int length = image.Capacity;
            if (!QueryFullProcessImageNameW(process, 0, image, ref length) ||
                !string.Equals(image.ToString(), Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("The source drive must belong to this BijouShare installation.");
            return process;
        }
        catch { process.Dispose(); throw; }
    }

    private static SafeFileHandle DuplicateRoot(SafeProcessHandle process, long rootHandle)
    {
        if (DuplicateHandle(process, (nint)rootHandle, GetCurrentProcess(), out var root,
                0x80 /* FILE_READ_ATTRIBUTES */, false, 0))
            return root;
        var error = Error("The original mounted drive is no longer available.");
        root?.Dispose();
        throw error;
    }

    private static string OwnerProfile(SafeAccessTokenHandle token)
    {
        var home = new StringBuilder(32768);
        int length = home.Capacity;
        if (!GetUserProfileDirectoryW(token, home, ref length)) throw Error("Cannot identify the drive owner's Windows profile.");
        return Path.Combine(home.ToString(), ".bijoushare");
    }

    private static string VerifiedRoot(SafeFileHandle root, string mount, int session) =>
        VerifyMount(root, mount, session, null);

    // The worker supplies its own mount directory. The elevated helper accepts only a driver-reported
    // slot in the linked owner's real profile and never receives a directory or a link target from IPC.
    private static string VerifyMount(SafeFileHandle root, string mount, int session, string? workerDirectory)
        => VerifyMountForOwner(root, mount, session, workerDirectory, UserProfileStorage.ProfileDirectory);

    private static string VerifyMountForOwner(SafeFileHandle root, string mount, int session, string? workerDirectory,
        string ownerProfile)
    {
        var path = new StringBuilder(512);
        var count = GetFinalPathNameByHandleW(root, path, path.Capacity, 0x0a /* VOLUME_NAME_NT | FILE_NAME_OPENED */);
        if (count == 0 || count >= path.Capacity) throw Error("Cannot identify the worker's mounted root.");
        var target = path.ToString().TrimEnd('\\');
        const string prefix = @"\Device\Volume";
        if (!target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            target.Length != prefix.Length + 38 || !Guid.TryParseExact(target.AsSpan(prefix.Length), "B", out _))
            throw new IOException("The root handle does not identify a Dokan volume.");
        var entries = DokanGetMountPointList(false, out var total);
        if (entries == 0) throw new IOException("Cannot find the active Dokan mount.");
        try
        {
            var stride = Marshal.SizeOf<MountInfo>();
            for (var i = 0; i < total && i < 65536; ++i)
            {
                var entry = Marshal.PtrToStructure<MountInfo>(entries + i * stride);
                // Dokan 2 sys/public.h: FILE_DEVICE_DISK_FILE_SYSTEM (8), CURRENT_SESSION (16), MOUNT_MANAGER (8).
                if (entry.Session != session || entry.Type != 8 ||
                    !string.Equals(entry.DeviceName, target, StringComparison.OrdinalIgnoreCase))
                    continue;
                const string dosDevices = @"\DosDevices\";
                if (workerDirectory is null && (entry.Options & 24) == 16 &&
                    string.Equals(entry.MountPoint, dosDevices + mount[..2], StringComparison.OrdinalIgnoreCase))
                    return target;
                if ((entry.Options & 24) != 24 || !entry.MountPoint.StartsWith(dosDevices, StringComparison.OrdinalIgnoreCase))
                    continue;
                var directory = entry.MountPoint[dosDevices.Length..].TrimEnd('\\');
                if (workerDirectory is not null
                    ? !directory.Equals(workerDirectory, StringComparison.OrdinalIgnoreCase)
                    : !IsOwnerMountSlot(directory, mount[0], ownerProfile))
                    continue;
                VerifyVolumePaths(root, directory);
                return target;
            }
        }
        finally { DokanReleaseMountPointList(entries); }
        throw new IOException("This drive no longer matches its original Dokan mount.");
    }

    private static bool IsOwnerMountSlot(string directory, char letter, string ownerProfile)
    {
        var slot = Path.GetFileName(directory);
        return slot.Length == 34 && slot[0] == letter && slot[1] == '-' &&
            Guid.TryParseExact(slot.AsSpan(2), "N", out _) &&
            string.Equals(Path.GetDirectoryName(directory), Path.Combine(ownerProfile, PrivateMountDirectory.ContainerName),
                StringComparison.OrdinalIgnoreCase);
    }

    private static void VerifyVolumePaths(SafeFileHandle root, string directory)
    {
        const string prefix = @"\\?\Volume";
        var guidPath = new StringBuilder(64);
        var count = GetFinalPathNameByHandleW(root, guidPath, guidPath.Capacity, 9 /* VOLUME_NAME_GUID | FILE_NAME_OPENED */);
        if (count == 0 || count >= guidPath.Capacity) throw Error("Windows could not identify the drive's volume GUID.");
        var name = guidPath.ToString();
        if (name.Length != prefix.Length + 39 || !name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            name[^1] != '\\' || !Guid.TryParseExact(name.AsSpan(prefix.Length, 38), "B", out _))
            throw new IOException("The private mount does not resolve to a registered volume root.");
        // This API includes Mount Manager's global drive letters even when a local alias shadows one.
        var paths = new char[1024];
        if (!GetVolumePathNamesForVolumeNameW(name, paths, paths.Length, out var size))
        {
            if (Marshal.GetLastPInvokeError() != 234 /* ERROR_MORE_DATA */ || size <= paths.Length || size > 32768)
                throw Error("Cannot verify the drive's registered mount points.");
            paths = new char[size];
            if (!GetVolumePathNamesForVolumeNameW(name, paths, paths.Length, out size))
                throw Error("Cannot verify the drive's registered mount points.");
        }
        var names = new string(paths, 0, checked((int)size)).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        if (names.Length != 1 || !string.Equals(Path.TrimEndingDirectorySeparator(names[0]), directory,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("The drive must have only its private directory registered with Windows.");
    }

    // A named NT object without OBJ_PERMANENT is deleted when the last handle closes, including on process exit.
    // An explicit per-logon directory prevents falling back to the global device map. No OBJ_OPENIF or replacement.
    private static SafeFileHandle CreateTemporaryLink(string name, string target, int session, long logon)
    {
        var existing = new StringBuilder(1024);
        if (QueryDosDeviceW(name, existing, existing.Capacity) != 0 || Marshal.GetLastPInvokeError() != 2 /* FILE_NOT_FOUND */)
            throw new DriveLetterInUseException(name);
        var link = CreateLogonLink(name, target, session, logon);
        try
        {
            if (QueryDosDeviceW(name, existing, existing.Capacity) == 0 ||
                !string.Equals(existing.ToString(), target, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Windows did not resolve the temporary drive letter to this mount.");
            return link;
        }
        catch { link.Dispose(); throw; }
    }

    private static SafeFileHandle OpenMatchingLetter(string name, string target, int session, long logon)
    {
        using var directory = OpenLocalDeviceDirectory(session, logon, create: false);
        using var linkName = new NativeString(name);
        var attributes = Attributes(linkName, directory.DangerousGetHandle());
        var status = NtOpenSymbolicLinkObject(out var link, 1 /* SYMBOLIC_LINK_QUERY */, ref attributes);
        GC.KeepAlive(directory);
        try
        {
            if (status < 0) throw NtError("Cannot identify the drive letter in its owner's sign-in.", status);
            using var output = new NativeString(new string('\0', target.Length + 1));
            output.Value.Length = 0;
            status = NtQuerySymbolicLinkObject(link, ref output.Value, out _);
            if (status < 0 || output.Value.Length != target.Length * sizeof(char) ||
                !string.Equals(Marshal.PtrToStringUni(output.Value.Buffer, target.Length), target, StringComparison.OrdinalIgnoreCase))
                throw new IOException("The owner's drive letter no longer identifies the original mount.");
            return link;
        }
        catch { link.Dispose(); throw; }
    }

    private static SafeFileHandle CreateLogonLink(string name, string target, int session, long logon)
    {
        if (name.Length != 2 || name[0] is < 'A' or > 'Z' || name[1] != ':') throw new ArgumentException("Invalid drive letter.");
        EnsureGlobalLetterIsFree(name);
        using var directory = OpenLocalDeviceDirectory(session, logon, create: true);
        using var linkName = new NativeString(name);
        using var linkTarget = new NativeString(target);
        var attributes = Attributes(linkName, directory.DangerousGetHandle());
        var status = NtCreateSymbolicLinkObject(out var link, 1 /* SYMBOLIC_LINK_QUERY */, ref attributes, ref linkTarget.Value);
        GC.KeepAlive(directory);
        if (status < 0)
        {
            link?.Dispose();
            if (status == unchecked((int)0xc0000035)) throw new DriveLetterInUseException(name);
            throw NtError("Cannot create a drive letter in this Windows logon.", status);
        }
        try
        {
            // A global disk can arrive between the first check and creation of the local link.
            EnsureGlobalLetterIsFree(name);
            return link;
        }
        catch { link.Dispose(); throw; }
    }

    private static void EnsureGlobalLetterIsFree(string name)
    {
        using var globalName = new NativeString(@"\GLOBAL??\" + name);
        var attributes = Attributes(globalName, 0);
        var status = NtOpenSymbolicLinkObject(out var globalLink, 1 /* SYMBOLIC_LINK_QUERY */, ref attributes);
        globalLink?.Dispose();
        if (status == unchecked((int)0xc0000034) /* STATUS_OBJECT_NAME_NOT_FOUND */) return;
        if (status >= 0) throw new DriveLetterInUseException(name);
        throw NtError("Cannot verify that the system drive letter is free.", status);
    }

    private static SafeFileHandle OpenLocalDeviceDirectory(int session, long logon, bool create)
    {
        // Windows stores DOS device directories under Sessions. Some versions use session zero for all logons.
        var luid = $"{(uint)(logon >> 32):x8}-{(uint)logon:x8}";
        foreach (var id in new[] { session, 0 })
        {
            using var name = new NativeString($@"\Sessions\{id}\DosDevices\{luid}");
            var attributes = Attributes(name, 0);
            var status = NtOpenDirectoryObject(out var directory, create ? 6u : 2u /* DIRECTORY_TRAVERSE [+ DIRECTORY_CREATE_OBJECT] */, ref attributes);
            if (status >= 0) return directory;
            directory?.Dispose();
            if (status != unchecked((int)0xc0000034) && status != unchecked((int)0xc000003a))
                throw NtError("Cannot open the user's local drive directory.", status);
        }
        throw new IOException("This Windows logon has no private drive directory.");
    }

    internal static long AuthenticationId(SafeAccessTokenHandle token)
    {
        if (!GetStatistics(token, 10 /* TokenStatistics */, out var statistics, Marshal.SizeOf<TokenStatistics>(), out _))
            throw Error("Cannot identify the Windows logon.");
        return statistics.AuthenticationId;
    }
    private static bool GetTokenInt(SafeAccessTokenHandle token, int kind, out int value) =>
        GetInt(token, kind, out value, sizeof(int), out _);
    private static IOException Error(string message) => new(message, new Win32Exception(Marshal.GetLastPInvokeError()));
    private static IOException NtError(string message, int status) => new(message, new Win32Exception((int)RtlNtStatusToDosError(status)));

    private static ObjectAttributes Attributes(NativeString name, nint root) =>
        new() { Length = Marshal.SizeOf<ObjectAttributes>(), Root = root, Name = name.Pointer, Flags = 64 /* OBJ_CASE_INSENSITIVE */ };

    private sealed class NativeString : IDisposable
    {
        public UnicodeString Value;
        public readonly nint Pointer;
        public NativeString(string value)
        {
            var length = checked((ushort)(value.Length * 2));
            Value = new() { Length = length, MaximumLength = checked((ushort)(length + 2)), Buffer = Marshal.StringToHGlobalUni(value) };
            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(Value, Pointer, false);
        }
        public void Dispose() { Marshal.FreeHGlobal(Pointer); Marshal.FreeHGlobal(Value.Buffer); }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length, MaximumLength; public nint Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes { public int Length; public nint Root, Name; public uint Flags; public nint Security, QualityOfService; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStatistics
    {
        public long TokenId, AuthenticationId, Expiration;
        public int Type, Level;
        public uint Charged, Available, Groups, Privileges;
        public long Modified;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MountInfo
    {
        public uint Type;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string MountPoint;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string UncName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string DeviceName;
        public uint Session, Options;
    }

    [DllImport("ntdll.dll")] private static extern int NtCreateSymbolicLinkObject(out SafeFileHandle handle, uint rights, ref ObjectAttributes name, ref UnicodeString target);
    [DllImport("ntdll.dll")] private static extern int NtOpenSymbolicLinkObject(out SafeFileHandle handle, uint rights, ref ObjectAttributes name);
    [DllImport("ntdll.dll")] private static extern int NtQuerySymbolicLinkObject(SafeFileHandle link, ref UnicodeString target, out uint returnedBytes);
    [DllImport("ntdll.dll")] private static extern int NtOpenDirectoryObject(out SafeFileHandle handle, uint rights, ref ObjectAttributes name);
    [DllImport("ntdll.dll")] private static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string name, StringBuilder buffer, int size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder buffer, int size, uint flags);
    [DllImport("userenv.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetUserProfileDirectoryW(SafeAccessTokenHandle token, StringBuilder directory, ref int length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool GetVolumePathNamesForVolumeNameW(string volume, [Out] char[] paths, int length, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder buffer, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint rights, bool inherit, int pid);
    [DllImport("kernel32.dll")] private static extern nint GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(SafeProcessHandle source, nint handle, nint recipient, out SafeFileHandle copy, uint rights, bool inherit, uint options);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint rights, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    private static extern bool GetStatistics(SafeAccessTokenHandle token, int kind, out TokenStatistics value, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    private static extern bool GetLinkedToken(SafeAccessTokenHandle token, int kind, out nint value, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    private static extern bool GetInt(SafeAccessTokenHandle token, int kind, out int value, int size, out int needed);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("dokan2.dll", ExactSpelling = true)] private static extern nint DokanGetMountPointList(bool uncOnly, out uint count);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("dokan2.dll", ExactSpelling = true)] private static extern void DokanReleaseMountPointList(nint entries);
}
