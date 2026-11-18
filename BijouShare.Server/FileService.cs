using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BijouShare.Shared;

namespace BijouShare.Server;

// Only the administrator audit receives this explanation. The file protocol still returns AccessDenied.
internal sealed class FileAccessDenial(string detail, Exception? inner = null) : UnauthorizedAccessException(detail, inner);
internal sealed class FileSharingConflict(string detail) : IOException(detail);

public sealed class FileService(StateStore store, AuditLog audit) : IDisposable
{
    internal static string StorageAccount { get; } = GetStorageAccount();
    private static string GetStorageAccount()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        try { return identity.Name; }
        catch (System.Security.Principal.IdentityNotMappedException) { return identity.User!.Value; }
    }
    private readonly ReaderWriterLockSlim gate = new();
    private long prunedRevision = -1;
    private readonly ConcurrentDictionary<(Guid principal, Guid Share, string Path), Permission> permissions = new();
    private int permissionCacheMisses;
    private readonly ConcurrentDictionary<Guid, string> shareRoots = new();
    private readonly string[] protectedRoots = ProtectedRoots(store.DataDirectory);
    internal static string[] ProtectedRoots(string dataDirectory)
    {
        var programData = WindowsPaths.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        // Older installations can still have private identities in their original ProgramData tree.
        return [WindowsPaths.Canonical(dataDirectory), WindowsPaths.Canonical(AppContext.BaseDirectory),
            Path.Combine(programData, "BijouShare"), Path.Combine(programData, "NetworkDrive")];
    }
    private readonly Dictionary<Guid, OpenHandle> handles = [];
    private readonly List<RangeLock> ranges = [];
    private readonly Dictionary<(Guid Session, Guid Handle, string Path), DirectoryCursor> directoryCursors = [];
    private sealed class DirectoryCursor(string path) : IDisposable
    {
        public IEnumerator<FileSystemInfo> Iterator { get; } = new DirectoryInfo(path).EnumerateFileSystemInfos().GetEnumerator();
        public long Position;
        public bool Pending;
        public void Dispose() => Iterator.Dispose();
    }
    private sealed record Location(ExportShare Share, string Relative, string Physical);
    private sealed class OpenHandle(Guid id, Guid session, Device identity, Location location, uint access,
        FileShare share, FileStream? stream, bool directory, bool appendOnly)
    {
        public Guid Id { get; } = id;
        public Guid Session { get; } = session;
        public Device Identity { get; } = identity;
        public Location Location { get; set; } = location;
        public uint Access { get; } = access;
        public FileShare Share { get; } = share;
        public FileShare SharingAccess { get; } = GetSharingAccess(access);
        public bool ReservesSharing => !Cleaned && SharingAccess != FileShare.None;
        public bool DeniesDeleteSharing => ReservesSharing && !Share.HasFlag(FileShare.Delete);
        public FileStream? Stream { get; } = stream;
        public bool Directory { get; } = directory;
        public bool AppendOnly { get; } = appendOnly;
        public bool Cleaned
        {
            get; set;
        }
        public bool Writer => !Directory && AccessMask.Writes(Access);
        public object WriteGate { get; } = new();
    }
    private sealed record RangeLock(Guid Handle, string Physical, long Offset, long Length);
    private sealed record PolicyScope(ExportShare Share, string Root);
    private static readonly DateTime VolumeTime = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static RemoteEntry Root => new("", FileAttributes.Directory, 0, VolumeTime, VolumeTime, VolumeTime,
        Permission.ListDirectory | Permission.ReadAttributes | Permission.ReadPermissions);

    public RpcResponse Execute(Guid session, Guid deviceId, RpcRequest request, Device? authenticatedDevice = null)
    {
        // Read/data requests run concurrently; mutations and policy invalidation remain exclusive.
        if (request.Operation is "Read" or "Write" or "Flush" or "Stat" or "Ping" or "Security" or "Space")
        {
            gate.EnterReadLock();
            try
            {
                var response = store.Read(_ => prunedRevision == store.Revision
                    ? ExecuteLocked(session, deviceId, request, authenticatedDevice) : null);
                if (response is not null)
                    return response;
            }
            finally { gate.ExitReadLock(); }
        }
        gate.EnterWriteLock();
        try
        {
            return store.Read(_ =>
            {
                var changed = prunedRevision != store.Revision;
                if (changed)
                {
                    permissions.Clear();
                    shareRoots.Clear();
                    ClearDirectoryCursors();
                    PruneRevokedHandles(request.Handle);
                }
                try
                {
                    return ExecuteLocked(session, deviceId, request, authenticatedDevice);
                }
                finally
                {
                    if (changed)
                    {
                        PruneRevokedHandles(Guid.Empty);
                        prunedRevision = store.Revision;
                    }
                }
            });
        }
        finally { gate.ExitWriteLock(); }
    }
    private RpcResponse ExecuteLocked(Guid session, Guid deviceId, RpcRequest request, Device? authenticatedDevice)
    {
        var device = store.Identity(deviceId);
        var principal = device; // Re-evaluated even on existing handles.
        if (authenticatedDevice is not null && !device.HasSameIdentity(authenticatedDevice))
            throw new UnauthorizedAccessException("The device binding changed. Authenticate again.");
        if (request.Operation == "Ping")
            return new();
        if (request.Operation == "Space")
            return Space(principal);
        if (request.Operation == "Close")
        {
            var h = GetHandle(session, request.Handle);
            try
            {
                if (request.DeleteOnClose)
                    Delete(h.Location, principal, h);
            }
            finally { Release(h); }
            return new();
        }
        if (request.Operation == "Cleanup")
            return Cleanup(GetHandle(session, request.Handle), principal, request.DeleteOnClose);
        if (request.Path is "" or "\\" or "/" && request.Handle == Guid.Empty)
        {
            return request.Operation switch
            {
                "Stat" => new() { Entry = Root, Existed = true },
                "Open" => OpenRoot(request),
                "List" => Page(ListShares(principal), request),
                "Security" => new() { Permissions = Root.Permissions },
                _ => throw new UnauthorizedAccessException()
            };
        }
        var handle = request.Handle != Guid.Empty ? GetHandle(session, request.Handle) : null;
        if (handle is { Cleaned: true } && request.Operation is not ("Read" or "Write" or "Flush" or "Stat" or "Security"))
            throw new RemoteException("InvalidHandle");
        var location = handle?.Location ?? Resolve(request.Path);
        if (handle?.Stream is not null && request.Operation is "Read" or "Write" or "Flush" or "Stat" or "Security")
        {
            CheckShare(location); // An already-open OS handle cannot be redirected by a later path/junction change.
            if (IsClientProfilePath(location.Physical))
                throw new UnauthorizedAccessException();
        }
        else
            CheckLocation(location);
        return request.Operation switch
        {
            "Open" => Open(session, device, principal, location, request),
            "Stat" => new() { Entry = Stat(location, principal, handle) },
            "List" => List(session, location, principal, request),
            "Read" => Read(RequireHandle(handle), principal, request),
            "Write" => Write(RequireHandle(handle), principal, request),
            "Flush" => Flush(RequireHandle(handle)),
            "Resize" => Resize(RequireHandle(handle), principal, request.Length),
            "Allocate" => Allocate(RequireHandle(handle), principal, request.Length),
            "Attributes" => SetAttributes(location, principal, handle, request.Attributes),
            "Times" => SetTimes(location, principal, handle, request),
            "CanDelete" => CanDelete(location, principal, handle),
            "Move" => Move(location, principal, handle, request),
            "Lock" => Lock(RequireHandle(handle), request),
            "Unlock" => Unlock(RequireHandle(handle), request),
            "Security" => Security(location, principal),
            _ => throw new RemoteException("Unsupported")
        };
    }

    private static RpcResponse OpenRoot(RpcRequest request)
    {
        if (!Enum.IsDefined(request.Mode))
            throw new ArgumentException("Invalid open mode.");
        if (request.Mode == FileMode.CreateNew)
            throw new RemoteException("Exists");
        if (request.Mode is not (FileMode.Open or FileMode.OpenOrCreate) ||
            (RequiredAccess(request.Access, true) & ~Root.Permissions) != 0)
            throw new UnauthorizedAccessException("The virtual root is read-only.");
        return new()
        {
            Entry = Root,
            Existed = true
        };
    }

    private Location Resolve(string virtualPath)
    {
        var path = StateStore.NormalizeRelative(virtualPath);
        var parts = path.Split('/', 2);
        var share = store.Read(s => s.Shares.SingleOrDefault(x => x.Enabled && x.Name.Equals(parts[0], StringComparison.OrdinalIgnoreCase)))
            ?? throw new FileNotFoundException();
        var root = shareRoots.GetOrAdd(share.Id, _ => WindowsPaths.Canonical(share.LocalPath));
        var relative = parts.Length == 2 ? parts[1] : "";
        var physical = WindowsPaths.Canonical(relative.Length == 0 ? root : Path.Combine(root, relative.Replace('/', '\\')));
        if (!Within(physical, root))
            throw new UnauthorizedAccessException();
        var canonicalRelative = relative.Length == 0 ? "" : Path.GetRelativePath(root, physical).Replace('\\', '/');
        return new(share, canonicalRelative, physical);
    }
    private static bool Within(string path, string root) =>
        path.Equals(root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
        path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    internal static bool IsProtectedExportPath(string canonicalPath, string[] protectedRoots)
    {
        if (protectedRoots.Any(root => Within(canonicalPath, root)))
            return true;
        return IsClientProfilePath(canonicalPath);
    }

    private static bool IsClientProfilePath(string path)
    {
        if (path.EndsWith(@"\.bijoushare", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\.bijoushare\", StringComparison.OrdinalIgnoreCase))
            return true;
        const string defaultBase = @"\AppData\Local\BijouShare\Client";
        if (path.EndsWith(defaultBase, StringComparison.OrdinalIgnoreCase) ||
            path.Contains(defaultBase + "\\", StringComparison.OrdinalIgnoreCase))
            return true;

        // Custom profile bases can be on any drive. Only probe SID components:
        // normal shares and their file operations do not need any extra file I/O.
        var offset = 0;
        while ((offset = path.IndexOf(@"\S-1-", offset, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var end = path.IndexOf('\\', offset + 1);
            var directory = end < 0 ? path : path[..end];
            var component = directory.AsSpan(offset + 5);
            if (component.Length != 0 && component.IndexOfAnyExcept("0123456789-") < 0 &&
                (WindowsPaths.TryGetAttributes(Path.Combine(directory, ".instance.lock"), out _) ||
                 WindowsPaths.TryGetAttributes(Path.Combine(directory, "client.json"), out _)))
                return true;
            if (end < 0)
                break;
            offset = end;
        }
        return false;
    }
    private void CheckLocation(Location location)
    {
        CheckShare(location);
        if (IsProtectedExportPath(location.Physical, protectedRoots))
            throw new UnauthorizedAccessException();
        var currentPath = location.Physical;
        while (!string.IsNullOrEmpty(currentPath))
        {
            if (WindowsPaths.TryGetAttributes(currentPath, out var attributes))
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException("Reparse points are not exported.");
            currentPath = Path.GetDirectoryName(currentPath);
        }
    }
    private void CheckShare(Location location)
    {
        var current = store.Read(s => s.Shares.SingleOrDefault(x => x.Id == location.Share.Id && x.Enabled));
        if (current is null || current != location.Share)
            throw new UnauthorizedAccessException();
    }
    private Permission Effective(Location location, Device principal)
    {
        var key = (principal.Id, location.Share.Id, location.Relative);
        if (permissions.TryGetValue(key, out var cached))
            return cached;
        if (Interlocked.Increment(ref permissionCacheMisses) > 8192)
        {
            permissions.Clear();
            Interlocked.Exchange(ref permissionCacheMisses, 0);
        }
        return permissions.GetOrAdd(key, _ => store.Permissions(principal, location.Share.Id, location.Relative));
    }
    private void Demand(Location location, Device principal, Permission permission)
    {
        var missing = permission & ~Effective(location, principal);
        if (missing != Permission.None)
            throw new FileAccessDenial($"Device group permissions do not grant {missing} on {Virtual(location)}.");
    }
    private Location Parent(Location location)
    {
        if (location.Relative.Length == 0)
            throw new UnauthorizedAccessException("Share roots are protected.");
        var index = location.Relative.LastIndexOf('/');
        return Resolve(location.Share.Name + (index < 0 ? "" : "/" + location.Relative[..index]));
    }
    private RemoteEntry Stat(Location location, Device principal, OpenHandle? handle = null)
    {
        Demand(location, principal, Permission.ReadAttributes);
        if (handle?.Stream is { } stream)
        {
            return new(location.Relative.Length == 0 ? location.Share.Name : Path.GetFileName(location.Physical),
                ExportAttributes(location, File.GetAttributes(stream.SafeFileHandle)), stream.Length, File.GetCreationTimeUtc(stream.SafeFileHandle),
                File.GetLastAccessTimeUtc(stream.SafeFileHandle), File.GetLastWriteTimeUtc(stream.SafeFileHandle), Effective(location, principal));
        }
        FileSystemInfo item = Directory.Exists(location.Physical) ? new DirectoryInfo(location.Physical) : new FileInfo(location.Physical);
        if (!item.Exists)
            throw new FileNotFoundException();
        return new(location.Relative.Length == 0 ? location.Share.Name : item.Name, ExportAttributes(location, item.Attributes),
            item is FileInfo file ? file.Length : 0, item.CreationTimeUtc, item.LastAccessTimeUtc, item.LastWriteTimeUtc,
            Effective(location, principal));
    }
    private static FileAttributes ExportAttributes(Location location, FileAttributes attributes)
    {
        // Drive roots are normally Hidden|System on Windows. An explicitly named export is a
        // visible entry in our virtual namespace, independent of those physical root flags.
        if (location.Relative.Length == 0)
        {
            attributes &= ~(FileAttributes.Hidden | FileAttributes.System);
            if (attributes == 0)
                attributes = FileAttributes.Normal;
        }
        return attributes;
    }
    private List<RemoteEntry> ListShares(Device principal)
    {
        var entries = new List<RemoteEntry>();
        foreach (var share in store.Read(s => s.Shares.Where(x => x.Enabled).ToArray()))
        {
            try
            {
                var location = Resolve(share.Name);
                CheckLocation(location);
                entries.Add(Stat(location, principal));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { }
        }
        return entries;
    }
    private static RpcResponse Page(List<RemoteEntry> entries, RpcRequest r)
    {
        if (r.Offset is < 0 or > int.MaxValue || r.Count is < 0 or > 256)
            throw new ArgumentException("Invalid page.");
        var count = r.Count == 0 ? 256 : r.Count;
        var page = entries.Skip((int)r.Offset).Take(count).ToList();
        return new()
        {
            Entries = page,
            Length = r.Offset + page.Count,
            More = r.Offset + page.Count < entries.Count
        };
    }
    private RpcResponse List(Guid session, Location location, Device principal, RpcRequest request)
    {
        Demand(location, principal, Permission.ListDirectory);
        if (!Directory.Exists(location.Physical))
            throw new RemoteException("NotADirectory");
        if (request.Offset is < 0 or > int.MaxValue || request.Count is < 0 or > 256)
            throw new ArgumentException("Invalid page.");
        var count = request.Count == 0 ? 256 : request.Count;
        var result = new List<RemoteEntry>();
        var key = (session, request.Handle, location.Physical);
        if (!directoryCursors.TryGetValue(key, out var cursor) || cursor.Position != request.Offset || request.Offset == 0)
        {
            if (cursor is not null)
            {
                cursor.Dispose();
                directoryCursors.Remove(key);
            }
            if (directoryCursors.Count >= 256)
            {
                var oldest = directoryCursors.First();
                oldest.Value.Dispose();
                directoryCursors.Remove(oldest.Key);
            }
            cursor = new DirectoryCursor(location.Physical);
            directoryCursors[key] = cursor;
            while (cursor.Position < request.Offset && cursor.Iterator.MoveNext())
                cursor.Position++;
        }
        var examined = 0;
        while (examined < count && (cursor.Pending || cursor.Iterator.MoveNext()))
        {
            cursor.Pending = false;
            var entry = cursor.Iterator.Current;
            examined++;
            cursor.Position++;
            try
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                    continue;
                StateStore.NormalizeRelative(entry.Name);
                var child = new Location(location.Share, (location.Relative.Length == 0 ? "" : location.Relative + "/") + entry.Name,
                    Path.Combine(location.Physical, entry.Name));
                if (IsProtectedExportPath(child.Physical, protectedRoots))
                    continue;
                Demand(child, principal, Permission.ReadAttributes);
                // FindFirst/FindNext already returns these fields. Reopening/stat-ing every child
                // discards that metadata and turns one directory page into thousands of system calls.
                result.Add(new(entry.Name, entry.Attributes, entry is FileInfo file ? file.Length : 0,
                    entry.CreationTimeUtc, entry.LastAccessTimeUtc, entry.LastWriteTimeUtc, Effective(child, principal)));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or ArgumentException) { }
        }
        var more = cursor.Iterator.MoveNext();
        cursor.Pending = more;
        if (!more)
        {
            cursor.Dispose();
            directoryCursors.Remove(key);
        }
        return new()
        {
            Entries = result,
            Length = request.Offset + examined,
            More = more
        };
    }
    private static Permission RequiredAccess(uint access, bool directory)
    {
        if ((access & (AccessMask.WriteDac | AccessMask.WriteOwner)) != 0)
            throw new UnauthorizedAccessException("Use the administration UI for group permissions.");
        var permission = Permission.None;
        if (AccessMask.Reads(access))
            permission |= directory ? Permission.ListDirectory : Permission.ReadData;
        if (directory)
        {
            if ((access & (AccessMask.WriteData | AccessMask.GenericWrite | AccessMask.GenericAll)) != 0)
                permission |= Permission.CreateFiles;
            if ((access & (AccessMask.AppendData | AccessMask.GenericWrite | AccessMask.GenericAll)) != 0)
                permission |= Permission.CreateDirectories;
            if ((access & AccessMask.DeleteChild) != 0)
                permission |= Permission.Delete;
        }
        else if (AccessMask.Writes(access))
            permission |= Permission.WriteData;
        if (AccessMask.Deletes(access))
            permission |= Permission.Delete;
        if ((access & (AccessMask.ReadAttributes | AccessMask.ReadEa | AccessMask.GenericRead | AccessMask.GenericAll)) != 0)
            permission |= Permission.ReadAttributes;
        if ((access & (AccessMask.WriteAttributes | AccessMask.WriteEa | AccessMask.GenericWrite | AccessMask.GenericAll)) != 0)
            permission |= Permission.WriteAttributes;
        if ((access & (AccessMask.ReadControl | AccessMask.GenericRead | AccessMask.GenericAll)) != 0)
            permission |= Permission.ReadPermissions;
        if (access == 0)
            permission = Permission.ReadAttributes;
        return permission;
    }
    private void DemandHandleAccess(Location location, Device principal, uint access, bool directory)
    {
        var required = RequiredAccess(access, directory);
        // Windows requests DELETE access for both renaming and deleting. The final operation still
        // demands its exact server permission; admitting the handle must not make Rename depend on Delete.
        if (AccessMask.Deletes(access) && (Effective(location, principal) & Permission.Rename) != 0)
            required &= ~Permission.Delete;
        Demand(location, principal, required);
    }
    private RpcResponse Open(Guid session, Device identity, Device principal, Location location, RpcRequest request)
    {
        if (handles.Count >= 4096 || handles.Values.Count(x => x.Session == session) >= 512)
            throw new RemoteException("TooManyOpenFiles");
        if (!Enum.IsDefined(request.Mode) || (request.Share & ~(FileShare.ReadWrite | FileShare.Delete)) != 0)
            throw new ArgumentException("Invalid open flags.");
        var directory = Directory.Exists(location.Physical);
        var existed = directory || File.Exists(location.Physical);
        if (existed && request.Mode == FileMode.CreateNew)
            throw new RemoteException("Exists");
        if (!existed && request.Mode is FileMode.Open or FileMode.Truncate)
            throw new FileNotFoundException();
        if (request.Directory && existed && !directory)
            throw new RemoteException("NotADirectory");
        directory |= request.Directory;
        DemandHandleAccess(location, principal, request.Access, directory);
        var write = AccessMask.Writes(request.Access);
        if (!directory && !write &&
            (request.Mode is FileMode.Truncate or FileMode.Append || existed && request.Mode == FileMode.Create))
            throw new UnauthorizedAccessException();
        if (!existed)
        {
            var parent = Parent(location);
            Demand(parent, principal, directory ? Permission.CreateDirectories : Permission.CreateFiles);
            if (!Directory.Exists(parent.Physical))
                throw new DirectoryNotFoundException();
            ValidateAttributes(request.Attributes);
        }
        if (directory && existed && request.Mode is FileMode.Create or FileMode.Truncate or FileMode.Append)
            throw new UnauthorizedAccessException();
        CheckSharing(location.Physical, request.Access, request.Share, directory);
        FileStream? stream = null;
        try
        {
            if (directory)
            {
                if (!existed)
                    Directory.CreateDirectory(location.Physical);
            }
            else if (!existed && !write)
            {
                // Adding a new directory entry is a parent right. The resulting handle can
                // be metadata-only or read-only, even if the device may never write file data.
                stream = CreateWithoutWriteAccess(location.Physical, AccessMask.Reads(request.Access), request.Attributes);
            }
            else if (AccessMask.Reads(request.Access) || write)
            {
                var access = AccessMask.Reads(request.Access) ? (write ? FileAccess.ReadWrite : FileAccess.Read) : FileAccess.Write;
                // The registry enforces each caller's FILE_SHARE flags. Physical sharing also excludes external writers.
                var mode = !existed ? FileMode.CreateNew : request.Mode switch
                {
                    FileMode.Append or FileMode.OpenOrCreate => FileMode.Open,
                    FileMode.Create => FileMode.Truncate,
                    _ => request.Mode
                };
                stream = new FileStream(location.Physical, mode, access,
                    write ? FileShare.Read | FileShare.Delete : FileShare.ReadWrite | FileShare.Delete, 4096,
                    FileOptions.RandomAccess | (request.WriteThrough ? FileOptions.WriteThrough : FileOptions.None));
            }
            if (!existed && (directory || write) && request.Attributes != 0)
            {
                ApplyAttributes(location, request.Attributes);
            }
            if (!existed)
                ClearDirectoryCursors();
            var id = Guid.NewGuid();
            var handle = new OpenHandle(id, session, identity, location, request.Access, request.Share, stream, directory,
                request.Mode == FileMode.Append || AccessMask.AppendOnly(request.Access));
            // Opening requires only requested rights; it must not silently require ReadAttributes as well.
            var attributes = ExportAttributes(location, File.GetAttributes(location.Physical));
            var info = new RemoteEntry(Path.GetFileName(location.Physical), attributes, stream?.Length ?? 0,
                VolumeTime, VolumeTime, VolumeTime, Effective(location, principal));
            audit.WriteFrequent(principal.Name, "Open", Virtual(location));
            handles.Add(id, handle);
            stream = null; // The registered handle now owns the stream.
            return new()
            {
                Handle = id,
                Entry = info,
                Existed = existed
            };
        }
        catch (UnauthorizedAccessException ex) when (ex is not FileAccessDenial)
        {
            var operation = existed ? "opening the item" : directory ? "creating the folder" : "creating the file";
            throw new FileAccessDenial($"Windows denied storage access for {StorageAccount} while {operation}. Check the NTFS permissions on the item and its parent.", ex);
        }
        finally { stream?.Dispose(); }
    }

    private static FileStream? CreateWithoutWriteAccess(string path, bool read, FileAttributes attributes)
    {
        // FileStream requires write access for CreateNew. CREATE_NEW on Windows can instead
        // acquire just the requested read access and still guarantees an atomic collision check.
        var handle = CreateFileNative(@"\\?\" + path, read ? AccessMask.GenericRead : 0u,
            FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, FileMode.CreateNew,
            (uint)FileOptions.RandomAccess | (uint)(attributes & SettableAttributes), IntPtr.Zero);
        try
        {
            if (handle.IsInvalid)
            {
                var hr = Marshal.GetHRForLastWin32Error();
                var error = Marshal.GetExceptionForHR(hr)!;
                throw error is COMException ? new IOException(error.Message, hr) : error;
            }
            if (read)
                return new FileStream(handle, FileAccess.Read);
        }
        catch { handle.Dispose(); throw; }
        handle.Dispose();
        return null;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileNative(string path, uint access, FileShare share, IntPtr security,
        FileMode mode, uint flags, IntPtr template);

    private static FileShare GetSharingAccess(uint access)
    {
        var required = FileShare.None;
        if (AccessMask.Reads(access)) required |= FileShare.Read;
        if (AccessMask.Writes(access)) required |= FileShare.Write;
        if (AccessMask.Deletes(access)) required |= FileShare.Delete;
        return required;
    }

    private static FileSharingConflict SharingConflict(OpenHandle holder, string reason) =>
        new($"{reason} Device '{holder.Identity.Name}' has '{Virtual(holder.Location)}' open (access 0x{holder.Access:X8}, sharing {holder.Share}).");

    private void CheckSharing(string path, uint access, FileShare share, bool directory)
    {
        // Attribute, security and synchronize-only opens do not participate in Windows share-mode checks.
        var required = GetSharingAccess(access);
        if (required == FileShare.None)
            return;
        foreach (var h in handles.Values.Where(x => x.Location.Physical.Equals(path, StringComparison.OrdinalIgnoreCase)))
        {
            if (!directory && AccessMask.Writes(access) && h.Writer)
                throw SharingConflict(h, "A writable file handle is already open.");
            if (h.ReservesSharing && ((required & ~h.Share) != 0 || (h.SharingAccess & ~share) != 0))
                throw SharingConflict(h, $"Requested access 0x{access:X8} with sharing {share} conflicts with an open handle.");
        }
    }
    private OpenHandle GetHandle(Guid session, Guid id) => handles.TryGetValue(id, out var h) && h.Session == session
        ? h : throw new RemoteException("InvalidHandle");
    private static OpenHandle RequireHandle(OpenHandle? h) => h ?? throw new RemoteException("InvalidHandle");
    private static void Bounds(long offset, long length)
    {
        if (offset < 0 || length < 0 || offset > long.MaxValue - length)
            throw new ArgumentException("Invalid range.");
    }
    private void CheckRanges(OpenHandle h, long offset, long length)
    {
        Bounds(offset, length);
        if (length == 0)
            return;
        if (ranges.Any(x => x.Handle != h.Id && x.Physical.Equals(h.Location.Physical, StringComparison.OrdinalIgnoreCase) &&
            offset < x.Offset + x.Length && x.Offset < offset + length))
            throw new RemoteException("LockViolation");
    }
    private RpcResponse Read(OpenHandle h, Device principal, RpcRequest request)
    {
        if (h.Cleaned && !request.PagingIo)
            throw new RemoteException("InvalidHandle");
        Demand(h.Location, principal, Permission.ReadData);
        if (h.Stream is null || !AccessMask.Reads(h.Access))
            throw new UnauthorizedAccessException();
        if (request.Count is < 0 or > Wire.MaxChunk)
            throw new ArgumentException("Invalid read size.");
        CheckRanges(h, request.Offset, request.Count);
        var borrowed = request.BorrowReadBuffer && request.Count != 0;
        var buffer = borrowed ? ArrayPool<byte>.Shared.Rent(request.Count) : new byte[request.Count];
        try
        {
            var count = RandomAccess.Read(h.Stream.SafeFileHandle, buffer.AsSpan(0, request.Count), request.Offset);
            if (borrowed)
                return new()
                {
                    Data = buffer,
                    BorrowedCount = count,
                    OwnsData = true
                };
            if (count != buffer.Length)
                Array.Resize(ref buffer, count);
            return new()
            {
                Data = buffer
            };
        }
        catch { if (borrowed) ArrayPool<byte>.Shared.Return(buffer, clearArray: true); throw; }
    }
    private RpcResponse Write(OpenHandle h, Device principal, RpcRequest request)
    {
        lock (h.WriteGate)
            return WriteLocked(h, principal, request);
    }
    private RpcResponse WriteLocked(OpenHandle h, Device principal, RpcRequest request)
    {
        if (h.Cleaned && !request.PagingIo)
            throw new RemoteException("InvalidHandle");
        Demand(h.Location, principal, Permission.WriteData);
        if (!h.Writer || h.Stream is null)
            throw new UnauthorizedAccessException();
        if (request.Data is null || request.DataCount > Wire.MaxChunk)
            throw new ArgumentException("Invalid write size.");
        var offset = request.Append || h.AppendOnly ? h.Stream.Length : request.Offset;
        Bounds(offset, request.DataCount);
        var count = request.PagingIo ? (int)Math.Min(request.DataCount, Math.Max(0, h.Stream.Length - offset)) : request.DataCount;
        CheckRanges(h, offset, count);
        if (count == 0)
            return new()
            {
                Length = 0
            };
        RandomAccess.Write(h.Stream.SafeFileHandle, request.Data.AsSpan(request.DataOffset, count), offset);
        if (request.WriteThrough)
            h.Stream.Flush(true);
        audit.WriteFrequent(principal.Name, "Write", Virtual(h.Location));
        return new()
        {
            Length = count
        };
    }
    private static RpcResponse Flush(OpenHandle h)
    {
        h.Stream?.Flush(true);
        return new();
    }
    private RpcResponse Resize(OpenHandle h, Device principal, long length)
    {
        Demand(h.Location, principal, Permission.WriteData);
        if (!h.Writer || h.Stream is null || h.AppendOnly)
            throw new UnauthorizedAccessException();
        Bounds(0, length);
        CheckRanges(h, Math.Min(length, h.Stream.Length), Math.Abs(length - h.Stream.Length));
        h.Stream.SetLength(length);
        audit.Write(principal.Name, "Resize", Virtual(h.Location));
        return new();
    }
    private RpcResponse Allocate(OpenHandle h, Device principal, long length)
    {
        Demand(h.Location, principal, Permission.WriteData);
        if (!h.Writer || h.Stream is null)
            throw new UnauthorizedAccessException();
        Bounds(0, length);
        return length < h.Stream.Length ? Resize(h, principal, length) : new();
    }
    private RpcResponse Cleanup(OpenHandle h, Device principal, bool delete)
    {
        if (h.Cleaned)
            return new();
        try
        {
            if (delete)
                Delete(h.Location, principal, h);
        }
        finally
        {
            h.Cleaned = true;
            ranges.RemoveAll(range => range.Handle == h.Id);
        }
        return new();
    }
    private void Mutation(Location location, OpenHandle? handle)
    {
        var writer = handles.Values.FirstOrDefault(x => x.Id != handle?.Id && x.Writer && x.Location.Physical.Equals(location.Physical, StringComparison.OrdinalIgnoreCase));
        if (writer is not null)
            throw SharingConflict(writer, "A writable file handle is still open.");
    }
    private void MetadataMutation(Location location, Device principal, OpenHandle? h)
    {
        Demand(location, principal, Permission.WriteAttributes);
        if (h is not null && (h.Access & (AccessMask.WriteAttributes | AccessMask.GenericWrite | AccessMask.GenericAll)) == 0)
            throw new UnauthorizedAccessException();
        Mutation(location, h);
    }
    private const FileAttributes SettableAttributes = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System |
        FileAttributes.Archive | FileAttributes.Temporary | FileAttributes.NotContentIndexed;

    private static void ValidateAttributes(FileAttributes attributes)
    {
        if ((attributes & ~(SettableAttributes | FileAttributes.Normal | FileAttributes.Directory)) != 0)
            throw new RemoteException("Unsupported");
    }
    private static void ApplyAttributes(Location location, FileAttributes attributes)
    {
        ValidateAttributes(attributes);
        var directory = Directory.Exists(location.Physical);
        File.SetAttributes(location.Physical, (attributes & SettableAttributes) |
            (directory ? FileAttributes.Directory : 0));
    }
    private RpcResponse SetAttributes(Location location, Device principal, OpenHandle? h, FileAttributes attributes)
    {
        MetadataMutation(location, principal, h);
        ApplyAttributes(location, attributes);
        audit.Write(principal.Name, "Attributes", Virtual(location));
        return new();
    }
    private RpcResponse SetTimes(Location location, Device principal, OpenHandle? h, RpcRequest r)
    {
        MetadataMutation(location, principal, h);
        if (r.CreationTime is { } creation)
            File.SetCreationTimeUtc(location.Physical, creation.ToUniversalTime());
        if (r.LastAccessTime is { } access)
            File.SetLastAccessTimeUtc(location.Physical, access.ToUniversalTime());
        if (r.LastWriteTime is { } write)
            File.SetLastWriteTimeUtc(location.Physical, write.ToUniversalTime());
        audit.Write(principal.Name, "Times", Virtual(location));
        return new();
    }
    private RpcResponse CanDelete(Location location, Device principal, OpenHandle? h)
    {
        if (location.Relative.Length == 0)
            throw new UnauthorizedAccessException();
        Demand(location, principal, Permission.Delete);
        if (h is not null && !AccessMask.Deletes(h.Access))
            throw new UnauthorizedAccessException();
        Mutation(location, h);
        foreach (var other in handles.Values.Where(x => x.Id != h?.Id && Within(x.Location.Physical, location.Physical)))
            if (other.DeniesDeleteSharing)
                throw SharingConflict(other, "An open handle prevents deletion.");
        if (Directory.Exists(location.Physical) && Directory.EnumerateFileSystemEntries(location.Physical).Any())
            throw new RemoteException("NotEmpty");
        if ((File.GetAttributes(location.Physical) & FileAttributes.ReadOnly) != 0)
            throw new UnauthorizedAccessException();
        return new();
    }
    private void Delete(Location location, Device principal, OpenHandle h)
    {
        CheckLocation(location);
        CanDelete(location, principal, h);
        if (h.Directory)
            Directory.Delete(location.Physical);
        else
            File.Delete(location.Physical);
        ClearDirectoryCursors();
        audit.Write(principal.Name, "Delete", Virtual(location));
    }
    private RpcResponse Move(Location source, Device principal, OpenHandle? h, RpcRequest request)
    {
        var destination = Resolve(request.Destination ?? throw new ArgumentException("Missing destination."));
        var requestedLeaf = StateStore.NormalizeRelative(request.Destination).Split('/')[^1];
        if (source.Physical.Equals(destination.Physical, StringComparison.OrdinalIgnoreCase) &&
            requestedLeaf.Equals(Path.GetFileName(source.Physical), StringComparison.OrdinalIgnoreCase))
        {
            // Authorization uses canonical names, but a case-only rename must retain the requested spelling.
            destination = destination with
            {
                Physical = Path.Combine(Path.GetDirectoryName(destination.Physical)!, requestedLeaf),
                Relative = destination.Relative[..(destination.Relative.LastIndexOf('/') + 1)] + requestedLeaf
            };
        }
        CheckLocation(destination);
        if (source.Relative.Length == 0 || destination.Relative.Length == 0 || source.Share.Id != destination.Share.Id)
            throw new UnauthorizedAccessException("Share roots and cross-share renames are protected.");
        Demand(source, principal, Permission.Rename | Permission.ReadAttributes);
        var directory = Directory.Exists(source.Physical);
        Demand(Parent(destination), principal, directory ? Permission.CreateDirectories : Permission.CreateFiles);
        if (directory && Within(destination.Physical, source.Physical) &&
            !destination.Physical.Equals(source.Physical, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid destination.");
        Mutation(source, h);
        Mutation(destination, source.Physical.Equals(destination.Physical, StringComparison.OrdinalIgnoreCase) ? h : null);
        foreach (var other in handles.Values.Where(x => x.Id != h?.Id &&
            (Within(x.Location.Physical, source.Physical) || x.Location.Physical.Equals(destination.Physical, StringComparison.OrdinalIgnoreCase))))
            if (other.DeniesDeleteSharing || other.Writer)
                throw SharingConflict(other, "An open handle prevents the rename.");
        // A directory rename must not move unreadable descendants into a more permissive path.
        var scopes = store.Read(s => s.Shares.Where(x => x.Enabled &&
                string.Equals(Path.GetPathRoot(x.LocalPath), Path.GetPathRoot(source.Physical), StringComparison.OrdinalIgnoreCase))
            .Select(x => new PolicyScope(x, WindowsPaths.Canonical(x.LocalPath))).ToArray());
        VerifyMoveTree(source, destination, source, principal, scopes);
        var same = source.Physical.Equals(destination.Physical, StringComparison.OrdinalIgnoreCase);
        if (!same && (File.Exists(destination.Physical) || Directory.Exists(destination.Physical)))
        {
            if (!request.Replace)
                throw new RemoteException("Exists");
            if (directory || Directory.Exists(destination.Physical))
                throw new RemoteException("IsDirectory");
            Demand(destination, principal, Permission.Delete | Permission.WriteData);
        }
        try
        {
            if (directory)
                Directory.Move(source.Physical, destination.Physical);
            else
                File.Move(source.Physical, destination.Physical, request.Replace);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException && (ex.HResult & 0xffff) == 5)
        {
            // Windows can also refuse a directory move while a file inside it is open.
            throw new FileAccessDenial($"Windows denied the rename on backing storage for {StorageAccount}. Check for open files and verify permissions on the source and destination folders.", ex);
        }
        // Enumerators are bound to the original physical directory. Discard them before a
        // renamed/recreated path can reuse that cursor and expose entries from the moved tree.
        ClearDirectoryCursors();
        foreach (var other in handles.Values.Where(x => Within(x.Location.Physical, source.Physical)).ToArray())
        {
            var suffix = other.Location.Physical[source.Physical.Length..];
            var physical = destination.Physical + suffix;
            var originalRoot = scopes.Single(x => x.Share.Id == other.Location.Share.Id).Root;
            if (!Within(physical, originalRoot))
            {
                // A handle must never acquire another export's authorization context after an alias rename.
                Release(other);
                continue;
            }
            var relative = RelativeToRoot(originalRoot, physical);
            other.Location = new(other.Location.Share, relative, physical);
            try
            {
                var owner = store.Identity(other.Identity.Id);
                DemandHandleAccess(other.Location, owner, other.Access, other.Directory);
            }
            catch (UnauthorizedAccessException) { Release(other); }
        }
        foreach (var range in ranges.Where(x => Within(x.Physical, source.Physical)).ToArray())
        {
            ranges.Remove(range);
            ranges.Add(range with
            {
                Physical = destination.Physical + range.Physical[source.Physical.Length..]
            });
        }
        audit.Write(principal.Name, "Rename", Virtual(source) + " -> " + Virtual(destination));
        return new();
    }
    private static string RelativeToRoot(string root, string physical)
    {
        var relative = Path.GetRelativePath(root, physical);
        return relative == "." ? "" : relative.Replace('\\', '/');
    }
    private void VerifyMoveTree(Location location, Location destination, Location source, Device principal, PolicyScope[] scopes)
    {
        CheckLocation(location);
        var directory = Directory.Exists(location.Physical);
        Demand(location, principal, Permission.Rename | Permission.ReadAttributes | (directory ? Permission.ListDirectory : Permission.ReadData));
        // Rules stay attached to paths. A rename may not bypass a restriction by moving data to a looser path.
        var targetPhysical = destination.Physical + location.Physical[source.Physical.Length..];
        store.Read(s =>
        {
            foreach (var scope in scopes.Where(x => Within(targetPhysical, x.Root)))
            {
                var beforeRelative = Within(location.Physical, scope.Root) ? RelativeToRoot(scope.Root, location.Physical) : null;
                var afterRelative = RelativeToRoot(scope.Root, targetPhysical);
                foreach (var group in s.Groups)
                {
                    (Permission Allow, Permission Deny) Policy(string? relative)
                    {
                        if (relative is null)
                            return (Permission.None, Permission.None);
                        var allow = Permission.None;
                        var deny = Permission.None;
                        foreach (var rule in s.Rules.Where(x => x.GroupId == group.Id && x.ShareId == scope.Share.Id))
                        {
                            var matching = rule.MatchingPermissions(relative);
                            allow |= matching.Allow;
                            deny |= matching.Deny;
                        }
                        return (allow & ~deny, deny);
                    }
                    var before = Policy(beforeRelative);
                    var after = Policy(afterRelative);
                    if ((after.Allow & ~before.Allow) != 0 || (before.Deny & ~after.Deny) != 0)
                        throw new UnauthorizedAccessException("A move cannot loosen group permissions in any overlapping export. Adjust the rules in the server UI first.");
                }
            }
            return true;
        });
        if (directory)
            foreach (var child in Directory.EnumerateFileSystemEntries(location.Physical))
                VerifyMoveTree(Resolve(location.Share.Name + "/" + location.Relative + "/" + Path.GetFileName(child)), destination, source, principal, scopes);
    }
    private RpcResponse Lock(OpenHandle h, RpcRequest r)
    {
        if (h.Stream is null)
            throw new RemoteException("InvalidHandle");
        if (r.Length == 0)
            throw new ArgumentException("Empty lock.");
        CheckRanges(h, r.Offset, r.Length);
        if (ranges.Any(x => x.Physical.Equals(h.Location.Physical, StringComparison.OrdinalIgnoreCase) &&
            r.Offset < x.Offset + x.Length && x.Offset < r.Offset + r.Length))
            throw new RemoteException("LockViolation");
        ranges.Add(new(h.Id, h.Location.Physical, r.Offset, r.Length));
        return new();
    }
    private RpcResponse Unlock(OpenHandle h, RpcRequest r)
    {
        var range = ranges.SingleOrDefault(x => x.Handle == h.Id && x.Offset == r.Offset && x.Length == r.Length)
            ?? throw new RemoteException("LockViolation");
        ranges.Remove(range);
        return new();
    }
    private RpcResponse Security(Location location, Device principal)
    {
        Demand(location, principal, Permission.ReadPermissions);
        return new()
        {
            Permissions = Effective(location, principal)
        };
    }
    private RpcResponse Space(Device principal)
    {
        long free = 0, total = 0;
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var share in store.Read(s => s.Shares.Where(x => x.Enabled).ToArray()))
        {
            if ((store.Permissions(principal, share.Id, "") & Permission.ReadAttributes) == 0)
                continue;
            try
            {
                var path = shareRoots.GetOrAdd(share.Id, _ => WindowsPaths.Canonical(share.LocalPath));
                if (IsProtectedExportPath(path, protectedRoots))
                    continue;
                var root = Path.GetPathRoot(path)!;
                if (!roots.Add(root))
                    continue;
                var drive = new DriveInfo(root);
                var available = drive.AvailableFreeSpace;
                var capacity = drive.TotalSize;
                free += available;
                total += capacity;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Removable volumes may be unready after resume. Keep reporting the healthy volumes.
            }
        }
        return new()
        {
            FreeBytes = free,
            TotalBytes = total
        };
    }
    private static string Virtual(Location l) => l.Share.Name + (l.Relative.Length == 0 ? "" : "/" + l.Relative);
    private void Release(OpenHandle h)
    {
        h.Stream?.Dispose();
        handles.Remove(h.Id);
        ranges.RemoveAll(x => x.Handle == h.Id);
        foreach (var key in directoryCursors.Keys.Where(key => key.Session == h.Session && key.Handle == h.Id).ToArray())
        {
            directoryCursors[key].Dispose();
            directoryCursors.Remove(key);
        }
    }
    private void ClearDirectoryCursors()
    {
        foreach (var cursor in directoryCursors.Values)
            cursor.Dispose();
        directoryCursors.Clear();
    }
    private void PruneRevokedHandles(Guid except)
    {
        foreach (var h in handles.Values.Where(x => x.Id != except).ToArray())
        {
            try
            {
                var identity = store.Identity(h.Identity.Id);
                var owner = identity;
                if (!identity.HasSameIdentity(h.Identity))
                {
                    Release(h);
                    continue;
                }
                var share = store.Read(s => s.Shares.SingleOrDefault(x => x.Id == h.Location.Share.Id && x.Enabled));
                if (share != h.Location.Share)
                {
                    Release(h);
                    continue;
                }
                DemandHandleAccess(h.Location, owner, h.Access, h.Directory);
            }
            catch (UnauthorizedAccessException) { Release(h); }
        }
    }
    public void ReleaseSession(Guid session)
    {
        gate.EnterWriteLock();
        try
        {
            foreach (var h in handles.Values.Where(x => x.Session == session).ToArray())
                Release(h);
            foreach (var key in directoryCursors.Keys.Where(key => key.Session == session).ToArray())
            {
                directoryCursors[key].Dispose();
                directoryCursors.Remove(key);
            }
        }
        finally { gate.ExitWriteLock(); }
    }
    public void Dispose()
    {
        gate.EnterWriteLock();
        try
        {
            foreach (var h in handles.Values.ToArray())
                Release(h);
            ClearDirectoryCursors();
        }
        finally { gate.ExitWriteLock(); }
    }

    public static string ErrorCode(Exception exception) => exception switch
    {
        RemoteException remote => remote.Code,
        FileSharingConflict => "SharingViolation",
        UnauthorizedAccessException => "AccessDenied",
        FileNotFoundException or DirectoryNotFoundException => "NotFound",
        ArgumentException or NotSupportedException => "InvalidParameter",
        IOException io when (io.HResult & 0xffff) is 32 or 33 => "SharingViolation",
        IOException io when (io.HResult & 0xffff) is 80 or 183 => "Exists",
        IOException io when (io.HResult & 0xffff) == 145 => "NotEmpty",
        IOException io when (io.HResult & 0xffff) is 39 or 112 => "DiskFull",
        _ => "IOError"
    };
}
