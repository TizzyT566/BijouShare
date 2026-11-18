using System.IO.Enumeration;
using System.Security.AccessControl;
using System.Security.Principal;
using DokanNet;
using BijouShare.Shared;
using DokanAccess = DokanNet.FileAccess;

namespace BijouShare.Client;

public sealed class DriveOperations(IRemoteConnection connection, ILogger<DriveOperations> logger) : IDokanOperations
{
    private sealed class Context(Guid handle, long generation)
    {
        public Guid Handle { get; } = handle;
        public long Generation { get; } = generation;
        public int Cleaned;
        public int Closed;
    }
    private static FileInformation Info(RemoteEntry entry) => new()
    {
        FileName = entry.Name,
        Attributes = entry.Attributes,
        Length = entry.Length,
        CreationTime = entry.CreationTime.ToLocalTime(),
        LastAccessTime = entry.LastAccessTime.ToLocalTime(),
        LastWriteTime = entry.LastWriteTime.ToLocalTime()
    };
    private RemoteReply Send(RpcRequest request, IDokanFileInfo? info = null, bool useHandle = true)
    {
        if (useHandle && info?.Context is Context c && c.Handle != Guid.Empty)
        {
            if (Volatile.Read(ref c.Closed) != 0)
                throw new RemoteException("InvalidHandle");
            return connection.Call(request with
            {
                Handle = c.Handle
            }, c.Generation);
        }
        return connection.Call(request);
    }
    private static NtStatus Status(Exception ex) => ex switch
    {
        RemoteException r => r.Code switch
        {
            "AccessDenied" or "DeviceBlocked" or "DeviceRejected" or "PendingApproval" => NtStatus.AccessDenied,
            "NotFound" => NtStatus.ObjectNameNotFound,
            "Exists" => NtStatus.ObjectNameCollision,
            "SharingViolation" => NtStatus.SharingViolation,
            "LockViolation" => NtStatus.FileLockConflict,
            "NotEmpty" => NtStatus.DirectoryNotEmpty,
            "NotADirectory" => NtStatus.NotADirectory,
            "IsDirectory" => unchecked((NtStatus)0xC00000BA),
            "InvalidHandle" => NtStatus.FileClosed,
            "InvalidParameter" => NtStatus.InvalidParameter,
            "Unsupported" or "HybridUnavailable" => unchecked((NtStatus)0xC00000BB),
            "DiskFull" => NtStatus.DiskFull,
            "TooManyOpenFiles" => NtStatus.TooManyOpenedFiles,
            "Disconnected" => unchecked((NtStatus)0xC000009D),
            "Timeout" => NtStatus.IoTimeout,
            "PendingApproval" or "DeviceRejected" or "DeviceBlocked" or "ServerIdentityChanged" or "ServerIdentityConflict" or "AuthenticationFailed" => NtStatus.AccessDenied,
            "NotSameDevice" => unchecked((NtStatus)0xC00000D4),
            _ => NtStatus.Unsuccessful
        },
        OperationCanceledException => NtStatus.IoTimeout,
        ObjectDisposedException => NtStatus.FileClosed,
        ArgumentException => NtStatus.InvalidParameter,
        _ => NtStatus.Unsuccessful
    };
    private NtStatus Try(Action action)
    {
        try
        {
            action();
            return NtStatus.Success;
        }
        catch (Exception ex) { logger.LogDebug(ex, "Filesystem callback failed"); return Status(ex); }
    }
    public NtStatus CreateFile(string fileName, DokanAccess access, FileShare share, FileMode mode,
        FileOptions options, FileAttributes attributes, IDokanFileInfo info)
    {
        try
        {
            if ((options & FileOptions.Encrypted) != 0)
                return unchecked((NtStatus)0xC00000BB);
            var reply = Send(new()
            {
                Operation = "Open",
                Path = fileName,
                Access = (uint)access,
                Share = share,
                Mode = mode,
                Attributes = attributes,
                Directory = info.IsDirectory,
                WriteThrough = (options & FileOptions.WriteThrough) != 0
            }, useHandle: false);
            info.IsDirectory = (reply.Response.Entry ?? throw new InvalidDataException("Missing open-file metadata.")).IsDirectory;
            info.Context = new Context(reply.Response.Handle, reply.Generation);
            return reply.Response.Existed && mode is FileMode.Create or FileMode.OpenOrCreate
                ? DokanResult.AlreadyExists : NtStatus.Success;
        }
        catch (Exception ex) { return Status(ex); }
    }
    public void Cleanup(string fileName, IDokanFileInfo info)
    {
        if (info.Context is not Context context || Interlocked.Exchange(ref context.Cleaned, 1) != 0 ||
            Volatile.Read(ref context.Closed) != 0 || context.Handle == Guid.Empty)
            return;
        try
        {
            connection.Call(new()
            {
                Operation = "Cleanup",
                Path = fileName,
                Handle = context.Handle,
                DeleteOnClose = info.DeletePending
            }, context.Generation);
        }
        catch (RemoteException ex) when (ex.Code is "InvalidHandle" or "Disconnected")
        {
            logger.LogDebug("Remote cleanup already completed for {Path}: {Reason}", fileName, ex.Code);
        }
        catch (Exception ex) { logger.LogWarning("Cleanup of {Path} failed: {Reason}", fileName, ex.Message); }
    }
    public void CloseFile(string fileName, IDokanFileInfo info)
    {
        Close(fileName, info);
        info.Context = null;
    }
    private void Close(string fileName, IDokanFileInfo info)
    {
        if (info.Context is not Context context || Interlocked.Exchange(ref context.Closed, 1) != 0 || context.Handle == Guid.Empty)
            return;
        try
        {
            connection.Call(new()
            {
                Operation = "Close",
                Path = fileName,
                Handle = context.Handle
            }, context.Generation);
        }
        catch (RemoteException ex) when (ex.Code is "InvalidHandle" or "Disconnected")
        {
            logger.LogDebug("Remote handle already closed for {Path}: {Reason}", fileName, ex.Code);
        }
        catch (Exception ex) { logger.LogWarning("Closing {Path} failed: {Reason}", fileName, ex.Message); }
    }
    public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
    {
        var count = 0;
        var status = Try(() =>
        {
            if (offset < 0 || offset > long.MaxValue - buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            while (count < buffer.Length)
            {
                var size = Math.Min(connection.MaxTransferSizeFor(fileName), buffer.Length - count);
                var data = Send(new()
                {
                    Operation = "Read",
                    Path = fileName,
                    Offset = checked(offset + count),
                    Count = size,
                    PagingIo = info.PagingIo
                }, info).Response.Data
                    ?? throw new InvalidDataException("Missing read data.");
                if (data.Length > size)
                    throw new InvalidDataException("Server returned more bytes than requested.");
                data.CopyTo(buffer, count);
                count += data.Length;
                if (data.Length < size)
                    break;
                info.TryResetTimeout(60000);
            }
        });
        bytesRead = count;
        return status;
    }
    public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
    {
        var count = 0;
        var status = Try(() =>
        {
            if (!info.WriteToEndOfFile && (offset < 0 || offset > long.MaxValue - buffer.Length))
                throw new ArgumentOutOfRangeException(nameof(offset));
            while (count < buffer.Length)
            {
                var size = Math.Min(connection.MaxTransferSizeFor(fileName), buffer.Length - count);
                var reply = Send(new()
                {
                    Operation = "Write",
                    Path = fileName,
                    Offset = info.WriteToEndOfFile ? 0 : checked(offset + count),
                    Data = buffer,
                    DataOffset = count,
                    BorrowedCount = size,
                    Append = info.WriteToEndOfFile,
                    PagingIo = info.PagingIo
                }, info);
                if (reply.Response.Length < 0 || reply.Response.Length > size || (reply.Response.Length == 0 && !info.PagingIo))
                    throw new InvalidDataException("Server returned an invalid write acknowledgement.");
                count += (int)reply.Response.Length;
                if (reply.Response.Length < size)
                    break;
                info.TryResetTimeout(60000);
            }
        });
        bytesWritten = count;
        return status;
    }
    public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info) =>
        Try(() => Send(new() { Operation = "Flush", Path = fileName }, info));
    public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
    {
        FileInformation result = default;
        var status = Try(() => result = Info(Send(new() { Operation = "Stat", Path = fileName }, info).Response.Entry!));
        fileInfo = result;
        return status;
    }
    public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info) => FindFilesWithPattern(fileName, "*", out files, info);
    public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files, IDokanFileInfo info)
    {
        IList<FileInformation> result = [];
        var status = Try(() =>
        {
            long offset = 0;
            while (true)
            {
                var page = Send(new()
                {
                    Operation = "List",
                    Path = fileName,
                    Count = 256,
                    Offset = offset
                }, info).Response;
                foreach (var entry in (page.Entries ?? throw new InvalidDataException("Missing directory page.")).Where(e => FileSystemName.MatchesWin32Expression(searchPattern, e.Name, true)))
                    result.Add(Info(entry));
                if (!page.More)
                    break;
                if (page.Length <= offset)
                    throw new IOException("Directory enumeration made no progress.");
                offset = page.Length;
                info.TryResetTimeout(60000);
            }
            // Win32 FindFirstFile reports FILE_NOT_FOUND when an empty virtual volume
            // yields no entries. Native directory readers need the dot entries to
            // distinguish an existing empty root from a missing directory.
            if (result.Count == 0 && fileName.Trim('\\', '/').Length == 0)
                foreach (var name in new[] { ".", ".." })
                    if (FileSystemName.MatchesWin32Expression(searchPattern, name, true))
                        result.Add(new FileInformation
                        {
                            FileName = name,
                            Attributes = FileAttributes.Directory,
                            CreationTime = DateTime.UnixEpoch,
                            LastAccessTime = DateTime.UnixEpoch,
                            LastWriteTime = DateTime.UnixEpoch
                        });
        });
        files = result;
        return status;
    }
    public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info) =>
        Try(() => Send(new() { Operation = "Attributes", Path = fileName, Attributes = attributes }, info));
    public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, IDokanFileInfo info) =>
        Try(() => Send(new()
        {
            Operation = "Times",
            Path = fileName,
            CreationTime = creationTime?.ToUniversalTime(),
            LastAccessTime = lastAccessTime?.ToUniversalTime(),
            LastWriteTime = lastWriteTime?.ToUniversalTime()
        }, info));
    public NtStatus DeleteFile(string fileName, IDokanFileInfo info) => Try(() => Send(new() { Operation = "CanDelete", Path = fileName }, info));
    public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info) => DeleteFile(fileName, info);
    public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info) =>
        Try(() => Send(new() { Operation = "Move", Path = oldName, Destination = newName, Replace = replace }, info));
    public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info) =>
        Try(() => Send(new() { Operation = "Resize", Path = fileName, Length = length }, info));
    public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info)
    {
        return Try(() =>
        {
            if (length < 0)
                throw new ArgumentException("Invalid allocation size.");
            Send(new()
            {
                Operation = "Allocate",
                Path = fileName,
                Length = length
            }, info);
        });
    }
    public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info) =>
        Try(() => Send(new() { Operation = "Lock", Path = fileName, Offset = offset, Length = length }, info));
    public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info) =>
        Try(() => Send(new() { Operation = "Unlock", Path = fileName, Offset = offset, Length = length }, info));
    public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, IDokanFileInfo info)
    {
        long free = 0, total = 0;
        var status = Try(() => { var r = Send(new() { Operation = "Space" }).Response; free = r.FreeBytes; total = r.TotalBytes; });
        freeBytesAvailable = totalNumberOfFreeBytes = free;
        totalNumberOfBytes = total;
        return status;
    }
    public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features, out string fileSystemName,
        out uint maximumComponentLength, IDokanFileInfo info)
    {
        volumeLabel = "BijouShare";
        fileSystemName = "BijouShare";
        maximumComponentLength = 255;
        features = FileSystemFeatures.CasePreservedNames | FileSystemFeatures.UnicodeOnDisk;
        return NtStatus.Success;
    }
    public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info)
    {
        FileSystemSecurity result = info.IsDirectory ? new DirectorySecurity() : new FileSecurity();
        var status = Try(() =>
        {
            if ((sections & AccessControlSections.Audit) != 0)
                throw new RemoteException("AccessDenied");
            var p = Send(new()
            {
                Operation = "Security",
                Path = fileName
            }, info).Response.Permissions;
            FileSystemRights rights = FileSystemRights.Synchronize;
            if (info.IsDirectory)
            {
                if (p.HasFlag(Permission.ListDirectory))
                    rights |= FileSystemRights.ListDirectory;
                if (p.HasFlag(Permission.CreateFiles))
                    rights |= FileSystemRights.CreateFiles;
                if (p.HasFlag(Permission.CreateDirectories))
                    rights |= FileSystemRights.CreateDirectories;
            }
            else
            {
                if (p.HasFlag(Permission.ReadData))
                    rights |= FileSystemRights.ReadData;
                if (p.HasFlag(Permission.WriteData))
                    rights |= FileSystemRights.WriteData | FileSystemRights.AppendData;
            }
            if ((p & (Permission.Delete | Permission.Rename)) != 0)
                rights |= FileSystemRights.Delete;
            if (p.HasFlag(Permission.ReadAttributes))
                rights |= FileSystemRights.ReadAttributes | FileSystemRights.ReadExtendedAttributes;
            if (p.HasFlag(Permission.WriteAttributes))
                rights |= FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;
            if (p.HasFlag(Permission.ReadPermissions))
                rights |= FileSystemRights.ReadPermissions;
            var owner = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            result.SetOwner(owner);
            result.SetGroup(owner);
            result.SetAccessRuleProtection(true, false);
            result.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), rights, AccessControlType.Allow));
        });
        security = result;
        return status;
    }
    public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info) => NtStatus.AccessDenied;
    public NtStatus Mounted(string mountPoint, IDokanFileInfo info)
    {
        logger.LogInformation("Mounted {Mount}", mountPoint);
        return NtStatus.Success;
    }
    public NtStatus Unmounted(IDokanFileInfo info)
    {
        logger.LogInformation("Virtual drive unmounted");
        return NtStatus.Success;
    }
    public NtStatus FindStreams(string fileName, out IList<FileInformation> streams, IDokanFileInfo info)
    {
        streams = [];
        return NtStatus.NotImplemented;
    }
}
