using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using BijouShare.Shared;

namespace BijouShare.Server;

// Built into the server so the solution remains exactly two projects.
public static class ServerSelfTests
{
    public static async Task<int> RunAsync()
    {
        await ProtocolSelfTests.RunAsync();
        await HybridSelfTests.RunAsync();
        await HybridNetworkSelfTests.RunAsync();
        BackendSelfTests.Run();
        await ServerSetupSelfTests.RunAsync();
        await DeviceApprovalSelfTests.RunAsync();
        await InviteSelfTests.RunAsync();
        var root = Path.GetFullPath(Path.Combine("artifacts", "self-tests", Guid.NewGuid().ToString("N")));
        var fixture = CreateFixture(root);
        var (store, options, device, key, publicKey) = fixture;
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        var count = 0;
        void Check(bool ok, string label)
        {
            if (!ok)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        var session = Guid.NewGuid();
        var second = Guid.NewGuid();
        RpcResponse Call(RpcRequest r, Guid? s = null) => files.Execute(s ?? session, device.Id, r);
        void Fails(string code, RpcRequest r, Guid? s = null)
        {
            try
            {
                Call(r, s);
                throw new InvalidOperationException("Expected " + code + " from " + r.Operation);
            }
            catch (Exception e) when (FileService.ErrorCode(e) == code) { Check(true, r.Operation + " rejects " + code); }
        }
        var full = (uint)(AccessMask.GenericRead | AccessMask.GenericWrite | AccessMask.Delete);
        RpcResponse Open(string path, uint access, Guid? s = null, FileMode mode = FileMode.Open) => Call(new()
        {
            Operation = "Open",
            Path = path,
            Access = access,
            Share = FileShare.ReadWrite | FileShare.Delete,
            Mode = mode
        }, s);
        var group = device.GroupIds.Single();
        var share = store.Read(s => s.Shares.Single(s => s.Name == "Team"));
        using var secondDeviceKey = KeyAgreement.NewKey();
        var secondDevice = store.Enroll(new(Guid.NewGuid().ToString(), "Second device", Convert.ToBase64String(secondDeviceKey.ExportSubjectPublicKeyInfo())), device.GroupIds);
        Check(secondDevice.ServerPublicKey != device.ServerPublicKey, "Each device receives a distinct persistent server key pair");
        Check(Call(new()
        {
            Operation = "List"
        }).Entries!.Any(x => x.Name == "Team"), "Authorized shares appear under one virtual root");
        var writer = Open("/Team/example.txt", full);
        var reader = Open("/Team/example.txt", AccessMask.GenericRead, second);
        Fails("SharingViolation", new()
        {
            Operation = "Open",
            Path = "/Team/example.txt",
            Access = full,
            Share = FileShare.ReadWrite
        }, second);
        Call(new()
        {
            Operation = "Write",
            Handle = writer.Handle,
            Data = "updated"u8.ToArray()
        });
        Check(System.Text.Encoding.UTF8.GetString(Call(new()
        {
            Operation = "Read",
            Handle = reader.Handle,
            Count = 7
        }, second).Data!) == "updated", "Concurrent reader sees the single writer's bytes");
        Fails("AccessDenied", new()
        {
            Operation = "Write",
            Handle = reader.Handle,
            Data = [0]
        }, second);
        Fails("InvalidHandle", new()
        {
            Operation = "Read",
            Handle = writer.Handle,
            Count = 1
        }, second);
        Call(new()
        {
            Operation = "Lock",
            Handle = writer.Handle,
            Offset = 1,
            Length = 2
        });
        Fails("LockViolation", new()
        {
            Operation = "Read",
            Handle = reader.Handle,
            Offset = 1,
            Count = 1
        }, second);
        Call(new()
        {
            Operation = "Unlock",
            Handle = writer.Handle,
            Offset = 1,
            Length = 2
        });
        Check(Call(new()
        {
            Operation = "Read",
            Handle = reader.Handle,
            Offset = 1,
            Count = 1
        }, second).Data!.Length == 1, "Unlock releases a byte-range lock");
        Call(new()
        {
            Operation = "Resize",
            Handle = writer.Handle,
            Length = 3
        });
        Check(new FileInfo(Path.Combine(root, "share", "example.txt")).Length == 3, "Truncation changes the physical file length");
        store.Update(s => { var index = s.Devices.FindIndex(x => x.Id == device.Id); s.Devices[index] = s.Devices[index] with { GroupIds = [] }; return true; });
        Fails("AccessDenied", new()
        {
            Operation = "Write",
            Handle = writer.Handle,
            Data = [0]
        });
        Check(Call(new()
        {
            Operation = "List"
        }).Entries!.Count == 0, "Removing group membership hides shares immediately");
        store.Update(s => { s.Devices[s.Devices.FindIndex(x => x.Id == device.Id)] = device; return true; });
        Open("/Team/example.txt", full);
        files.ReleaseSession(session);
        files.ReleaseSession(second);
        writer = Open("/Team/example.txt", full, second);
        Check(writer.Handle != Guid.Empty, "Disconnect releases writer ownership and file handles");
        files.ReleaseSession(second);
        var deny = new AccessRule(Guid.NewGuid(), group, share.Id, "restricted", Permission.None, Permission.FullControl, true);
        store.Update(s => { s.Rules.Add(deny); return true; });
        Check(Call(new()
        {
            Operation = "List",
            Path = "/Team"
        }).Entries!.All(x => x.Name != "restricted"), "Explicit denies hide restricted folder metadata");
        Fails("AccessDenied", new()
        {
            Operation = "Stat",
            Path = "/Team/restricted/secret.txt"
        });
        Fails("AccessDenied", new()
        {
            Operation = "Move",
            Path = "/Team/restricted",
            Destination = "/Team/public"
        });
        File.WriteAllText(Path.Combine(root, "share", "scoped.txt"), "scoped");
        store.Update(s => { s.Rules.Add(new(Guid.NewGuid(), group, share.Id, "scoped.txt", 0, Permission.WriteData, false)); return true; });
        Fails("AccessDenied", new()
        {
            Operation = "Move",
            Path = "/Team/scoped.txt",
            Destination = "/Team/looser.txt"
        });
        Check(File.Exists(Path.Combine(root, "share", "scoped.txt")), "Rename cannot bypass a file-specific restriction");
        foreach (var path in new[] { "/Team/../state/state.json", "/Team/a:stream", "/Team/CON", "/Team/a.", "/Team//escape" })
            Fails("InvalidParameter", new()
            {
                Operation = "Stat",
                Path = path
            });
        store.Update(s => { s.Shares.Add(new(Guid.NewGuid(), "Private", store.DataDirectory, true)); var id = s.Shares[^1].Id; s.Rules.Add(new(Guid.NewGuid(), group, id, "", Permission.FullControl, 0, true)); return true; });
        Fails("AccessDenied", new()
        {
            Operation = "Stat",
            Path = "/Private/state.json"
        });
        var created = Open("/Team/new.txt", full, mode: FileMode.CreateNew);
        Call(new()
        {
            Operation = "Write",
            Handle = created.Handle,
            Data = "hello"u8.ToArray()
        });
        Call(new()
        {
            Operation = "Times",
            Handle = created.Handle,
            LastWriteTime = new(2025, 2, 3, 4, 5, 6, DateTimeKind.Utc)
        });
        Call(new()
        {
            Operation = "Attributes",
            Handle = created.Handle,
            Attributes = FileAttributes.Archive
        });
        Call(new()
        {
            Operation = "Move",
            Handle = created.Handle,
            Destination = "/Team/renamed.txt"
        });
        Check(Call(new()
        {
            Operation = "Stat",
            Handle = created.Handle
        }).Entry!.Name == "renamed.txt", "Rename updates the open handle's path");
        Call(new()
        {
            Operation = "CanDelete",
            Handle = created.Handle
        });
        Call(new()
        {
            Operation = "Close",
            Handle = created.Handle,
            DeleteOnClose = true
        });
        Check(!File.Exists(Path.Combine(root, "share", "renamed.txt")), "Delete is committed on handle cleanup");
        var directory = Call(new()
        {
            Operation = "Open",
            Path = "/Team/new-folder",
            Directory = true,
            Mode = FileMode.CreateNew,
            Access = full,
            Share = FileShare.ReadWrite | FileShare.Delete
        });
        Call(new()
        {
            Operation = "Close",
            Handle = directory.Handle
        });
        Check(Directory.Exists(Path.Combine(root, "share", "new-folder")), "Folder creation is implemented");
        Fails("NotFound", new()
        {
            Operation = "Open",
            Path = "/Team/missing-parent/child",
            Directory = true,
            Mode = FileMode.CreateNew,
            Access = full
        });
        Check(!Directory.Exists(Path.Combine(root, "share", "missing-parent")), "Creating a folder cannot implicitly create unchecked ancestors");
        Call(new()
        {
            Operation = "Move",
            Path = "/Team/new-folder",
            Destination = "/Team/NEW-FOLDER"
        });
        Check(Directory.EnumerateDirectories(Path.Combine(root, "share")).Any(x => Path.GetFileName(x) == "NEW-FOLDER"), "Case-only folder renames preserve the requested spelling");
        Fails("AccessDenied", new()
        {
            Operation = "CanDelete",
            Path = "/Team/restricted"
        });
        Directory.CreateDirectory(Path.Combine(root, "share", "nonempty"));
        File.WriteAllText(Path.Combine(root, "share", "nonempty", "child.txt"), "child");
        Fails("NotEmpty", new()
        {
            Operation = "CanDelete",
            Path = "/Team/nonempty"
        });
        Directory.CreateDirectory(Path.Combine(root, "share", "paged"));
        for (var i = 0; i < 300; i++)
            File.WriteAllText(Path.Combine(root, "share", "paged", $"file-{i:D3}.txt"), "");
        var firstPage = Call(new()
        {
            Operation = "List",
            Path = "/Team/paged",
            Count = 256
        });
        var lastPage = Call(new()
        {
            Operation = "List",
            Path = "/Team/paged",
            Offset = firstPage.Length,
            Count = 256
        });
        Check(firstPage.More && !lastPage.More && firstPage.Entries!.Count + lastPage.Entries!.Count == 300, "Large directories use bounded, complete pages");
        DirectoryCursorRegressions(root, store, files, device, group, share.Id, Check);
        var retained = Open("/Team/retained.bin", full, mode: FileMode.CreateNew);
        Call(new()
        {
            Operation = "Resize",
            Handle = retained.Handle,
            Length = 4
        });
        Call(new()
        {
            Operation = "Lock",
            Handle = retained.Handle,
            Offset = 0,
            Length = 1
        });
        Call(new()
        {
            Operation = "Cleanup",
            Handle = retained.Handle
        });
        Fails("InvalidHandle", new()
        {
            Operation = "Write",
            Handle = retained.Handle,
            Data = [1]
        });
        Call(new()
        {
            Operation = "Write",
            Handle = retained.Handle,
            PagingIo = true,
            Data = [42]
        });
        Check(Call(new()
        {
            Operation = "Read",
            Handle = retained.Handle,
            PagingIo = true,
            Count = 1
        }).Data![0] == 42,
            "Paging I/O survives cleanup until the final file-object close");
        var retainedReader = Call(new()
        {
            Operation = "Open",
            Path = "/Team/retained.bin",
            Access = AccessMask.GenericRead,
            Share = FileShare.Read
        }, second);
        Check(Call(new()
        {
            Operation = "Read",
            Handle = retainedReader.Handle,
            Count = 1
        }, second).Data![0] == 42,
            "Cleanup releases byte-range locks while keeping the mapped file alive");
        Fails("SharingViolation", new()
        {
            Operation = "Open",
            Path = "/Team/retained.bin",
            Access = full,
            Share = FileShare.ReadWrite
        }, second);
        Call(new()
        {
            Operation = "Close",
            Handle = retainedReader.Handle
        }, second);
        Call(new()
        {
            Operation = "Close",
            Handle = retained.Handle
        });
        retained = Open("/Team/retained.bin", full);
        Check(retained.Handle != Guid.Empty, "Final close releases a retained mapped writer lease");
        Call(new()
        {
            Operation = "Cleanup",
            Handle = retained.Handle,
            DeleteOnClose = true
        });
        Check(!File.Exists(Path.Combine(root, "share", "retained.bin")), "Delete disposition unlinks a file during cleanup");
        Check(Call(new()
        {
            Operation = "Read",
            Handle = retained.Handle,
            PagingIo = true,
            Count = 1
        }).Data![0] == 42,
            "Unlinked mapped files remain readable through their retained handle");
        Call(new()
        {
            Operation = "Close",
            Handle = retained.Handle
        });
        FileSystemRegressions(root, store, files, device, secondDevice, share, Check);
        ExportVisibilityRegressions(root, store, files, device, group, Check);
        await NetworkTests(options, store, files, audit, device, key, publicKey, Check);
        CryptographicOperations.ZeroMemory(key);
        Console.WriteLine($"Server: {count} checks passed. Fixture: {root}");
        return 0;
    }

    private static void DirectoryCursorRegressions(string root, StateStore store, FileService files,
        Device device, Guid group, Guid share, Action<bool, string> check)
    {
        var session = Guid.NewGuid();
        RpcResponse Call(RpcRequest request) => files.Execute(session, device.Id, request);
        var directory = Path.Combine(root, "share", "cursor-before");
        Directory.CreateDirectory(directory);
        for (var index = 0; index < 12; index++)
            File.WriteAllText(Path.Combine(directory, $"original-{index:D2}.txt"), "original");
        var first = Call(new()
        {
            Operation = "List",
            Path = "/Team/cursor-before",
            Count = 1
        });
        Call(new()
        {
            Operation = "Move",
            Path = "/Team/cursor-before",
            Destination = "/Team/cursor-after"
        });
        Directory.CreateDirectory(directory);
        for (var index = 0; index < 12; index++)
            File.WriteAllText(Path.Combine(directory, $"replacement-{index:D2}.txt"), "replacement");
        var next = Call(new()
        {
            Operation = "List",
            Path = "/Team/cursor-before",
            Offset = first.Length,
            Count = 256
        });
        check(first.More && !next.More && next.Entries is { Count: 11 } &&
            next.Entries.All(entry => entry.Name.StartsWith("replacement-", StringComparison.Ordinal)),
            "Directory pagination never reuses a moved directory's entries when its old path is recreated");

        var page = Call(new()
        {
            Operation = "List",
            Path = "/Team/paged",
            Count = 7
        });
        var deny = new AccessRule(Guid.NewGuid(), group, share, "paged", Permission.None, Permission.ReadAttributes, true);
        store.Update(state => { state.Rules.Add(deny); return true; });
        try
        {
            var hidden = true;
            var offset = page.Length;
            do
            {
                page = Call(new()
                {
                    Operation = "List",
                    Path = "/Team/paged",
                    Offset = offset,
                    Count = 256
                });
                hidden &= page.Entries is { Count: 0 };
                if (!page.More)
                    break;
                if (page.Length <= offset)
                    throw new InvalidOperationException("Directory revocation enumeration made no progress.");
                offset = page.Length;
            } while (true);
            check(hidden, "A group permission edit hides remaining directory pages immediately");
        }
        finally
        {
            store.Update(state => { state.Rules.RemoveAll(rule => rule.Id == deny.Id); return true; });
            files.ReleaseSession(session);
        }
        check(Call(new() { Operation = "List", Path = "/Team/paged", Count = 1 }).Entries is { Count: 1 },
            "Restored group permissions invalidate cached directory denials");
        files.ReleaseSession(session);
    }

    private static void ExportVisibilityRegressions(string root, StateStore store, FileService files,
        Device device, Guid groupId, Action<bool, string> check)
    {
        var directory = Path.Combine(root, "hidden-export");
        Directory.CreateDirectory(directory);
        var child = Path.Combine(directory, "hidden-child.txt");
        File.WriteAllText(child, "hidden child");
        var rootAttributes = File.GetAttributes(directory);
        File.SetAttributes(directory, rootAttributes | FileAttributes.Hidden | FileAttributes.System);
        File.SetAttributes(child, FileAttributes.Hidden | FileAttributes.System);
        var exportId = Guid.NewGuid();
        var driveId = Guid.NewGuid();
        var driveRoot = Path.GetPathRoot(root)!;
        store.Update(state =>
        {
            state.Shares.Add(new(exportId, "VisibleExport", directory, true));
            state.Rules.Add(new(Guid.NewGuid(), groupId, exportId, "", Permission.FullControl, Permission.None, true));
            state.Shares.Add(new(driveId, "VisibleDrive", driveRoot, true));
            state.Rules.Add(new(Guid.NewGuid(), groupId, driveId, "", Permission.ReadAttributes, Permission.None, true));
            return true;
        });
        var session = Guid.NewGuid();
        RpcResponse Call(RpcRequest request) => files.Execute(session, device.Id, request);
        static bool Visible(RemoteEntry entry) => (entry.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0;
        try
        {
            var listing = Call(new()
            {
                Operation = "List"
            }).Entries!;
            check(Visible(listing.Single(entry => entry.Name == "VisibleExport")), "Explicit exports do not inherit physical Hidden/System root flags");
            check(Visible(listing.Single(entry => entry.Name == "VisibleDrive")), "A whole drive appears as a visible virtual share");
            check(Visible(Call(new()
            {
                Operation = "Stat",
                Path = "/VisibleExport"
            }).Entry!), "Share-root stat returns visible attributes consistently");
            var opened = Call(new()
            {
                Operation = "Open",
                Path = "/VisibleExport",
                Access = AccessMask.ReadAttributes,
                Share = FileShare.ReadWrite | FileShare.Delete
            });
            check(Visible(opened.Entry!), "Opening a share root preserves its visible virtual attributes");
            Call(new()
            {
                Operation = "Close",
                Handle = opened.Handle
            });
            var fileExport = Guid.NewGuid();
            store.Update(state =>
            {
                state.Shares.Add(new(fileExport, "VisibleFile", child, true));
                state.Rules.Add(new(Guid.NewGuid(), groupId, fileExport, "", Permission.FullControl, Permission.None, true));
                return true;
            });
            var file = Call(new()
            {
                Operation = "Open",
                Path = "/VisibleFile",
                Access = AccessMask.GenericRead,
                Share = FileShare.ReadWrite | FileShare.Delete
            });
            check(Visible(Call(new()
            {
                Operation = "Stat",
                Handle = file.Handle
            }).Entry!), "Open file-share handle metadata also normalizes root flags");
            Call(new()
            {
                Operation = "Close",
                Handle = file.Handle
            });
            var descendant = Call(new()
            {
                Operation = "Stat",
                Path = "/VisibleExport/hidden-child.txt"
            }).Entry!;
            check((descendant.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == (FileAttributes.Hidden | FileAttributes.System),
                "Hidden/system attributes of descendants are preserved");
            check((File.GetAttributes(directory) & (FileAttributes.Hidden | FileAttributes.System)) == (FileAttributes.Hidden | FileAttributes.System),
                "Virtual share visibility never changes physical directory attributes");
        }
        finally
        {
            files.ReleaseSession(session);
            File.SetAttributes(child, FileAttributes.Normal);
            File.SetAttributes(directory, rootAttributes);
        }
    }

    private static void FileSystemRegressions(string root, StateStore store, FileService files, Device device,
        Device secondDevice, ExportShare share, Action<bool, string> check)
    {
        var session = Guid.NewGuid();
        var readerSession = Guid.NewGuid();
        const uint full = AccessMask.GenericRead | AccessMask.GenericWrite | AccessMask.Delete;
        const FileShare sharing = FileShare.ReadWrite | FileShare.Delete;
        const Permission readOnly = Permission.ListDirectory | Permission.ReadData | Permission.ReadAttributes | Permission.ReadPermissions;
        RpcResponse Call(RpcRequest request, Guid? owner = null) => files.Execute(owner ?? session, device.Id, request);
        void Reject(string code, RpcRequest request, string label)
        {
            try
            {
                Call(request);
                throw new InvalidOperationException("Expected " + code + ": " + label);
            }
            catch (Exception exception) when (FileService.ErrorCode(exception) == code) { check(true, label); }
        }
        RpcResponse Open(string path, uint access = full, Guid? owner = null, FileMode mode = FileMode.Open) =>
            Call(new()
            {
                Operation = "Open",
                Path = path,
                Access = access,
                Share = sharing,
                Mode = mode
            }, owner);

        Reject("AccessDenied", new()
        {
            Operation = "Open",
            Access = AccessMask.GenericWrite
        }, "The virtual root rejects writable opens");
        Reject("Exists", new()
        {
            Operation = "Open",
            Mode = FileMode.CreateNew
        }, "Creating the existing virtual root reports a collision");
        Reject("Unsupported", new()
        {
            Operation = "Open",
            Path = "/Team/unsupported.txt",
            Mode = FileMode.CreateNew,
            Access = full,
            Attributes = FileAttributes.ReparsePoint
        }, "Unsupported create attributes fail before file creation");
        check(!File.Exists(Path.Combine(root, "share", "unsupported.txt")), "Rejected attributes leave no empty file behind");

        var physical = Path.Combine(root, "share", "regression.txt");
        File.WriteAllText(physical, "abcde");
        Reject("AccessDenied", new()
        {
            Operation = "Open",
            Path = "/Team/regression.txt",
            Access = AccessMask.ReadAttributes,
            Mode = FileMode.Create
        }, "Destructive modes require a writable handle");
        check(File.ReadAllText(physical) == "abcde", "A rejected destructive open preserves the file data");
        var writer = Open("/Team/regression.txt");
        var reader = Open("/Team/regression.txt", AccessMask.GenericRead, readerSession);
        Call(new()
        {
            Operation = "Lock",
            Handle = writer.Handle,
            Offset = 0,
            Length = 5
        });
        check(Call(new()
        {
            Operation = "Read",
            Handle = reader.Handle,
            Count = 0
        }, readerSession).Data!.Length == 0,
            "Zero-length reads do not conflict with byte-range locks");
        Call(new()
        {
            Operation = "Unlock",
            Handle = writer.Handle,
            Offset = 0,
            Length = 5
        });
        check(Call(new()
        {
            Operation = "Write",
            Handle = writer.Handle,
            Offset = 3,
            Data = [1, 2, 3, 4],
            PagingIo = true,
            WriteThrough = true
        }).Length == 2 &&
            new FileInfo(physical).Length == 5, "Paging writes are clamped to EOF instead of extending a file");
        check(Call(new()
        {
            Operation = "Write",
            Handle = writer.Handle,
            Offset = 20,
            Data = [1],
            PagingIo = true
        }).Length == 0 &&
            new FileInfo(physical).Length == 5, "Paging writes beyond EOF report zero bytes without extending the file");
        Call(new()
        {
            Operation = "Close",
            Handle = reader.Handle
        }, readerSession);
        Call(new()
        {
            Operation = "Move",
            Handle = writer.Handle,
            Destination = "/Team/REGRESSION.txt"
        });
        check(Directory.EnumerateFiles(Path.Combine(root, "share")).Any(x => Path.GetFileName(x) == "REGRESSION.txt"),
            "A case-only rename does not conflict with its own writable handle");
        Call(new()
        {
            Operation = "Close",
            Handle = writer.Handle
        });

        File.WriteAllText(Path.Combine(root, "share", "append.txt"), "A");
        var append = Open("/Team/append.txt", AccessMask.WriteData, mode: FileMode.Append);
        Call(new()
        {
            Operation = "Write",
            Handle = append.Handle,
            Offset = 0,
            Data = "B"u8.ToArray()
        });
        Reject("AccessDenied", new()
        {
            Operation = "Resize",
            Handle = append.Handle,
            Length = 0
        }, "Append-only handles cannot truncate files");
        Call(new()
        {
            Operation = "Close",
            Handle = append.Handle
        });
        check(File.ReadAllText(Path.Combine(root, "share", "append.txt")) == "AB", "FileMode.Append remains append-only on later write RPCs");

        var createGroup = Guid.NewGuid();
        var renameGroup = Guid.NewGuid();
        var aliasId = Guid.NewGuid();
        var aliasReaders = Guid.NewGuid();
        store.Update(state =>
        {
            state.Groups.Add(new(createGroup, "Create files only"));
            state.Groups.Add(new(renameGroup, "Rename only"));
            state.Groups.Add(new(aliasReaders, "Alias readers"));
            state.Rules.Add(new(Guid.NewGuid(), createGroup, share.Id, "", Permission.CreateFiles, Permission.None, true));
            state.Rules.Add(new(Guid.NewGuid(), renameGroup, share.Id, "", readOnly | Permission.Rename | Permission.CreateFiles, Permission.None, true));
            state.Shares.Add(new(aliasId, "Alias", share.LocalPath, true));
            state.Rules.Add(new(Guid.NewGuid(), device.GroupIds[0], aliasId, "", readOnly, Permission.None, true));
            state.Rules.Add(new(Guid.NewGuid(), aliasReaders, aliasId, "", readOnly, Permission.None, true));
            return true;
        });
        using var creatorKey = KeyAgreement.NewKey();
        using var renamerKey = KeyAgreement.NewKey();
        var creatorDevice = store.Enroll(new(Guid.NewGuid().ToString(), "Creator device", Convert.ToBase64String(creatorKey.ExportSubjectPublicKeyInfo())), [createGroup]);
        var renamerDevice = store.Enroll(new(Guid.NewGuid().ToString(), "Renamer device", Convert.ToBase64String(renamerKey.ExportSubjectPublicKeyInfo())), [renameGroup]);
        var creatorSession = Guid.NewGuid();
        var creator = files.Execute(creatorSession, creatorDevice.Id, new()
        {
            Operation = "Open",
            Path = "/Team",
            Directory = true,
            Access = AccessMask.WriteData,
            Share = sharing
        });
        check(creator.Handle != Guid.Empty, "Directory FILE_ADD_FILE admission requires only CreateFiles");
        try
        {
            files.Execute(creatorSession, creatorDevice.Id, new()
            {
                Operation = "Open",
                Path = "/Team",
                Directory = true,
                Access = AccessMask.AppendData,
                Share = sharing
            });
            throw new InvalidOperationException("CreateDirectories was granted by CreateFiles.");
        }
        catch (UnauthorizedAccessException) { check(true, "CreateFiles does not implicitly grant CreateDirectories"); }
        files.ReleaseSession(creatorSession);

        File.WriteAllText(Path.Combine(root, "share", "rename-only.txt"), "rename");
        var renameSession = Guid.NewGuid();
        RpcResponse Renamer(RpcRequest request) => files.Execute(renameSession, renamerDevice.Id, request);
        var rename = Renamer(new()
        {
            Operation = "Open",
            Path = "/Team/rename-only.txt",
            Access = AccessMask.Delete | AccessMask.ReadAttributes,
            Share = sharing
        });
        Renamer(new()
        {
            Operation = "Move",
            Handle = rename.Handle,
            Destination = "/Team/renamed-only.txt"
        });
        check(File.Exists(Path.Combine(root, "share", "renamed-only.txt")), "Rename-only devices can admit Windows DELETE handles for a rename");
        try
        {
            Renamer(new()
            {
                Operation = "CanDelete",
                Handle = rename.Handle
            });
            throw new InvalidOperationException("Rename granted deletion.");
        }
        catch (UnauthorizedAccessException) { check(true, "DELETE handle admission does not grant the Delete operation"); }
        Renamer(new()
        {
            Operation = "Close",
            Handle = rename.Handle
        });

        File.WriteAllText(Path.Combine(root, "share", "alias-source.txt"), "alias");
        var aliasReader = Open("/Alias/alias-source.txt", AccessMask.GenericRead, readerSession);
        writer = Open("/Team/alias-source.txt");
        Call(new()
        {
            Operation = "Move",
            Handle = writer.Handle,
            Destination = "/Team/alias-renamed.txt"
        });
        check(Call(new()
        {
            Operation = "Stat",
            Handle = aliasReader.Handle
        }, readerSession).Entry!.Permissions == readOnly,
            "Renamed overlapping-share handles retain their original share permissions");
        Call(new()
        {
            Operation = "Close",
            Handle = writer.Handle
        });
        Call(new()
        {
            Operation = "Close",
            Handle = aliasReader.Handle
        }, readerSession);
        File.WriteAllText(Path.Combine(root, "share", "alias-policy.txt"), "policy");
        store.Update(state => { state.Rules.Add(new(Guid.NewGuid(), aliasReaders, aliasId, "alias-policy.txt", Permission.None, Permission.ReadData, false)); return true; });
        Reject("AccessDenied", new()
        {
            Operation = "Move",
            Path = "/Team/alias-policy.txt",
            Destination = "/Team/exposed-alias.txt"
        },
            "Rename cannot loosen permissions through a different overlapping export");

        File.WriteAllText(Path.Combine(root, "share", "binding.txt"), "binding");
        writer = Open("/Team/binding.txt");
        store.Update(state => { var current = state.Devices.Single(x => x.Id == device.Id); state.Devices[state.Devices.IndexOf(current)] = current with { GroupIds = [] }; return true; });
        try
        {
            files.Execute(session, device.Id, new()
            {
                Operation = "Write",
                Handle = writer.Handle,
                Data = [42]
            }, device);
            throw new InvalidOperationException("Accepted a revoked device group membership.");
        }
        catch (UnauthorizedAccessException) { check(true, "Existing sessions immediately enforce device group membership changes"); }
        var freshSession = Guid.NewGuid();
        var freshWriter = files.Execute(freshSession, secondDevice.Id, new()
        {
            Operation = "Open",
            Path = "/Team/binding.txt",
            Access = full,
            Share = sharing
        });
        check(freshWriter.Handle != Guid.Empty, "Removing device group access releases its retained writer lease");
        files.ReleaseSession(freshSession);
        store.Update(state => { var current = state.Devices.Single(x => x.Id == device.Id); state.Devices[state.Devices.IndexOf(current)] = current with { GroupIds = device.GroupIds }; return true; });

        var outside = Path.Combine(root, "outside-created.txt");
        var link = Path.Combine(root, "share", "dangling-link.txt");
        try
        {
            File.CreateSymbolicLink(link, outside);
            Reject("AccessDenied", new()
            {
                Operation = "Open",
                Path = "/Team/dangling-link.txt",
                Access = full,
                Share = sharing,
                Mode = FileMode.OpenOrCreate
            },
                "Dangling file links cannot redirect creation outside an export");
            check(!File.Exists(outside), "A blocked dangling link never creates its external target");
            File.Delete(link);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException ||
            exception is IOException && (exception.HResult & 0xffff) == 1314)
        {
            Console.WriteLine("SKIP: File-symlink regression requires Windows developer mode or administrator link privileges.");
        }
        finally
        {
            if (WindowsPaths.TryGetAttributes(link, out var attributes) && (attributes & FileAttributes.ReparsePoint) != 0)
                File.Delete(link);
        }
        var outsideDirectory = Path.Combine(root, "outside-directory");
        var directoryLink = Path.Combine(root, "share", "dangling-directory");
        try
        {
            Directory.CreateDirectory(outsideDirectory);
            CreateTestJunction(directoryLink, outsideDirectory);
            Directory.Delete(outsideDirectory);
            Reject("AccessDenied", new()
            {
                Operation = "Open",
                Path = "/Team/dangling-directory/child.txt",
                Access = full,
                Share = sharing,
                Mode = FileMode.OpenOrCreate
            },
                "Dangling directory junctions cannot redirect child creation outside an export");
            check(!Directory.Exists(outsideDirectory), "Blocked junctions leave no outside directory behind");
        }
        finally
        {
            if (WindowsPaths.TryGetAttributes(directoryLink, out var attributes) && (attributes & FileAttributes.ReparsePoint) != 0)
                Directory.Delete(directoryLink);
            files.ReleaseSession(session);
            files.ReleaseSession(readerSession);
            files.ReleaseSession(renameSession);
        }
    }

    private static void CreateTestJunction(string link, string target)
    {
        Directory.CreateDirectory(link);
        using var directory = OpenJunctionDirectory(link, 0x40000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (directory.IsInvalid)
            throw new IOException("Cannot open the test junction directory.", new Win32Exception(Marshal.GetLastPInvokeError()));
        var substitute = Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target));
        var display = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        var data = new byte[20 + substitute.Length + display.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0xA0000003);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), checked((ushort)(data.Length - 8)));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(10), checked((ushort)substitute.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), checked((ushort)(substitute.Length + 2)));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(14), checked((ushort)display.Length));
        substitute.CopyTo(data, 16);
        display.CopyTo(data, 18 + substitute.Length);
        if (!SetJunction(directory, 0x000900A4, data, data.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new IOException("Cannot create the test junction.", new Win32Exception(Marshal.GetLastPInvokeError()));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle OpenJunctionDirectory(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetJunction(SafeFileHandle directory, uint code, byte[] data, int dataSize,
        IntPtr output, int outputSize, out int returned, IntPtr overlapped);

    public static (StateStore Store, ServerOptions Options, Device Device, byte[] Key, byte[] ServerPublicKey) CreateFixture(string root)
    {
        Directory.CreateDirectory(Path.Combine(root, "share", "restricted"));
        File.WriteAllText(Path.Combine(root, "share", "example.txt"), "example data");
        File.WriteAllText(Path.Combine(root, "share", "restricted", "secret.txt"), "restricted data");
        var options = new ServerOptions { DataDirectory = Path.Combine(root, "state"), ListenAddress = "127.0.0.1", Port = FreePort() };
        var store = new StateStore(options);
        store.InitializeAdmin("admin", "Test-only-password-42!");
        var group = Guid.NewGuid();
        var share = Guid.NewGuid();
        store.Update(s =>
        {
            s.Groups.Add(new(group, "Team members"));
            s.Shares.Add(new(share, "Team", Path.Combine(root, "share"), true));
            s.Rules.Add(new(Guid.NewGuid(), group, share, "", Permission.FullControl, 0, true));
            return true;
        });
        using var client = KeyAgreement.NewKey();
        var key = client.ExportPkcs8PrivateKey();
        var publicKey = Convert.ToBase64String(client.ExportSubjectPublicKeyInfo());
        var device = store.Enroll(new(Guid.NewGuid().ToString(), "Test workstation", publicKey), [group]);
        return (store, options, device, key, Convert.FromBase64String(device.ServerPublicKey));
    }
    public static void WriteAcceptanceFixture(string root)
    {
        root = Path.GetFullPath(root);
        if (Directory.Exists(root))
            throw new ArgumentException("Use a new, empty fixture path.");
        var (store, options, device, key, serverPublic) = CreateFixture(root);
        store.InitializeAdmin("admin", "Test-only-password-42!", "Fixture");
        var clientDirectory = Path.Combine(root, "client");
        PrivateStorage.SecureDirectory(clientDirectory);
        PrivateStorage.AtomicWrite(Path.Combine(clientDirectory, "client.json"), Wire.Encode(new
        {
            deviceId = device.Id.ToString(),
            deviceName = device.Name,
            protectedPrivateKey = PrivateStorage.Protect(key),
            publicKey = device.ClientPublicKey,
            serverPublicKey = Convert.ToBase64String(serverPublic),
            host = "127.0.0.1",
            port = 17443,
            userName = device.Name,
            mountPoint = "N:\\",
            requestTimeoutSeconds = 15
        }));
        CryptographicOperations.ZeroMemory(key);
        PrivateStorage.AtomicWrite(Path.Combine(root, "share", ".bijoushare-acceptance.json"), Wire.Encode(new
        {
            schema = 1,
            fixtureId = Guid.NewGuid()
        }));
        Console.WriteLine($"Fixture created at {root}. Admin: admin / Test-only-password-42!");
    }
    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }
    private static async Task NetworkTests(ServerOptions options, StateStore store, FileService files, AuditLog audit, Device device,
        byte[] privateKey, byte[] serverPublic, Action<bool, string> check)
    {
        using var service = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        await service.StartAsync(CancellationToken.None);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            using var socket = new TcpClient();
            using var transport = await AuthenticatedClient.ConnectAsync(socket, "127.0.0.1", options.Port, device.Id.ToString(), privateKey, serverPublic, deadline.Token, binaryPayloads: false);
            await transport.SendAsync(new RpcRequest { Operation = "List" }, deadline.Token);
            check((await transport.ReceiveAsync<RpcResponse>(deadline.Token)).Entries!.Any(e => e.Name == "Team"), "Real TCP handshake and encrypted file listing succeed");
            using var other = KeyAgreement.NewKey();
            using var badSocket = new TcpClient();
            try
            {
                using var invalid = await AuthenticatedClient.ConnectAsync(badSocket, "127.0.0.1", options.Port, device.Id.ToString(), privateKey, other.ExportSubjectPublicKeyInfo(), deadline.Token);
                throw new InvalidOperationException("Accepted untrusted server key");
            }
            catch (CryptographicException) { check(true, "Incorrect pinned server identity is rejected"); }
            using var wrongDevice = new TcpClient();
            try
            {
                using var invalid = await AuthenticatedClient.ConnectAsync(wrongDevice, "127.0.0.1", options.Port, device.Id.ToString(), other.ExportPkcs8PrivateKey(), serverPublic, deadline.Token);
                throw new InvalidOperationException("Accepted wrong device key");
            }
            catch (CryptographicException) { check(true, "Possession of a device ID without its private key is insufficient"); }
            using (var binarySocket = new TcpClient())
            using (var binary = await AuthenticatedClient.ConnectAsync(binarySocket, "127.0.0.1", options.Port,
                device.Id.ToString(), privateKey, serverPublic, deadline.Token))
            using (var rpc = new RpcClientSession(binary))
            {
                check(binary.BinaryPayloads, "Modern peers authenticate the optimized binary transfer mode");
                Task<RpcResponse> Call(RpcRequest request) => rpc.CallAsync(request, deadline.Token);
                var handle = (await Call(new()
                {
                    Operation = "Open",
                    Path = "/Team/pipeline.bin",
                    Mode = FileMode.CreateNew,
                    Access = AccessMask.GenericRead | AccessMask.GenericWrite,
                    Share = FileShare.ReadWrite | FileShare.Delete
                })).Handle;
                var payload = RandomNumberGenerator.GetBytes(Wire.MaxChunk);
                await Call(new()
                {
                    Operation = "Write",
                    Handle = handle,
                    Data = payload
                });
                var concurrent = await Task.WhenAll(Enumerable.Range(0, 64).Select(async index =>
                {
                    var offset = index * 7919 % (payload.Length - 4096);
                    var response = await Call(new()
                    {
                        Operation = "Read",
                        Handle = handle,
                        Offset = offset,
                        Count = 4096
                    });
                    return response.Data!.AsSpan().SequenceEqual(payload.AsSpan(offset, 4096));
                }));
                check(concurrent.All(x => x), "64 concurrent encrypted reads correlate correctly across the bounded request window");
                var shortRead = await Call(new()
                {
                    Operation = "Read",
                    Handle = handle,
                    Offset = payload.Length - 7,
                    Count = 4096
                });
                check(shortRead.Data!.Length == 7 && shortRead.Data.AsSpan().SequenceEqual(payload.AsSpan(payload.Length - 7)),
                    "Pooled server reads return exactly the available data at EOF");
                var eof = await Call(new()
                {
                    Operation = "Read",
                    Handle = handle,
                    Offset = payload.Length,
                    Count = 4096
                });
                check(eof.Data is { Length: 0 }, "Pooled EOF responses contain no stale buffer data");
                var write = Call(new()
                {
                    Operation = "Write",
                    Handle = handle,
                    Data = "abcde"u8.ToArray()
                });
                var beforeResize = Call(new()
                {
                    Operation = "Read",
                    Handle = handle,
                    Count = 5
                });
                var resize = Call(new()
                {
                    Operation = "Resize",
                    Handle = handle,
                    Length = 3
                });
                var afterResize = Call(new()
                {
                    Operation = "Read",
                    Handle = handle,
                    Count = 5
                });
                await Task.WhenAll(write, beforeResize, resize, afterResize);
                check(beforeResize.Result.Data!.AsSpan().SequenceEqual("abcde"u8) && afterResize.Result.Data!.AsSpan().SequenceEqual("abc"u8),
                    "Pipelined mutations preserve write/read/resize ordering");
                await Call(new()
                {
                    Operation = "Close",
                    Handle = handle
                });
                var parallelPings = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Call(new() { Operation = "Ping" })));
                check(parallelPings.All(x => x.Error is null), "The request window remains usable after concurrent IO and close");
            }
            store.Update(s => { var d = s.Devices.Single(x => x.Id == device.Id); s.Devices[s.Devices.IndexOf(d)] = d with { Enabled = false }; return true; });
            await transport.SendAsync(new RpcRequest(), deadline.Token);
            check((await transport.ReceiveAsync<RpcResponse>(deadline.Token)).Error == "AccessDenied", "Revocation affects an already authenticated connection");
        }
        finally { await service.StopAsync(CancellationToken.None); }
    }
}
