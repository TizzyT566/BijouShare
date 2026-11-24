using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using DokanNet;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class ClientSelfTests
{
    private static void CheckMountLogonAccess(Action<bool, string> check)
    {
        using var owner = WindowsIdentity.GetCurrent();
        using var anonymous = WindowsIdentity.GetAnonymous();
        var access = new MountLogonAccess();
        check(access.Allows(owner) && !access.Allows(anonymous) && !access.Allows(null),
            "A mounted volume admits its Windows owner and rejects anonymous and missing caller tokens");
        // Compare logon IDs without creating a second Windows logon or requesting elevation.
        var otherLogon = ElevatedDriveAlias.AuthenticationId(owner.AccessToken) ^ long.MinValue;
        check(!access.AllowsLogon(otherLogon), "A second logon of the same user has no drive access");

        using var linked = ElevatedDriveAlias.OpenLinkedToken(owner.AccessToken);
        using var counterpart = linked is null ? null : new WindowsIdentity(linked.DangerousGetHandle());
        if (counterpart is not null && !new WindowsPrincipal(owner).IsInRole(WindowsBuiltInRole.Administrator))
        {
            check(!access.Allows(counterpart), "The owner's linked administrator starts without drive access");
            access.SetElevatedAllowed(true);
            check(access.Allows(owner) && access.Allows(counterpart) && !access.AllowsLogon(otherLogon),
                "Enabling access admits exactly the owner's linked administrator logon");
            access.SetElevatedAllowed(false);
            check(access.Allows(owner) && !access.Allows(counterpart),
                "Disabling elevated access revokes the paired logon and preserves the owner's access");
        }
        else
        {
            var rejected = false;
            try { access.SetElevatedAllowed(true); }
            catch (UnauthorizedAccessException) { rejected = true; }
            check(rejected && access.Allows(owner), "A logon without a paired administrator retains ordinary drive access");
        }
    }

    public static async Task<int> RunAsync()
    {
        await ProtocolSelfTests.RunAsync();
        await HybridSelfTests.RunAsync();
        var passed = 0;
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            passed++;
            Console.WriteLine("PASS: " + label);
        }
        void Reject<T>(Action action, string label) where T : Exception
        {
            try
            {
                action();
                throw new InvalidOperationException("Expected rejection: " + label);
            }
            catch (T) { Check(true, label); }
        }
        await MultiServerSelfTests.RunAsync(Check);
        ClientSetupSelfTests.Run(Check);
        await ClientSetupSelfTests.ActivationHandoff(Check);
        ClientProfileSelfTests.Run(Check);
        CheckMountLogonAccess(Check);
        await ClientManagementSelfTests.RunAsync(Check);

        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--data-dir", "--probe"]), "A missing CLI value cannot consume the next command");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--data-dir", "-h"]), "A missing CLI value cannot consume a short help option");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--probe", "--self-test"]), "Conflicting client commands are rejected");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--unknown"]), "Unknown client options fail clearly");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--server", "fileserver", "--server-name", "ClientOverride"]),
            "Client setup cannot override the server-owned folder name");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["wad://fileserver:7443", "--skip-server-verification"]),
            "A URI activation cannot disable server identity binding");
        Check(ClientSettings.NormalizeMountPoint("n:") == "N:\\", "Drive letters normalize consistently");

        var settings = ClientSettings.Create("Self-test device");
        settings.Validate();
        Check(!settings.IsConfigured, "A new persistent device starts without a server");
        Reject<InvalidDataException>(() => settings.Validate(true), "An unconfigured device cannot start a connection");
        var copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        var other = ClientSettings.Create("Another device");
        Check(other.DeviceId != settings.DeviceId && other.MlKemPublicKey != settings.MlKemPublicKey,
            "Distinct client profiles generate independent ML-KEM key pairs and device IDs");
        copy.PublicKey = other.PublicKey;
        Reject<InvalidDataException>(() => copy.Validate(), "Mismatched public/private client identity is rejected");
        copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        copy.ProtectedMlKemPrivateSeed = other.ProtectedMlKemPrivateSeed;
        Reject<InvalidDataException>(() => copy.Validate(), "A different protected ML-KEM seed cannot impersonate the saved identity");
        copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        copy.DeviceId = other.DeviceId;
        Reject<InvalidDataException>(() => copy.Validate(), "Changing the public device ID without changing the keys is rejected");
        copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        copy.RequestTimeoutSeconds = 0;
        Reject<InvalidDataException>(() => copy.Validate(), "Invalid request timeout is rejected before mounting");
        copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        copy.DeviceName = " ambiguous device ";
        Reject<InvalidDataException>(() => copy.Validate(), "Device names reject surrounding whitespace before enrollment export");
        using var serverKey = KeyAgreement.NewKey();
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--import-enrollment", "old.json"]), "A classical enrollment bundle cannot establish a v6 server identity");
        MultiServerSettings(Check);
        Reject<ArgumentException>(() => StorageLease.Acquire("relative-data-directory").Dispose(), "A relative state directory is rejected before changing filesystem permissions");

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var waitingSettings = Wire.Decode<ClientSettings>(Wire.Encode(settings));
            var endpoint = waitingSettings.AddServer("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, null, trustedServerId: new string('a', 64));
            using var connection = new RemoteConnection(waitingSettings.ForServer(endpoint), NullLogger<RemoteConnection>.Instance);
            var pending = connection.CallAsync(new()
            {
                Operation = "Ping"
            });
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var accepted = await listener.AcceptTcpClientAsync(deadline.Token);
            var stopwatch = Stopwatch.StartNew();
            await Task.Run(connection.Dispose).WaitAsync(TimeSpan.FromSeconds(5));
            try
            {
                await pending;
                throw new InvalidOperationException("Expected connection shutdown.");
            }
            catch (RemoteException ex) when (ex.Code == "Disconnected") { }
            Check(stopwatch.Elapsed < TimeSpan.FromSeconds(5), "Service shutdown cancels a stalled network handshake promptly");
        }
        finally { listener.Stop(); }
        await QueuedCancellation(settings, serverKey, Check);

        var temp = Path.Combine(Path.GetTempPath(), "BijouShare-client-tests", Guid.NewGuid().ToString("N"));
        try
        {
            using (var lease = StorageLease.Acquire(temp))
                Reject<IOException>(() => StorageLease.Acquire(temp).Dispose(), "A second process cannot acquire the same private state");
            File.WriteAllText(Path.Combine(temp, ".instance.lock"), "existing lock content");
            using (StorageLease.Acquire(temp))
            {
            }
            Check(File.ReadAllText(Path.Combine(temp, ".instance.lock")) == "existing lock content", "Acquiring a state lease never truncates an existing file");
        }
        finally { if (Directory.Exists(temp)) Directory.Delete(temp, true); }

        var remote = new ScriptedConnection();
        var transfers = new TransferMeter();
        var operations = new DriveOperations(remote, NullLogger<DriveOperations>.Instance, "Test drive", transfers);
        var info = new MockDokanFileInfo { WhatGetRequestorShouldReturn = System.Security.Principal.WindowsIdentity.GetCurrent() };
        Check(operations.GetVolumeInformation(out var label, out var features, out var format, out _, info) == NtStatus.Success &&
            label == "Test drive" && format == "NTFS" &&
            features == (FileSystemFeatures.CasePreservedNames | FileSystemFeatures.UnicodeOnDisk),
            "Windows sees a UAC-compatible filesystem name, the user's volume label and the supported filesystem capabilities");
        var unrelatedRoot = Directory.CreateTempSubdirectory("BijouShare-label-test-");
        try
        {
            Reject<IOException>(() => new MountedDriveLabel(unrelatedRoot.FullName, label, operations).Dispose(),
                "A directory handle opened on another volume cannot be used to relabel it");
        }
        finally { unrelatedRoot.Delete(); }
        var handle = Guid.NewGuid();
        using var anonymous = System.Security.Principal.WindowsIdentity.GetAnonymous();
        Check(operations.CreateFile("\\", DokanNet.FileAccess.GenericRead, FileShare.ReadWrite,
            FileMode.Open, FileOptions.None, FileAttributes.Directory, new MockDokanFileInfo { WhatGetRequestorShouldReturn = anonymous }) == NtStatus.AccessDenied && remote.Last is null,
            "An open without the mount owner's SID cannot reach the server");
        Check(operations.CreateFile("\\Team\\secret.bin", DokanNet.FileAccess.GenericWrite, FileShare.ReadWrite,
            FileMode.CreateNew, FileOptions.Encrypted, FileAttributes.Normal, new MockDokanFileInfo()) == unchecked((NtStatus)0xC00000BB) && remote.Last is null,
            "Unsupported EFS requests fail before creating an unencrypted file");
        remote.Respond = _ => throw new RemoteException("AccessDenied");
        NtStatus DeniedOpen(DokanNet.FileAccess desired) => operations.CreateFile("\\Team\\New folder", desired,
            FileShare.Read, FileMode.Open, FileOptions.None, FileAttributes.Directory,
            new MockDokanFileInfo { IsDirectory = true, WhatGetRequestorShouldReturn = System.Security.Principal.WindowsIdentity.GetCurrent() });
        Check(DeniedOpen(DokanNet.FileAccess.Delete | DokanNet.FileAccess.ReadAttributes) == NtStatus.CannotDelete &&
            DeniedOpen(DokanNet.FileAccess.GenericAll) == NtStatus.CannotDelete,
            "A denied delete-access open ends on the child without invoking Dokany's parent-open fallback");
        Check(DeniedOpen(DokanNet.FileAccess.ReadAttributes) == NtStatus.AccessDenied,
            "Ordinary denied attribute opens retain their access-denied status");
        remote.Respond = _ => new() { Handle = handle, Entry = Entry("test.bin") };
        Check(operations.CreateFile("\\Team\\test.bin", DokanNet.FileAccess.GenericWrite, FileShare.ReadWrite,
            FileMode.Open, FileOptions.WriteThrough, FileAttributes.Normal, info) == NtStatus.Success && remote.Last!.WriteThrough,
            "Native write-through opens retain their durability request");
        var beforeInvalid = remote.Calls.Count;
        Check(operations.ReadFile("\\Team\\test.bin", new byte[1], out var invalidRead, -1, info) == NtStatus.InvalidParameter &&
            invalidRead == 0 && remote.Calls.Count == beforeInvalid,
            "Negative read offsets fail before sending filesystem requests");
        Check(operations.WriteFile("\\Team\\test.bin", new byte[2], out var invalidWrite, long.MaxValue, info) == NtStatus.InvalidParameter &&
            invalidWrite == 0 && remote.Calls.Count == beforeInvalid,
            "An overflowing write range fails before writing a partial prefix");
        remote.Respond = _ => new() { Length = 1 };
        info.WriteToEndOfFile = true;
        Check(operations.WriteFile("\\Team\\test.bin", [1], out invalidWrite, -1, info) == NtStatus.Success &&
            invalidWrite == 1 && remote.Last is { Append: true, Offset: 0 },
            "Append ignores the native offset sentinel and targets the server EOF");
        info.WriteToEndOfFile = false;
        remote.Respond = _ => throw new RemoteException("Timeout");
        Check(operations.ReadFile("\\Team\\test.bin", new byte[1], out _, 0, info) == NtStatus.IoTimeout,
            "A queued request timeout reports native IO timeout instead of disconnection");

        remote.Respond = _ => new() { Length = 0 };
        Check(operations.WriteFile("\\Team\\test.bin", [1, 2, 3], out var written, 0, info) == NtStatus.Unsuccessful && written == 0,
            "A zero-byte normal write acknowledgement fails instead of looping forever");
        info.PagingIo = true;
        Check(operations.WriteFile("\\Team\\test.bin", [1, 2, 3], out written, 0, info) == NtStatus.Success && written == 0 && remote.Last!.PagingIo,
            "A paging write clipped at EOF terminates with the acknowledged byte count");
        info.PagingIo = false;
        remote.Respond = _ => new() { Length = 2 };
        Check(operations.WriteFile("\\Team\\test.bin", [1, 2, 3], out written, 0, info) == NtStatus.Success && written == 2,
            "Short write acknowledgements preserve the actual partial byte count");
        var largeWrite = System.Security.Cryptography.RandomNumberGenerator.GetBytes(Wire.MaxChunk + 73);
        using (var assembled = new MemoryStream())
        {
            remote.Respond = request =>
            {
                assembled.Write(request.Data!.AsSpan(request.DataOffset, request.DataCount));
                return new()
                {
                    Length = request.DataCount
                };
            };
            Check(operations.WriteFile("\\Team\\test.bin", largeWrite, out written, 0, info) == NtStatus.Success &&
                written == largeWrite.Length && assembled.ToArray().AsSpan().SequenceEqual(largeWrite),
                "Large Windows write buffers retain exact bytes across transfer chunk boundaries");
        }
        remote.Respond = request => new() { Data = new byte[request.Count + 1] };
        Check(operations.ReadFile("\\Team\\test.bin", new byte[2], out var read, 0, info) == NtStatus.Unsuccessful && read == 0,
            "Oversized read replies cannot overflow the Windows buffer");
        remote.Respond = _ => new() { Data = [9, 8] };
        var buffer = new byte[3];
        Check(operations.ReadFile("\\Team\\test.bin", buffer, out read, 0, info) == NtStatus.Success && read == 2 && buffer[0] == 9,
            "Short reads stop at EOF with the correct byte count");
        var transferred = transfers.Totals();
        Check(transferred.ReadBytes == 2 && transferred.WriteBytes == largeWrite.Length + 3,
            "Client transfer totals count validated file payload once across short and chunked I/O, excluding failed requests");
        var secondRemote = new ScriptedConnection
        {
            Respond = request => request.Offset == 0
                ? new() { Length = request.DataCount }
                : throw new RemoteException("AccessDenied")
        };
        var secondDrive = new DriveOperations(secondRemote, NullLogger<DriveOperations>.Instance, "Second drive", transfers);
        var partialStatus = secondDrive.WriteFile("\\backup.bin", largeWrite, out var partial, 0, new MockDokanFileInfo());
        Check(partialStatus == NtStatus.AccessDenied && partial == Wire.LegacyMaxChunk &&
            transfers.Totals().WriteBytes == transferred.WriteBytes + partial,
            "A second drive contributes acknowledged chunks to the same client totals even when a later chunk fails");

        var directoryInfo = new MockDokanFileInfo { IsDirectory = true };
        remote.Respond = request => request.Offset == 0
            ? new()
            {
                Entries = [Entry("first.txt")],
                More = true,
                Length = 256
            }
            : new()
            {
                Entries = [Entry("second.txt"), Entry("skip.bin")],
                More = false,
                Length = 258
            };
        Check(operations.FindFilesWithPattern("\\Team", "*.txt", out var entries, directoryInfo) == NtStatus.Success && entries.Count == 2 &&
            remote.Last is { SearchPattern: "*.txt", Count: 0, BasicDirectoryInfo: true },
            "Explorer requests server-side pattern matching and filters legacy unfiltered pages");
        var modified = DateTime.UtcNow;
        var metadata = new RemoteEntry("Résumé.txt", FileAttributes.ReadOnly, 9876543210L, modified.AddDays(-3), modified, modified, Permission.FullControl);
        var directoryPage = Wire.Decode<RpcResponse>(Wire.Encode(new RpcResponse { Items = [DirectoryItem.FromEntry(metadata)] }));
        remote.Respond = _ => directoryPage;
        Check(operations.FindFiles("\\Team", out entries, directoryInfo) == NtStatus.Success &&
            entries is [{ FileName: "Résumé.txt", Attributes: FileAttributes.ReadOnly, Length: 9876543210L } item] &&
            item.CreationTime == metadata.CreationTime.ToLocalTime() && item.LastAccessTime == modified.ToLocalTime() &&
            item.LastWriteTime == modified.ToLocalTime(), "Compact directory entries preserve names, flags, 64-bit sizes and all Windows timestamps");
        remote.Respond = _ => new() { Entries = [], More = true, Length = 0 };
        Check(operations.FindFiles("\\Team", out _, directoryInfo) == NtStatus.Unsuccessful,
            "A non-advancing directory cursor fails instead of hanging the driver");
        Check(operations.SetAllocationSize("\\Team\\test.bin", -1, info) == NtStatus.InvalidParameter,
            "Negative allocation sizes are rejected");
        remote.Respond = _ => new();
        Check(operations.SetAllocationSize("\\Team\\test.bin", 1024, info) == NtStatus.Success && remote.Last!.Operation == "Allocate",
            "Allocation changes do not require a separate metadata-read permission");

        remote.Respond = _ => new() { Permissions = Permission.CreateFiles | Permission.CreateDirectories | Permission.ReadPermissions };
        Check(operations.GetFileSecurity("\\Team\\test.bin", out var security, AccessControlSections.Access, info) == NtStatus.Success &&
            (Granted(security) & (FileSystemRights.WriteData | FileSystemRights.AppendData)) == 0,
            "Directory-create permissions cannot project as file-write permissions");
        Check(operations.GetFileSecurity("\\Team", out security, AccessControlSections.Access, directoryInfo) == NtStatus.Success &&
            (Granted(security) & (FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories)) != 0,
            "Directory security descriptors retain the correct create rights");
        remote.Respond = _ => new() { Permissions = Permission.ListDirectory | Permission.ReadPermissions };
        Check(operations.GetFileSecurity("\\", out security, AccessControlSections.Access, directoryInfo) == NtStatus.Success &&
            Granted(security).HasFlag(FileSystemRights.Traverse), "Explorer can traverse a listable virtual root");
        Check(operations.GetFileSecurity("\\Team\\test.bin", out security, AccessControlSections.Access, info) == NtStatus.Success &&
            !Granted(security).HasFlag(FileSystemRights.ExecuteFile), "Directory listing does not grant execute access to files");
        remote.Respond = _ => new() { Permissions = Permission.ReadData | Permission.ReadPermissions };
        Check(operations.GetFileSecurity("\\Team\\test.bin", out security, AccessControlSections.Access, info) == NtStatus.Success &&
            Granted(security).HasFlag(FileSystemRights.ExecuteFile), "The file descriptor matches the server's read and execute check");
        remote.Respond = _ => new() { Permissions = Permission.Rename | Permission.ReadPermissions };
        Check(operations.GetFileSecurity("\\Team\\test.bin", out security, AccessControlSections.Access, info) == NtStatus.Success &&
            (Granted(security) & FileSystemRights.Delete) != 0,
            "Rename permission admits Windows DELETE-access handles while the server controls deletion");

        remote.Respond = _ => new();
        var beforeCleanup = remote.Calls.Count;
        operations.Cleanup("\\Team\\test.bin", info);
        operations.Cleanup("\\Team\\test.bin", info);
        Check(remote.Calls.Count == beforeCleanup + 1 && remote.Last!.Operation == "Cleanup",
            "Cleanup is sent once and retains the remote context until final close");
        info.PagingIo = true;
        remote.Respond = _ => new() { Data = [7] };
        Check(operations.ReadFile("\\Team\\test.bin", new byte[1], out read, 0, info) == NtStatus.Success &&
            remote.Last!.PagingIo && remote.Last.Handle == handle,
            "Late paging reads retain their original remote handle after cleanup");
        remote.Respond = _ => new();
        operations.CloseFile("\\Team\\test.bin", info);
        var afterClose = remote.Calls.Count;
        operations.CloseFile("\\Team\\test.bin", info);
        Check(info.Context is null && remote.Calls.Count == afterClose && remote.Last!.Operation == "Close",
            "Final close releases a retained handle exactly once");
        Console.WriteLine($"Client: {passed} checks passed.");
        return 0;
    }

    private static void MultiServerSettings(Action<bool, string> check)
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "BijouShare-client-settings-tests"));
        var directory = Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "client.json");
        try
        {
            var original = ClientSettings.Create("Shared device");
            original.AddDrive("N:");
            original.AddDrive("P:");
            using var ec = KeyAgreement.NewKey();
            using var kem = HybridKem.Generate();
            var serverEc = ec.ExportSubjectPublicKeyInfo();
            var serverKem = kem.ExportPublicKey();
            var id = ServerIdentityNaming.Id(serverEc, serverKem);
            var code = new string('x', 32);
            original.AddServer("archive", 7443, code, "N:", new string('f', 64));
            original.AddServer("archive", 7443, code, "P:", new string('f', 64));
            var legacy = System.Text.Json.Nodes.JsonNode.Parse(Wire.Encode(original))!.AsObject();
            legacy.Remove("identityFormat");
            var previous = System.Text.Encoding.UTF8.GetBytes(legacy.ToJsonString());
            File.WriteAllBytes(path, previous);
            try
            {
                ClientSettings.Load(path);
                throw new InvalidOperationException("Accepted obsolete client settings.");
            }
            catch (InvalidDataException)
            {
                check(File.ReadAllBytes(path).SequenceEqual(previous), "An existing obsolete profile fails closed with its contents intact");
            }
            File.Delete(path);
            var current = ClientSettings.Create("Device");
            current.AddDrive("N:");
            current.AddDrive("P:");
            current.Save(path);
            var endpoint = current.AddServer("archive", 7443, null, "N:", id);
            var otherDrive = current.AddServer("archive", 7443, null, "P:", id);
            var view = current.ForServer(endpoint);
            view.RememberServerIdentity(id, "Archive", serverEc, serverKem);
            var saved = ClientSettings.Load(path);
            check(saved.Servers.All(e => e.ServerId == id && e.FolderName == "Archive_" + id[..16] &&
                e.ServerIdentityPublicKey == Convert.ToBase64String(serverEc) && e.ServerMlKemPublicKey == Convert.ToBase64String(serverKem)),
                "Authenticated connections save the expected identity and both persistent server public keys across drives");
            var alias = current.AddServer("archive-alias", 7443, null, "N:", id);
            var unproven = current.AddServer("unseen-alias", 7443, null, "N:", id);
            current.ForServer(alias).RememberServerIdentity(id, "Archive", serverEc, serverKem);
            view.RememberServerIdentity(id, "Archive-New", serverEc, serverKem);
            var renamed = ClientSettings.Load(path);
            check(otherDrive.FolderName == "Archive-New_" + id[..16] && alias.FolderName == otherDrive.FolderName &&
                renamed.Servers.Single(s => s.Host == alias.Host).FolderName == otherDrive.FolderName &&
                unproven.FolderName is null && unproven.ServerIdentityPublicKey is null && unproven.ServerMlKemPublicKey is null,
                "A rename propagates to every proven alias while an unobserved address with the same expected ID stays unverified");
            using var differentKem = HybridKem.Generate();
            try
            {
                view.RememberServerIdentity(id, "Archive-New", serverEc, differentKem.ExportPublicKey());
                throw new InvalidOperationException("Accepted a replacement server ML-KEM key.");
            }
            catch (ServerIdentityMismatchException) { check(ClientSettings.Load(path).Servers[0].ServerMlKemPublicKey == Convert.ToBase64String(serverKem),
                "A changed ML-KEM key cannot replace an existing pin or its saved keys"); }
            current.RemoveServer("archive", 7443, "N:");
            check(!view.IsVerificationCurrent && current.Servers.All(s => s.TrustedServerId == id),
                "Removing one drive entry invalidates its active view and preserves the other drive's expected fingerprint");
        }
        finally
        {
            var resolved = Path.GetFullPath(directory);
            if (!resolved.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Unsafe settings test cleanup path.");
            Directory.Delete(resolved, true);
        }
    }

    private static async Task QueuedCancellation(ClientSettings settings, ECDiffieHellman serverKey, Action<bool, string> check)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var full = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var sessionTicket = Guid.NewGuid();
        var fileHandle = Guid.NewGuid();
        var directoryHandle = Guid.NewGuid();
        var createDirectory = new RpcRequest { Operation = "Open", Directory = true, Mode = FileMode.CreateNew, Path = @"\Media\New folder" };
        using var serverKem = HybridKem.Generate();
        var kemPublic = serverKem.ExportPublicKey();
        var identityPublic = serverKey.ExportSubjectPublicKeyInfo();
        var fingerprint = ServerIdentityNaming.Id(identityPublic, kemPublic);
        var localRoot = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        localRoot.RequestTimeoutSeconds = 5;
        var directory = Path.Combine(Path.GetTempPath(), "BijouShare-handshake-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var profilePath = Path.Combine(directory, "client.json");
        localRoot.AttachPath(profilePath);
        var server = localRoot.AddServer("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, null, trustedServerId: fingerprint);
        var localSettings = localRoot.ForServer(server);
        var peer = ServePeerAsync();
        using var connection = new RemoteConnection(localSettings, NullLogger<RemoteConnection>.Instance);
        try
        {
            var established = await connection.CallAsync(new() { Operation = "Write" }, token: deadline.Token);
            check(server.TrustedServerId == fingerprint && server.PresentedServerId == fingerprint &&
                server.ServerMlKemPublicKey == Convert.ToBase64String(kemPublic), "The first authorized write can use the pinned server without another verification step");
            try
            {
                await connection.CallForIdentityAsync(new(), null, new string('f', 64), deadline.Token);
                throw new InvalidOperationException("Forwarded an RPC to the wrong server identity.");
            }
            catch (RemoteException ex) when (ex.Code == "InvalidHandle") { check(true, "A stale folder route cannot send an RPC to a different server"); }
            var pending = Enumerable.Range(0, 16).Select(i => connection.CallAsync(new(), token: deadline.Token)).ToArray();
            await full.Task.WaitAsync(deadline.Token);
            connection.PrepareAfterWake(); // A delivered notification must not interrupt these active calls.
            using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
            try
            {
                await connection.CallAsync(new(), token: cancel.Token);
                throw new InvalidOperationException("Expected queued cancellation.");
            }
            catch (RemoteException ex) when (ex.Code == "Timeout") { }
            release.SetResult();
            var replies = await Task.WhenAll(pending);
            var next = await connection.CallAsync(new(), token: deadline.Token);
            check(replies.All(x => x.Generation == established.Generation) && next.Generation == established.Generation,
                "Canceling an unsent queued request preserves all in-flight IO and the authenticated generation");
            var append = await connection.CallAsync(new() { Operation = "Write", Handle = fileHandle, Append = true, Data = [1, 2, 3] },
                established.Generation, deadline.Token);
            check(append.Generation == established.Generation && append.Response.Length == 3,
                "A lost append acknowledgement is recovered from the original lease after a dropped reconnect handshake");
            var created = await connection.CallAsync(createDirectory, token: deadline.Token);
            check(created.Generation == established.Generation && created.Response.Handle == directoryHandle,
                "A directory creation lost before delivery executes once after the server confirms it was never admitted");
            try
            {
                await connection.CallAsync(createDirectory with { Path = @"\Media\Uncertain" }, token: deadline.Token);
                throw new InvalidOperationException("Repeated an operation with an unknown outcome.");
            }
            catch (RemoteException ex) when (ex.Code == "OutcomeUnknown")
            { check(true, "An uncertain directory creation is never reissued"); }
            var reopened = await connection.CallAsync(new RpcRequest { Operation = "Open", Path = @"\Media\Uncertain" }, token: deadline.Token);
            check(reopened.Generation == established.Generation && reopened.Response.Handle == fileHandle,
                "An open whose result never reached Dokan releases only its own server handle before the next open");
            var read = new RpcRequest { Operation = "Read", Handle = fileHandle, Count = 1 };
            var resumedRead = await connection.CallAsync(read, established.Generation, deadline.Token);
            check(resumedRead.Generation == established.Generation && resumedRead.Response.Data is [9],
                "A handle-bound read retries on a fresh transport only after the server confirms the original lease");
            connection.PrepareAfterWake();
            try
            {
                await connection.CallAsync(read, established.Generation, deadline.Token);
                throw new InvalidOperationException("Sent an old file handle on a replacement lease.");
            }
            catch (RemoteException ex) when (ex.Code == "InvalidHandle") { }
            var fresh = await connection.CallAsync(new(), token: deadline.Token);
            check(fresh.Generation != established.Generation, "An expired lease invalidates old handles and allows new path requests");
            connection.Dispose();
            await peer;
        }
        finally
        {
            await deadline.CancelAsync();
            release.TrySetResult();
            listener.Stop();
            try
            {
                await peer;
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException) { }
            File.Delete(profilePath);
            Directory.Delete(directory);
        }

        async Task<SecureTransport> AcceptSessionAsync(TcpClient socket, Guid offered, Guid confirmed)
        {
            var stream = socket.GetStream();
            var hello = await SecureTransport.ReadPlainAsync<ClientHello>(stream, deadline.Token);
            using var ephemeral = KeyAgreement.NewKey();
            var staticEc = KeyAgreement.Agree(serverKey, Convert.FromBase64String(hello.ClientPublicKey!));
            var ephemeralEc = KeyAgreement.Agree(ephemeral, hello.EphemeralPublicKey);
            var (ciphertext, ephemeralKem) = HybridKem.Encapsulate(hello.MlKemPublicKey!);
            var (identityCiphertext, clientKem) = HybridKem.Encapsulate(hello.IdentityMlKemPublicKey!);
            byte[] material;
            try
            {
                var challenge = new ServerHello(RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
                {
                    Version = Wire.Version, CryptoSuite = Wire.CryptoSuite, ServerName = "TestServer", ServerId = fingerprint,
                    GlobalIdentityPublicKey = identityPublic, ServerMlKemPublicKey = kemPublic,
                    MlKemCiphertext = ciphertext, IdentityMlKemCiphertext = identityCiphertext
                };
                await SecureTransport.WritePlainAsync(stream, challenge, deadline.Token);
                var exchange = await SecureTransport.ReadPlainAsync<ClientKeyExchange>(stream, deadline.Token);
                var serverSecret = serverKem.Decapsulate(exchange.MlKemCiphertext);
                var secret = KeyAgreement.SessionSecret(staticEc, ephemeralEc, clientKem, serverSecret, ephemeralKem);
                try
                {
                    var transcript = KeyAgreement.Transcript(hello, challenge, exchange);
                    await SecureTransport.WritePlainAsync(stream, new ServerProof(KeyAgreement.Proof(secret, transcript, "server")), deadline.Token);
                    var proof = await SecureTransport.ReadPlainAsync<ClientProof>(stream, deadline.Token);
                    if (!KeyAgreement.Equals(KeyAgreement.Proof(secret, transcript, "client"), proof.Proof))
                        throw new CryptographicException("Invalid mock client proof.");
                    material = KeyAgreement.SessionMaterial(secret, transcript);
                }
                finally { CryptographicOperations.ZeroMemory(secret); CryptographicOperations.ZeroMemory(serverSecret); }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(staticEc);
                CryptographicOperations.ZeroMemory(ephemeralEc);
                CryptographicOperations.ZeroMemory(ephemeralKem);
                CryptographicOperations.ZeroMemory(clientKem);
            }
            SecureTransport secure;
            try
            {
                secure = new SecureTransport(stream, material, true, hello.BinaryPayloads);
            }
            finally { CryptographicOperations.ZeroMemory(material); }
            try
            {
                await secure.SendAsync(new RpcResponse { DeviceName = settings.DeviceName, SupportsSessionResume = true }, deadline.Token);
                var resume = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (resume.Operation != "ResumeSession" || resume.Handle != offered)
                    throw new InvalidOperationException("Expected the saved ticket on the first encrypted RPC.");
                await secure.SendAsync(new RpcResponse { RequestId = resume.RequestId, Handle = confirmed }, deadline.Token);
                return secure;
            }
            catch { secure.Dispose(); throw; }
        }

        async Task ServePeerAsync()
        {
            long receipt;
            using (var socket = await listener.AcceptTcpClientAsync(deadline.Token))
            using (var secure = await AcceptSessionAsync(socket, Guid.Empty, sessionTicket))
            {
                var first = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                try
                {
                    check(first.Operation == "Write",
                        "A pinned connection delivers the authorized file operation");
                    await secure.SendAsync(new RpcResponse { RequestId = first.RequestId }, deadline.Token);
                }
                finally { first.ReleasePayload(); }
                var ids = new List<long>();
                for (var index = 0; index < 16; index++)
                {
                    var request = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                    ids.Add(request.RequestId);
                    request.ReleasePayload();
                }
                full.SetResult();
                await release.Task.WaitAsync(deadline.Token);
                foreach (var id in ids.AsEnumerable().Reverse())
                    await secure.SendAsync(new RpcResponse { RequestId = id }, deadline.Token);
                var last = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                try
                {
                    await secure.SendAsync(new RpcResponse { RequestId = last.RequestId }, deadline.Token);
                }
                finally { last.ReleasePayload(); }
                var append = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                try
                {
                    if (append.Operation != "Write" || !append.Append || append.Handle != fileHandle ||
                        append.DataCount != 3 || append.OutcomeId <= first.OutcomeId || append.RecoveryAttempt)
                        throw new InvalidOperationException("Missing tracked append.");
                    receipt = append.OutcomeId;
                }
                finally { append.ReleasePayload(); }
                // Simulate a committed append whose acknowledgement never reached the client.
            }
            using (var unavailable = await listener.AcceptTcpClientAsync(deadline.Token))
            {
                await SecureTransport.ReadPlainAsync<ClientHello>(unavailable.GetStream(), deadline.Token);
            }
            using (var socket = await listener.AcceptTcpClientAsync(deadline.Token))
            using (var secure = await AcceptSessionAsync(socket, sessionTicket, sessionTicket))
            {
                var query = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (query.Operation != "GetOutcome" || query.OutcomeId != receipt)
                    throw new InvalidOperationException("An uncertain append must be queried, never sent twice.");
                await secure.SendAsync(new RpcResponse { RequestId = query.RequestId, Length = 3 }, deadline.Token);
                // Lose the next frame before the complete directory creation reaches the dispatcher.
                await socket.GetStream().ReadExactlyAsync(new byte[1], deadline.Token);
            }
            using (var socket = await listener.AcceptTcpClientAsync(deadline.Token))
            using (var secure = await AcceptSessionAsync(socket, sessionTicket, sessionTicket))
            {
                var query = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (query.Operation != "GetOutcome" || query.OutcomeId <= receipt) throw new InvalidOperationException("Missing directory receipt query.");
                await secure.SendAsync(new RpcResponse { RequestId = query.RequestId, Error = "OutcomeNotExecuted" }, deadline.Token);
                var create = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (create.Operation != "Open" || create.Path != createDirectory.Path || !create.Directory || create.Mode != FileMode.CreateNew ||
                    create.OutcomeId != query.OutcomeId || !create.RecoveryAttempt)
                    throw new InvalidOperationException("Directory recovery lost its original parameters or receipt.");
                await secure.SendAsync(new RpcResponse { RequestId = create.RequestId, Handle = directoryHandle }, deadline.Token);
                var uncertain = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (uncertain.Operation != "Open" || uncertain.RecoveryAttempt || uncertain.OutcomeId <= create.OutcomeId)
                    throw new InvalidOperationException("Missing fresh directory operation.");
                receipt = uncertain.OutcomeId;
            }
            using (var socket = await listener.AcceptTcpClientAsync(deadline.Token))
            using (var secure = await AcceptSessionAsync(socket, sessionTicket, sessionTicket))
            {
                var query = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (query.Operation != "GetOutcome" || query.OutcomeId != receipt) throw new InvalidOperationException("Missing uncertain directory query.");
                await secure.SendAsync(new RpcResponse { RequestId = query.RequestId, Error = "OutcomeUnknown" }, deadline.Token);
                var abandon = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (abandon.Operation != "AbandonOpen" || abandon.OutcomeId != receipt || abandon.Handle != Guid.Empty || abandon.DeleteOnClose)
                    throw new InvalidOperationException("A failed open's handle must be released by its exact original receipt.");
                await secure.SendAsync(new RpcResponse { RequestId = abandon.RequestId }, deadline.Token);
                var reopened = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (reopened.Operation != "Open" || reopened.OutcomeId <= receipt || reopened.RecoveryAttempt)
                    throw new InvalidOperationException("Expected the new open after releasing the unclaimed handle.");
                await secure.SendAsync(new RpcResponse { RequestId = reopened.RequestId, Handle = fileHandle }, deadline.Token);
                var read = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (read.Operation != "Read" || read.Handle != fileHandle)
                    throw new InvalidOperationException("Expected a read on the existing handle.");
                // A half-open connection can accept the request and then remain silent after wake.
                try { await secure.ReceiveAsync<RpcRequest>(deadline.Token); throw new InvalidOperationException("Expected the client to abandon the stalled transport."); }
                catch (IOException) { }
            }
            using (var socket = await listener.AcceptTcpClientAsync(deadline.Token))
            using (var secure = await AcceptSessionAsync(socket, sessionTicket, sessionTicket))
            {
                var retried = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (retried.Operation != "Read" || retried.Handle != fileHandle)
                    throw new InvalidOperationException("Expected a retried read on the existing handle.");
                await secure.SendAsync(new RpcResponse { RequestId = retried.RequestId, Data = [9] }, deadline.Token);
                try { await secure.ReceiveAsync<RpcRequest>(deadline.Token); throw new InvalidOperationException("Expected idle wake disconnect."); }
                catch (EndOfStreamException) { }
            }
            using (var socket = await listener.AcceptTcpClientAsync(deadline.Token))
            using (var secure = await AcceptSessionAsync(socket, sessionTicket, Guid.NewGuid()))
            {
                var fresh = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (fresh.Operation != "Ping") throw new InvalidOperationException("A stale handle reached a fresh lease.");
                await secure.SendAsync(new RpcResponse { RequestId = fresh.RequestId }, deadline.Token);
                var end = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                if (end.Operation != "EndSession") throw new InvalidOperationException("Expected explicit lease release.");
                await secure.SendAsync(new RpcResponse { RequestId = end.RequestId }, deadline.Token);
            }
        }
    }

    private static RemoteEntry Entry(string name) => new(name, FileAttributes.Normal, 3,
        DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, Permission.FullControl);

    private static FileSystemRights Granted(FileSystemSecurity security) => security
        .GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier))
        .Cast<FileSystemAccessRule>().Aggregate((FileSystemRights)0, (rights, rule) => rights | rule.FileSystemRights);

    private sealed class ScriptedConnection : IRemoteConnection
    {
        public Func<RpcRequest, RpcResponse> Respond { get; set; } = _ => new();
        public RpcRequest? Last
        {
            get; private set;
        }
        public List<RpcRequest> Calls { get; } = [];
        public RemoteReply Call(RpcRequest request, long? expectedGeneration = null)
        {
            Last = request;
            Calls.Add(request);
            return new(Respond(request), 1);
        }
        public Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default)
            => Task.FromResult(Call(request, expectedGeneration));
    }
}
