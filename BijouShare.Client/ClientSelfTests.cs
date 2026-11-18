using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using DokanNet;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class ClientSelfTests
{
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
        await ClientManagementSelfTests.RunAsync(Check);

        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--data-dir", "--probe"]), "A missing CLI value cannot consume the next command");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--data-dir", "-h"]), "A missing CLI value cannot consume a short help option");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--probe", "--create-device"]), "Conflicting client commands are rejected");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--unknown"]), "Unknown client options fail clearly");
        Reject<ArgumentException>(() => ClientCommandLine.Parse(["--server", "fileserver", "--server-name", "ClientOverride"]),
            "Client setup cannot override the server-owned folder name");
        Check(ClientSettings.NormalizeMountPoint("n:") == "N:\\", "Drive letters normalize consistently");

        var settings = ClientSettings.Create("Self-test device");
        settings.Validate();
        Check(!settings.IsConfigured, "A new persistent device needs only its server address before requesting approval");
        Reject<InvalidDataException>(() => settings.Validate(true), "An unconfigured device cannot start a connection");
        var pendingSettings = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        pendingSettings.Host = "fileserver";
        pendingSettings.Validate(true);
        Check(pendingSettings.IsConfigured && !pendingSettings.IsEnrolled, "A configured device can request approval without an imported bundle or server pin");
        var copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        var other = ClientSettings.Create("Another device");
        copy.PublicKey = other.PublicKey;
        Reject<InvalidDataException>(() => copy.Validate(), "Mismatched public/private client identity is rejected");
        copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        copy.RequestTimeoutSeconds = 0;
        Reject<InvalidDataException>(() => copy.Validate(), "Invalid request timeout is rejected before mounting");
        copy = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        copy.DeviceName = " ambiguous device ";
        Reject<InvalidDataException>(() => copy.Validate(), "Device names reject surrounding whitespace before enrollment export");
        using var serverKey = KeyAgreement.NewKey();
        var bundle = new EnrollmentBundle(settings.DeviceId, "test-user", "fileserver", 7443,
            Convert.ToBase64String(serverKey.ExportSubjectPublicKeyInfo()));
        Reject<ArgumentException>(() => settings.Enroll(bundle with { DeviceId = Guid.NewGuid().ToString() }), "Enrollment for a different device is rejected");
        Reject<InvalidDataException>(() => settings.Enroll(bundle with { Host = "http://fileserver/path" }), "Enrollment rejects URL-shaped server addresses");
        settings.Enroll(bundle);
        settings.Validate(true);
        Check(settings.IsEnrolled, "A matching enrollment bundle validates successfully");
        await MultiServerSettings(Check);
        Reject<ArgumentException>(() => StorageLease.Acquire("relative-data-directory").Dispose(), "A relative state directory is rejected before changing filesystem permissions");

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var waitingSettings = Wire.Decode<ClientSettings>(Wire.Encode(settings));
            waitingSettings.Host = "127.0.0.1";
            waitingSettings.Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var connection = new RemoteConnection(waitingSettings, NullLogger<RemoteConnection>.Instance);
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
        await GlobalIdentityProofTampering(settings, serverKey, Check);

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
        var operations = new DriveOperations(remote, NullLogger<DriveOperations>.Instance);
        var info = new MockDokanFileInfo();
        var handle = Guid.NewGuid();
        remote.Respond = _ => new() { Handle = handle, Entry = Entry("test.bin") };
        Check(operations.CreateFile("\\Team\\secret.bin", DokanNet.FileAccess.GenericWrite, FileShare.ReadWrite,
            FileMode.CreateNew, FileOptions.Encrypted, FileAttributes.Normal, new MockDokanFileInfo()) == unchecked((NtStatus)0xC00000BB) && remote.Last is null,
            "Unsupported EFS requests fail before creating an unencrypted file");
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
        Check(operations.FindFilesWithPattern("\\Team", "*.txt", out var entries, directoryInfo) == NtStatus.Success && entries.Count == 2,
            "Directory pagination preserves wildcard filtering across pages");
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

    private static async Task MultiServerSettings(Action<bool, string> check)
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "BijouShare-client-settings-tests"));
        var directory = Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "client.json");
        try
        {
            var original = ClientSettings.Create("Shared device identity");
            using var firstKey = KeyAgreement.NewKey();
            var firstPublic = firstKey.ExportSubjectPublicKeyInfo();
            PrivateStorage.AtomicWrite(path, Wire.Encode(new
            {
                original.DeviceId,
                original.DeviceName,
                original.ProtectedPrivateKey,
                original.PublicKey,
                host = "first-server",
                port = 7443,
                serverPublicKey = Convert.ToBase64String(firstPublic),
                mountPoint = "N:\\",
                requestTimeoutSeconds = 30
            }));
            var migrated = ClientSettings.Load(path);
            check(migrated.Servers.Count == 1 && migrated.Servers[0].Host == "first-server" &&
                migrated.DeviceId == original.DeviceId && migrated.PublicKey == original.PublicKey &&
                migrated.Servers[0].ServerPublicKey == Convert.ToBase64String(firstPublic),
                "Legacy client configuration migrates to one server without changing identity or trust");
            var first = migrated.Servers[0];
            var second = migrated.UpsertServer("second-server", 7444, "Media");
            var third = migrated.UpsertServer("third-server", 7445, "Backups");
            migrated.Save(path);
            using var secondKey = KeyAgreement.NewKey();
            using var thirdKey = KeyAgreement.NewKey();
            var secondView = migrated.ForServer(second);
            var thirdView = migrated.ForServer(third);
            var secondId = ServerIdentityNaming.Id("DarkArchives", secondKey.ExportSubjectPublicKeyInfo());
            var thirdId = ServerIdentityNaming.Id("Backups", thirdKey.ExportSubjectPublicKeyInfo());
            await Task.WhenAll(Task.Run(() => secondView.TrustApprovedServer(secondKey.ExportSubjectPublicKeyInfo(), secondId, "DarkArchives", secondKey.ExportSubjectPublicKeyInfo())),
                Task.Run(() => thirdView.TrustApprovedServer(thirdKey.ExportSubjectPublicKeyInfo(), thirdId, "Backups", thirdKey.ExportSubjectPublicKeyInfo())));
            var loaded = ClientSettings.Load(path);
            check(loaded.Servers.Count == 3 && loaded.Servers[0].ServerPublicKey == first.ServerPublicKey &&
                loaded.Servers[1].ServerPublicKey == second.ServerPublicKey && loaded.Servers[2].ServerPublicKey == third.ServerPublicKey,
                "Concurrent approved-server pins persist atomically without losing sibling trust");
            check(loaded.Servers[1].FolderName == "DarkArchives_" + secondId[..16] &&
                loaded.Servers[2].FolderName == "Backups_" + thirdId[..16] && loaded.Servers[1].ServerId == secondId,
                "Drive folders use the first 16 name-bound server-ID characters while retaining the full hash");
            check(secondView.DeviceId == thirdView.DeviceId && secondView.PublicKey == thirdView.PublicKey &&
                secondView.ProtectedPrivateKey.SequenceEqual(thirdView.ProtectedPrivateKey) && secondView.MountPoint == thirdView.MountPoint,
                "All server connections reuse one device identity and one mount point");
            var rejected = false;
            try
            {
                secondView.TrustApprovedServer(firstPublic);
            }
            catch (ServerIdentityMismatchException) { rejected = true; }
            check(rejected && ClientSettings.Load(path).Servers[1].ServerPublicKey == second.ServerPublicKey,
                "A changed server key cannot replace an existing endpoint pin");
            rejected = false;
            var sameDisplayDifferentId = secondId[..16] + new string(secondId[16] == '0' ? '1' : '0', 48);
            try
            {
                secondView.TrustApprovedServer(secondKey.ExportSubjectPublicKeyInfo(), sameDisplayDifferentId, "DarkArchives", secondKey.ExportSubjectPublicKeyInfo());
            }
            catch (CryptographicException) { rejected = true; }
            check(rejected && ClientSettings.Load(path).Servers[1].ServerId == secondId,
                "The complete name-bound hash is validated even when another ID has the same 16-character display prefix");
            rejected = false;
            try
            {
                secondView.TrustApprovedServer(secondKey.ExportSubjectPublicKeyInfo(), ServerIdentityNaming.Id("DarkArchives", thirdKey.ExportSubjectPublicKeyInfo()), "DarkArchives", thirdKey.ExportSubjectPublicKeyInfo());
            }
            catch (ServerIdentityMismatchException) { rejected = true; }
            check(rejected && ClientSettings.Load(path).Servers[1].ServerKeyFingerprint == ServerIdentityNaming.KeyFingerprint(secondKey.ExportSubjectPublicKeyInfo()),
                "A changed global public key cannot replace the stable server trust anchor");
            var renamedId = ServerIdentityNaming.Id("DarkArchives-New", secondKey.ExportSubjectPublicKeyInfo());
            secondView.TrustApprovedServer(secondKey.ExportSubjectPublicKeyInfo(), renamedId, "DarkArchives-New", secondKey.ExportSubjectPublicKeyInfo());
            check(ClientSettings.Load(path).Servers[1].FolderName == "DarkArchives-New_" + renamedId[..16] && renamedId != secondId &&
                ClientSettings.Load(path).Servers[1].ServerKeyFingerprint == ServerIdentityNaming.KeyFingerprint(secondKey.ExportSubjectPublicKeyInfo()),
                "An authenticated rename updates its name-bound ID while preserving the server-wide key trust anchor");
            foreach (var invalidName in new[] { "two words", "has_underscore", "döt", "", new string('x', 101) })
            {
                rejected = false;
                try
                {
                    secondView.TrustApprovedServer(secondKey.ExportSubjectPublicKeyInfo(), renamedId, invalidName, secondKey.ExportSubjectPublicKeyInfo());
                }
                catch (ArgumentException) { rejected = true; }
                check(rejected, "Invalid authenticated server names are rejected: " + (invalidName.Length == 0 ? "empty" : invalidName[..Math.Min(20, invalidName.Length)]));
            }
            rejected = false;
            try
            {
                migrated.UpsertServer("other-server", 7443, "media");
            }
            catch (ArgumentException) { rejected = true; }
            check(rejected && migrated.UpsertServer("SECOND-SERVER", 7444) == second && migrated.Servers.Count == 3,
                "Server aliases are unique and repeated host/port configuration reuses the endpoint");
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
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var localSettings = Wire.Decode<ClientSettings>(Wire.Encode(settings));
        localSettings.Host = "127.0.0.1";
        localSettings.Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var peer = ServePeerAsync();
        using var connection = new RemoteConnection(localSettings, NullLogger<RemoteConnection>.Instance);
        try
        {
            var established = await connection.CallAsync(new(), token: deadline.Token);
            var pending = Enumerable.Range(0, 16).Select(_ => connection.CallAsync(new(), token: deadline.Token)).ToArray();
            await full.Task.WaitAsync(deadline.Token);
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
            finished.SetResult();
            await peer;
        }
        finally
        {
            await deadline.CancelAsync();
            release.TrySetResult();
            finished.TrySetResult();
            listener.Stop();
            try
            {
                await peer;
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException) { }
        }

        async Task ServePeerAsync()
        {
            using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
            var stream = socket.GetStream();
            var hello = await SecureTransport.ReadPlainAsync<ClientHello>(stream, deadline.Token);
            var identitySecret = KeyAgreement.Agree(serverKey, Convert.FromBase64String(settings.PublicKey));
            var (ciphertext, kemSecret) = HybridKem.Encapsulate(hello.MlKemPublicKey!);
            byte[] material;
            try
            {
                using var ephemeral = KeyAgreement.NewKey();
                var secret = KeyAgreement.Agree(ephemeral, hello.EphemeralPublicKey);
                try
                {
                    var challenge = new ServerHello(RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo(), [])
                    {
                        Version = Wire.Version,
                        CryptoSuite = Wire.CryptoSuite,
                        MlKemCiphertext = ciphertext,
                        IdentityPublicKey = hello.ClientPublicKey is null ? null : serverKey.ExportSubjectPublicKeyInfo(),
                        ServerId = hello.ServerIdentityMetadata ? ServerIdentityNaming.Id("TestServer", serverKey.ExportSubjectPublicKeyInfo()) : null,
                        ServerName = hello.ServerIdentityMetadata ? "TestServer" : null,
                        GlobalIdentityPublicKey = hello.ServerIdentityMetadata ? serverKey.ExportSubjectPublicKeyInfo() : null
                    };
                    var transcript = KeyAgreement.Transcript(hello, challenge, serverKey.ExportSubjectPublicKeyInfo());
                    await SecureTransport.WritePlainAsync(stream, challenge with
                    {
                        Proof = KeyAgreement.HybridProof(identitySecret, secret, kemSecret, transcript, "server"),
                        ServerIdentityProof = hello.ServerIdentityMetadata ? KeyAgreement.HybridProof(identitySecret, secret, kemSecret, transcript, "server-identity") : null
                    }, deadline.Token);
                    var proof = await SecureTransport.ReadPlainAsync<ClientProof>(stream, deadline.Token);
                    if (!KeyAgreement.Equals(KeyAgreement.HybridProof(identitySecret, secret, kemSecret, transcript, "client"), proof.Proof))
                        throw new CryptographicException("Invalid test peer proof.");
                    material = KeyAgreement.SessionMaterial(identitySecret, secret, kemSecret, transcript);
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            }
            finally { CryptographicOperations.ZeroMemory(identitySecret); CryptographicOperations.ZeroMemory(kemSecret); }
            SecureTransport secure;
            try
            {
                secure = new SecureTransport(stream, material, true, hello.BinaryPayloads);
            }
            finally { CryptographicOperations.ZeroMemory(material); }
            using (secure)
            {
                await secure.SendAsync(new RpcResponse { DeviceName = settings.DeviceName }, deadline.Token);
                var first = await secure.ReceiveAsync<RpcRequest>(deadline.Token);
                try
                {
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
                await finished.Task.WaitAsync(deadline.Token);
            }
        }
    }

    private static async Task GlobalIdentityProofTampering(ClientSettings settings, ECDiffieHellman deviceServerKey, Action<bool, string> check)
    {
        using var globalKey = KeyAgreement.NewKey();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var peer = ServeAsync();
        var privateKey = PrivateStorage.Unprotect(settings.ProtectedPrivateKey);
        try
        {
            using var socket = new TcpClient();
            try
            {
                using var unexpected = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port,
                    settings.DeviceId, settings.DeviceName, privateKey, deviceServerKey.ExportSubjectPublicKeyInfo(), deadline.Token);
                throw new InvalidOperationException("Accepted a forged global identity proof.");
            }
            catch (CryptographicException ex)
            {
                check(ex.Message.Contains("global identity authentication", StringComparison.Ordinal),
                    "A valid per-device proof cannot substitute for possession of the server-wide identity private key");
            }
            await peer;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            listener.Stop();
        }

        async Task ServeAsync()
        {
            using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
            socket.NoDelay = true;
            var stream = socket.GetStream();
            var hello = await SecureTransport.ReadPlainAsync<ClientHello>(stream, deadline.Token);
            using var ephemeral = KeyAgreement.NewKey();
            var (ciphertext, kemSecret) = HybridKem.Encapsulate(hello.MlKemPublicKey!);
            var ephemeralSecret = KeyAgreement.Agree(ephemeral, hello.EphemeralPublicKey);
            var response = new ServerHello(RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo(), [])
            {
                Version = Wire.Version,
                CryptoSuite = Wire.CryptoSuite,
                MlKemCiphertext = ciphertext,
                IdentityPublicKey = deviceServerKey.ExportSubjectPublicKeyInfo(),
                GlobalIdentityPublicKey = globalKey.ExportSubjectPublicKeyInfo(),
                ServerId = ServerIdentityNaming.Id("DarkArchives", globalKey.ExportSubjectPublicKeyInfo()),
                ServerName = "DarkArchives"
            };
            var transcript = KeyAgreement.Transcript(hello, response, response.IdentityPublicKey);
            var identitySecret = KeyAgreement.Agree(deviceServerKey, Convert.FromBase64String(hello.ClientPublicKey!));
            var globalSecret = KeyAgreement.Agree(globalKey, Convert.FromBase64String(hello.ClientPublicKey!));
            try
            {
                var corruptProof = KeyAgreement.HybridProof(globalSecret, ephemeralSecret, kemSecret, transcript, "server-identity");
                corruptProof[0] ^= 1;
                await SecureTransport.WritePlainAsync(stream, response with
                {
                    Proof = KeyAgreement.HybridProof(identitySecret, ephemeralSecret, kemSecret, transcript, "server"),
                    ServerIdentityProof = corruptProof
                }, deadline.Token);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(identitySecret);
                CryptographicOperations.ZeroMemory(globalSecret);
                CryptographicOperations.ZeroMemory(ephemeralSecret);
                CryptographicOperations.ZeroMemory(kemSecret);
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
