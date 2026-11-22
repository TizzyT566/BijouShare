using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class DeviceApprovalSelfTests
{
    public static async Task RunAsync()
    {
        var count = 0;
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        var root = Path.GetFullPath(Path.Combine("artifacts", "device-approval-tests", Guid.NewGuid().ToString("N")));
        var (store, options, fixtureDevice, fixtureKey, _) = ServerSelfTests.CreateFixture(root);
        store.SetInviteOnly(false);
        using var identity = KeyAgreement.NewKey();
        using var wrongIdentity = KeyAgreement.NewKey();
        var privateKey = identity.ExportPkcs8PrivateKey();
        var wrongPrivateKey = wrongIdentity.ExportPkcs8PrivateKey();
        using var identityKem = HybridKem.Generate();
        var digest = DeviceIdentity.Id(identity.ExportSubjectPublicKeyInfo(), identityKem.ExportPublicKey());
        var id = TestRegistration.RecordId(digest);
        var name = "My custom workstation";
        var publicKey = Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        using var server = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        await server.StartAsync(deadline.Token);

        async Task<SecureTransport> Connect(string? pin = null, byte[]? clientKey = null, string? deviceName = null)
        {
            var socket = new TcpClient();
            try
            {
                return await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                    digest, deviceName ?? name, clientKey ?? privateKey, identityKem, deadline.Token, pin ?? store.ServerId);
            }
            catch { socket.Dispose(); throw; }
        }
        async Task ExpectStatus(string expected, string? deviceName = null)
        {
            try
            {
                using var transport = await Connect(deviceName: deviceName);
                throw new InvalidOperationException("Unexpected approved connection.");
            }
            catch (RemoteException exception) when (exception.Code == expected) { Check(true, "Automatic connection reports " + expected); }
        }

        async Task RejectWrongPersistentKem(bool pending)
        {
            var revisionBefore = store.Revision;
            using (var socket = new TcpClient())
            using (var ephemeral = KeyAgreement.NewKey())
            using (var kem = HybridKem.Generate())
            {
                await socket.ConnectAsync("127.0.0.1", options.Port, deadline.Token);
                var hello = new ClientHello(Wire.Version, digest, RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
                {
                    CryptoSuite = Wire.CryptoSuite,
                    MlKemPublicKey = kem.ExportPublicKey(),
                    IdentityMlKemPublicKey = identityKem.ExportPublicKey(),
                    BinaryPayloads = true,
                    DeviceName = "Unproven rename",
                    ClientPublicKey = publicKey
                };
                await SecureTransport.WritePlainAsync(socket.GetStream(), hello, deadline.Token);
                var challenge = await SecureTransport.ReadPlainAsync<ServerHello>(socket.GetStream(), deadline.Token);
                var serverEc = challenge.GlobalIdentityPublicKey ?? throw new InvalidDataException("Missing server identity");
                Check(challenge.PendingApproval == pending && ServerIdentityNaming.Id(serverEc, challenge.ServerMlKemPublicKey!) == store.ServerId,
                    pending ? "Enrollment presents the same global fingerprint as ordinary connections"
                        : "Approved reconnects authenticate against the link's global server keypair");
                using var sensitive = new HandshakeSecrets();
                var serverKem = HybridKem.Encapsulate(challenge.ServerMlKemPublicKey!);
                sensitive.Keep(serverKem.Secret);
                var exchange = new ClientKeyExchange(serverKem.Ciphertext);
                await SecureTransport.WritePlainAsync(socket.GetStream(), exchange, deadline.Token);
                await SecureTransport.ReadPlainAsync<ServerProof>(socket.GetStream(), deadline.Token);
                var transcript = KeyAgreement.Transcript(hello, challenge, exchange);
                using var unrelatedKem = HybridKem.Generate();
                var wrongSecret = sensitive.Keep(KeyAgreement.SessionSecret(
                    sensitive.Keep(KeyAgreement.Agree(identity, serverEc)),
                    sensitive.Keep(KeyAgreement.Agree(ephemeral, challenge.EphemeralPublicKey)),
                    sensitive.Keep(unrelatedKem.Decapsulate(challenge.IdentityMlKemCiphertext!)), serverKem.Secret,
                    sensitive.Keep(kem.Decapsulate(challenge.MlKemCiphertext!))));
                await SecureTransport.WritePlainAsync(socket.GetStream(), new ClientProof(KeyAgreement.Proof(wrongSecret, transcript, "client")), deadline.Token);
                var end = await socket.GetStream().ReadAsync(new byte[1], deadline.Token);
                Check(end == 0 && store.Revision == revisionBefore && store.FindPendingDevice(id) is null,
                    pending ? "Enrollment requires the persistent ML-KEM private key even with all other secrets"
                        : "An approved client cannot start a session or rename its device without the persistent ML-KEM private key");
            }
        }

        try
        {
            await RejectWrongPersistentKem(pending: true);
            using (var locked = File.Open(Path.Combine(store.DataDirectory, "state.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                await ExpectStatus("ConfigurationError");
                Check(store.FindPendingDevice(id) is null, "A failed enrollment write does not report an administrator kick");
            }
            await ExpectStatus("PendingApproval");
            Check(store.FindPendingDevice(id) is { } pending && pending.Name == name && pending.ClientPublicKey == publicKey &&
                store.FindRegisteredDevice(id) is null, "A proven unknown device queues exactly its public identity and remains unapproved");
            try
            {
                files.Execute(Guid.NewGuid(), id, new()
                {
                    Operation = "List"
                });
                throw new InvalidOperationException("Pending file access accepted.");
            }
            catch (UnauthorizedAccessException) { Check(true, "Pending identities have no file-operation authorization"); }
            var revision = store.Revision;
            await ExpectStatus("PendingApproval");
            Check(store.Revision == revision && store.Read(state => state.PendingDevices.Count) == 1,
                "Repeated pending connections neither duplicate requests nor continuously rewrite state");
            var firstSeen = store.FindPendingDevice(id)!.FirstSeenUtc;
            name = "Personal laptop";
            await ExpectStatus("PendingApproval");
            Check(store.FindPendingDevice(id) is { } renamedPending && renamedPending.Name == name &&
                renamedPending.ClientPublicKey == publicKey && renamedPending.FirstSeenUtc == firstSeen &&
                new StateStore(options).FindPendingDevice(id)!.Name == name,
                "A proven client name change updates the pending request and survives a server restart");
            store.RejectDevice(id);
            var reloaded = new StateStore(options);
            Check(reloaded.FindPendingDevice(id)?.Rejected == true, "Rejected approval decisions survive state reload");
            revision = store.Revision;
            await ExpectStatus("DeviceRejected", "Rejected rename");
            Check(store.FindPendingDevice(id) is { Rejected: true } rejected && rejected.Name == name && store.Revision == revision,
                "A reconnect cannot rename or resurrect a rejected request");

            var approved = store.ApproveDevice(id, [], digest);
            var pin = store.ServerId;
            Check(approved.PublicIdentity == digest && store.FindPendingDevice(id) is null,
                "Approval consumes the request and preserves the device identity");
            using (var transport = await Connect())
            using (var rpc = new RpcClientSession(transport))
            {
                Check(transport.RemoteServerId == pin && transport.RemoteServerMlKemPublicKey is { Length: HybridKem.PublicKeySize } && transport.RemoteDeviceName == name,
                    "The first approved connection authenticates both public keys from the link fingerprint");
                var hidden = await rpc.CallAsync(new()
                {
                    Operation = "List"
                }, deadline.Token);
                Check(hidden.Entries is { Count: 0 }, "Approval without group grants exposes no shared locations");
                store.Update(state => { var index = state.Devices.FindIndex(device => device.Id == id); state.Devices[index] = approved with { GroupIds = fixtureDevice.GroupIds }; return true; });
                var visible = await rpc.CallAsync(new()
                {
                    Operation = "List"
                }, deadline.Token);
                Check(visible.Entries!.Any(entry => entry.Name == "Team"), "Device group assignment takes effect on an existing authenticated connection");
            }
            using (var transport = await Connect(pin))
            using (var rpc = new RpcClientSession(transport))
            {
                await rpc.CallAsync(new(), deadline.Token);
                Check(transport.RemoteServerId == pin && store.FindRegisteredDevice(id)!.PublicIdentity == digest,
                    "Subsequent connections reuse and verify the same permanent server identity");
            }
            var beforeRename = store.FindRegisteredDevice(id)!;
            name = "Work laptop";
            using (var transport = await Connect(pin))
            {
                var renamed = store.FindRegisteredDevice(id)!;
                Check(transport.RemoteDeviceName == name && renamed.Name == name && renamed.Enabled &&
                    renamed.GroupIds.SequenceEqual(beforeRename.GroupIds) && renamed.ClientPublicKey == beforeRename.ClientPublicKey &&
                    renamed.ClientMlKemPublicKey == beforeRename.ClientMlKemPublicKey &&
                    new StateStore(options).FindRegisteredDevice(id)!.Name == name,
                    "An authenticated approved client name change persists while retaining groups, keys, and approval");
            }
            revision = store.Revision;
            using (var transport = await Connect(pin))
                Check(store.Revision == revision && transport.RemoteDeviceName == name,
                    "An unchanged approved name reconnects without rewriting server state");
            await RejectWrongPersistentKem(pending: false);
            try
            {
                using var transport = await Connect(new string('f', 64));
                throw new InvalidOperationException("Accepted a mismatched server pin.");
            }
            catch (ServerIdentityMismatchException) { Check(true, "A changed pinned server identity fails closed"); }
            try
            {
                using var transport = await Connect(pin, wrongPrivateKey);
                throw new InvalidOperationException("Accepted another private key for an approved ID.");
            }
            catch (Exception exception) when (exception is IOException or CryptographicException)
            {
                Check(store.FindRegisteredDevice(id)!.ClientPublicKey == publicKey && store.FindPendingDevice(id) is null,
                "An approved device ID cannot be overwritten or requeued using another private key");
            }
            store.Update(state => { var index = state.Devices.FindIndex(device => device.Id == id); state.Devices[index] = state.Devices[index] with { Enabled = false }; return true; });
            revision = store.Revision;
            await ExpectStatus("DeviceBlocked", "Blocked rename");
            Check(store.FindRegisteredDevice(id)!.PublicIdentity == digest &&
                store.FindRegisteredDevice(id)!.Name == name && store.FindPendingDevice(id) is null && store.Revision == revision,
                "Blocking an approved device retains its name and keys without adding another pending request");
            store.Update(state => { var index = state.Devices.FindIndex(device => device.Id == id); state.Devices[index] = state.Devices[index] with { Enabled = true }; return true; });
            using (var transport = await Connect(pin))
            using (var rpc = new RpcClientSession(transport))
            {
                await rpc.CallAsync(new(), deadline.Token);
                Check(true, "Re-enabling an approved device reconnects with its existing pin");
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(wrongPrivateKey);
            CryptographicOperations.ZeroMemory(fixtureKey);
        }
        Console.WriteLine($"Device approval: {count} checks passed.");
    }
}
