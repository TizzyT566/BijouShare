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
        using var identity = KeyAgreement.NewKey();
        using var wrongIdentity = KeyAgreement.NewKey();
        var privateKey = identity.ExportPkcs8PrivateKey();
        var wrongPrivateKey = wrongIdentity.ExportPkcs8PrivateKey();
        var id = Guid.NewGuid();
        var name = "My custom workstation";
        var publicKey = Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        using var server = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        await server.StartAsync(deadline.Token);

        async Task<SecureTransport> Connect(byte[]? pin = null, byte[]? clientKey = null, string? deviceName = null)
        {
            var socket = new TcpClient();
            try
            {
                return await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                    id.ToString(), deviceName ?? name, clientKey ?? privateKey, pin, deadline.Token);
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

        try
        {
            // Merely advertising someone else's public identity cannot fill or overwrite the queue.
            using (var socket = new TcpClient())
            using (var ephemeral = KeyAgreement.NewKey())
            using (var kem = HybridKem.Generate())
            {
                await socket.ConnectAsync("127.0.0.1", options.Port, deadline.Token);
                var hello = new ClientHello(Wire.Version, id.ToString(), RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
                {
                    CryptoSuite = Wire.CryptoSuite,
                    MlKemPublicKey = kem.ExportPublicKey(),
                    BinaryPayloads = true,
                    DeviceName = name,
                    ClientPublicKey = publicKey
                };
                await SecureTransport.WritePlainAsync(socket.GetStream(), hello, deadline.Token);
                var challenge = await SecureTransport.ReadPlainAsync<ServerHello>(socket.GetStream(), deadline.Token);
                Check(challenge.PendingApproval && challenge.IdentityPublicKey is { } pendingKey &&
                    KeyAgreement.Equals(pendingKey, challenge.EphemeralPublicKey), "Unapproved devices receive only an ephemeral registration challenge");
                await SecureTransport.WritePlainAsync(socket.GetStream(), new ClientProof(new byte[32]), deadline.Token);
                var end = await socket.GetStream().ReadAsync(new byte[1], deadline.Token);
                Check(end == 0 && store.FindPendingDevice(id) is null, "A device is not queued without proof of its static private key");
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

            var approved = store.ApproveDevice(id, [], KeyAgreement.Fingerprint(publicKey));
            var pin = Convert.FromBase64String(approved.ServerPublicKey);
            Check(approved.ServerPublicKey != fixtureDevice.ServerPublicKey && store.FindPendingDevice(id) is null,
                "Approval consumes the request and creates a distinct permanent server key pair for this device");
            using (var transport = await Connect())
            using (var rpc = new RpcClientSession(transport))
            {
                Check(transport.RemoteIdentityPublicKey is { } remote && KeyAgreement.Equals(remote, pin) && transport.RemoteDeviceName == name,
                    "The first approved connection returns the permanent identity for client pinning");
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
                Check(KeyAgreement.Equals(transport.RemoteIdentityPublicKey!, pin) && store.FindRegisteredDevice(id)!.ServerPublicKey == approved.ServerPublicKey,
                    "Subsequent connections reuse and verify the same permanent server identity");
            }
            var beforeRename = store.FindRegisteredDevice(id)!;
            name = "Work laptop";
            using (var transport = await Connect(pin))
            {
                var renamed = store.FindRegisteredDevice(id)!;
                Check(transport.RemoteDeviceName == name && renamed.Name == name && renamed.Enabled &&
                    renamed.GroupIds.SequenceEqual(beforeRename.GroupIds) && renamed.ClientPublicKey == beforeRename.ClientPublicKey &&
                    renamed.ServerPublicKey == beforeRename.ServerPublicKey &&
                    renamed.ProtectedServerPrivateKey.SequenceEqual(beforeRename.ProtectedServerPrivateKey) &&
                    new StateStore(options).FindRegisteredDevice(id)!.Name == name,
                    "An authenticated approved client name change persists while retaining groups, keys, and approval");
            }
            revision = store.Revision;
            using (var transport = await Connect(pin))
                Check(store.Revision == revision && transport.RemoteDeviceName == name,
                    "An unchanged approved name reconnects without rewriting server state");
            using (var socket = new TcpClient())
            using (var ephemeral = KeyAgreement.NewKey())
            using (var kem = HybridKem.Generate())
            {
                await socket.ConnectAsync("127.0.0.1", options.Port, deadline.Token);
                var hello = new ClientHello(Wire.Version, id.ToString(), RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
                {
                    CryptoSuite = Wire.CryptoSuite,
                    MlKemPublicKey = kem.ExportPublicKey(),
                    BinaryPayloads = true,
                    DeviceName = "Unproven rename",
                    ClientPublicKey = publicKey
                };
                await SecureTransport.WritePlainAsync(socket.GetStream(), hello, deadline.Token);
                _ = await SecureTransport.ReadPlainAsync<ServerHello>(socket.GetStream(), deadline.Token);
                await SecureTransport.WritePlainAsync(socket.GetStream(), new ClientProof(new byte[32]), deadline.Token);
                var end = await socket.GetStream().ReadAsync(new byte[1], deadline.Token);
                Check(end == 0 && store.Revision == revision && store.FindRegisteredDevice(id)!.Name == name,
                    "Advertising an approved public identity without its private-key proof cannot rename the device");
            }
            try
            {
                using var transport = await Connect(wrongIdentity.ExportSubjectPublicKeyInfo());
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
            Check(store.FindRegisteredDevice(id)!.ServerPublicKey == approved.ServerPublicKey &&
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
