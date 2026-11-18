using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class InviteSelfTests
{
    public static async Task RunAsync()
    {
        var passed = 0;
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            passed++;
            Console.WriteLine("PASS: " + label);
        }
        void Reject(Action action, string label)
        {
            try
            {
                action();
            }
            catch (ArgumentException) { Check(true, label); return; }
            throw new InvalidOperationException("FAIL: " + label);
        }
        void Status(Action action, string expected, string label)
        {
            try
            {
                action();
            }
            catch (RemoteException exception) when (exception.Code == expected) { Check(true, label); return; }
            throw new InvalidOperationException("FAIL: " + label);
        }
        static EnrollmentRequest Request(string name = "Invited laptop")
        {
            using var key = KeyAgreement.NewKey();
            return TestRegistration.Create(name, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        }

        var root = Path.GetFullPath(Path.Combine("artifacts", "invite-tests", Guid.NewGuid().ToString("N")));
        var (store, options, fixtureDevice, fixtureKey, _) = ServerSelfTests.CreateFixture(root);
        var groups = fixtureDevice.GroupIds;
        Reject(() => store.CreateInvite("Invalid uses", groups, 0, null), "Invite use limits must be positive or unlimited");
        Reject(() => store.CreateInvite("Expired", groups, null, DateTime.UtcNow.AddMinutes(-1)), "New invites cannot already be expired");
        Reject(() => store.CreateInvite("Unknown group", [Guid.NewGuid()], 1, null), "Invites can grant only existing groups");
        var beforeForbiddenInvite = store.Revision;
        Reject(() => store.CreateInvite("Privileged invitation", [.. groups, StateStore.AdministratorGroupId], null, null),
            "An invite cannot include the Administrator group, even alongside an ordinary group");
        Check(store.Revision == beforeForbiddenInvite, "Rejecting a privileged invitation leaves server state untouched");
        Reject(() => store.CreateInvite("Bad date", groups, 1, DateTime.SpecifyKind(DateTime.UtcNow.AddHours(1), DateTimeKind.Unspecified)),
            "Invite expirations must use UTC in persisted state");
        var unlimited = store.CreateInvite("Unlimited", groups, null, null);
        var single = store.CreateInvite("Single use", [], 1, DateTime.UtcNow.AddHours(1));
        Check(unlimited.Code.Length == 32 && unlimited.Code != single.Code && unlimited.Invite.CodeHash != single.Invite.CodeHash &&
            unlimited.Code.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_'),
            "Independent invite codes use 192 random bits in URI-safe characters");
        var persisted = File.ReadAllText(Path.Combine(options.DataDirectory, "state.json"));
        Check(!persisted.Contains(unlimited.Code, StringComparison.Ordinal) && !persisted.Contains(single.Code, StringComparison.Ordinal),
            "Server state stores only invite hashes, never the bearer codes");

        var request = Request();
        var first = store.RedeemInvite(request, unlimited.Code);
        Check(first.Enabled && first.GroupIds.SequenceEqual(groups) && store.FindPendingDevice(first.Id) is null &&
            store.Read(state => state.Invites.Single(invite => invite.Id == unlimited.Invite.Id).Uses) == 1,
            "A valid invite directly approves the proven device with its configured groups");
        var revision = store.Revision;
        var second = store.RedeemInvite(request, single.Code);
        Check(second.Id == first.Id && second.HasSameIdentity(first) && second.GroupIds.SequenceEqual(first.GroupIds) &&
            store.Revision == revision && store.Read(state => state.Invites.Single(invite => invite.Id == single.Invite.Id).Uses) == 0,
            "Known device reconnects neither consume invites nor replace keys or groups");
        var reloaded = new StateStore(options);
        Check(reloaded.FindRegisteredDevice(first.Id)!.HasSameIdentity(first) &&
            reloaded.Read(state => state.Invites.Single(invite => invite.Id == unlimited.Invite.Id).Uses) == 1,
            "Invite limits and approved device identities survive reload");

        var competitors = Enumerable.Range(0, 8).Select(_ => Request()).ToArray();
        var results = await Task.WhenAll(competitors.Select(candidate => Task.Run(() =>
        {
            try
            {
                store.RedeemInvite(candidate, single.Code);
                return true;
            }
            catch (RemoteException exception) when (exception.Code == "InvalidInvite") { return false; }
        })));
        Check(results.Count(result => result) == 1 && store.Read(state => state.Invites.Single(invite => invite.Id == single.Invite.Id).Uses) == 1,
            "Concurrent enrollment atomically consumes the final invite use exactly once");
        Status(() => store.RedeemInvite(Request(), single.Code), "InvalidInvite", "An exhausted invite cannot approve another device");
        var pending = Request("Waiting laptop");
        store.QueueRegistration(pending);
        var promoted = store.RedeemInvite(pending, unlimited.Code);
        Check(store.FindPendingDevice(promoted.Id) is null && promoted.GroupIds.SequenceEqual(groups),
            "A valid invite promotes an existing pending request without leaving a duplicate identity");
        var rejected = Request("Rejected laptop");
        store.QueueRegistration(rejected);
        store.RejectDevice(TestRegistration.RecordId(rejected.DeviceId));
        var usesBefore = store.Read(state => state.Invites.Single(invite => invite.Id == unlimited.Invite.Id).Uses);
        Status(() => store.RedeemInvite(rejected, unlimited.Code), "DeviceRejected", "An invite cannot override an administrator's rejection");
        store.Update(state => { var index = state.Devices.FindIndex(device => device.Id == first.Id); state.Devices[index] = state.Devices[index] with { Enabled = false }; return true; });
        Status(() => store.RedeemInvite(request, unlimited.Code), "DeviceBlocked", "An invite cannot re-enable a blocked approved device");
        Check(store.Read(state => state.Invites.Single(invite => invite.Id == unlimited.Invite.Id).Uses) == usesBefore,
            "Rejected and blocked attempts do not consume invite uses");
        Status(() => store.RedeemInvite(Request(), new string('x', 32)), "InvalidInvite", "Unknown invite codes grant no access");
        var expired = store.CreateInvite("Expiring", groups, null, DateTime.UtcNow.AddHours(1));
        store.Update(state => { var index = state.Invites.FindIndex(invite => invite.Id == expired.Invite.Id); state.Invites[index] = state.Invites[index] with { ExpiresUtc = DateTime.UtcNow.AddSeconds(-1) }; return true; });
        Status(() => store.RedeemInvite(Request(), expired.Code), "InvalidInvite", "An expired invite cannot approve a device");
        var revoked = store.CreateInvite("Revoked", groups, null, null);
        store.RevokeInvite(revoked.Invite.Id);
        Status(() => store.RedeemInvite(Request(), revoked.Code), "InvalidInvite", "A revoked invite cannot approve a device");

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        using var server = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        await server.StartAsync(deadline.Token);
        try
        {
            using var networkIdentity = KeyAgreement.NewKey();
            var privateKey = networkIdentity.ExportPkcs8PrivateKey();
            try
            {
                using var identityKem = HybridKem.Generate();
                var id = DeviceIdentity.Id(networkIdentity.ExportSubjectPublicKeyInfo(), identityKem.ExportPublicKey());
                var proofInvite = store.CreateInvite("Private-key proof required", groups, 1, null);
                using (var socket = new TcpClient())
                using (var ephemeral = KeyAgreement.NewKey())
                using (var kem = HybridKem.Generate())
                {
                    var unprovenId = id;
                    await socket.ConnectAsync("127.0.0.1", options.Port, deadline.Token);
                    await SecureTransport.WritePlainAsync(socket.GetStream(), new ClientHello(Wire.Version, unprovenId.ToString(),
                        RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
                    {
                        CryptoSuite = Wire.CryptoSuite,
                        MlKemPublicKey = kem.ExportPublicKey(),
                        IdentityMlKemPublicKey = identityKem.ExportPublicKey(),
                        InviteEnrollment = true,
                        BinaryPayloads = true,
                        DeviceName = "Unproven invitation",
                        ClientPublicKey = Convert.ToBase64String(networkIdentity.ExportSubjectPublicKeyInfo())
                    }, deadline.Token);
                    var serverHello = await SecureTransport.ReadPlainAsync<ServerHello>(socket.GetStream(), deadline.Token);
                    var (ciphertext, secret) = HybridKem.Encapsulate(serverHello.ServerMlKemPublicKey!);
                    CryptographicOperations.ZeroMemory(secret);
                    await SecureTransport.WritePlainAsync(socket.GetStream(), new ClientKeyExchange(ciphertext), deadline.Token);
                    _ = await SecureTransport.ReadPlainAsync<ServerProof>(socket.GetStream(), deadline.Token);
                    await SecureTransport.WritePlainAsync(socket.GetStream(), new ClientProof(new byte[32]), deadline.Token);
                    var ended = await socket.GetStream().ReadAsync(new byte[1], deadline.Token);
                    Check(ended == 0 && store.FindRegisteredDevice(unprovenId) is null &&
                        store.Read(state => state.Invites.Single(invite => invite.Id == proofInvite.Invite.Id).Uses) == 0,
                        "Invite capability without private-key proof cannot approve a device or consume a use");
                }
                var wireInvite = store.CreateInvite("Network", groups, 1, null);
                var proxy = new TcpListener(IPAddress.Loopback, 0);
                proxy.Start();
                try
                {
                    using var captured = new MemoryStream();
                    async Task Relay()
                    {
                        using var client = await proxy.AcceptTcpClientAsync(deadline.Token);
                        using var upstream = new TcpClient();
                        await upstream.ConnectAsync(IPAddress.Loopback, options.Port, deadline.Token);
                        async Task Capture()
                        {
                            var buffer = new byte[4096];
                            while (true)
                            {
                                var length = await client.GetStream().ReadAsync(buffer, deadline.Token);
                                if (length == 0)
                                {
                                    upstream.Client.Shutdown(SocketShutdown.Send);
                                    return;
                                }
                                captured.Write(buffer, 0, length);
                                await upstream.GetStream().WriteAsync(buffer.AsMemory(0, length), deadline.Token);
                            }
                        }
                        await Task.WhenAll(Capture(), upstream.GetStream().CopyToAsync(client.GetStream(), deadline.Token));
                    }
                    var relay = Relay();
                    using (var socket = new TcpClient())
                    using (var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", ((IPEndPoint)proxy.LocalEndpoint).Port,
                        id, "Invited network laptop", privateKey, identityKem, deadline.Token, store.ServerId, wireInvite.Code))
                    using (var rpc = new RpcClientSession(transport))
                    {
                        var approved = store.FindRegisteredDevice(id)!;
                        var response = await rpc.CallAsync(new()
                        {
                            Operation = "List"
                        }, deadline.Token);
                        Check(approved.Enabled && response.Entries!.Any(entry => entry.Name == "Team") &&
                            KeyAgreement.Equals(transport.RemoteServerMlKemPublicKey!, Convert.FromBase64String(store.ServerMlKemPublicKey)) &&
                            transport.RemoteServerId == store.ServerId,
                            "Encrypted invite enrollment authenticates and exposes authorized files immediately with the permanent key pinned");
                    }
                    await relay.WaitAsync(deadline.Token);
                    var wire = Encoding.UTF8.GetString(captured.ToArray());
                    Check(wire.Contains("Invited network laptop", StringComparison.Ordinal) && !wire.Contains(wireInvite.Code, StringComparison.Ordinal),
                        "The network handshake exposes no plaintext invite code");
                }
                finally { proxy.Stop(); }
                using (var socket = new TcpClient())
                using (var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                    id, "Invited network laptop", privateKey, identityKem, deadline.Token, store.ServerId, wireInvite.Code))
                    Check(store.Read(state => state.Invites.Single(invite => invite.Id == wireInvite.Invite.Id).Uses) == 1,
                        "An exhausted invite does not prevent its already approved client from reconnecting with the same pins");
                var failedInvite = store.CreateInvite("Authentication check", groups, 1, null);
                var wrongFingerprint = (store.ServerId[0] == '0' ? "1" : "0") + store.ServerId[1..];
                using var invitedEc = KeyAgreement.NewKey();
                using var invitedKem = HybridKem.Generate();
                var invitedId = DeviceIdentity.Id(invitedEc.ExportSubjectPublicKeyInfo(), invitedKem.ExportPublicKey());
                var invitedPrivate = invitedEc.ExportPkcs8PrivateKey();
                try
                {
                    using var socket = new TcpClient();
                    using var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                        invitedId, "Untrusted hybrid identity", invitedPrivate, invitedKem, deadline.Token, wrongFingerprint, failedInvite.Code);
                    throw new InvalidOperationException("Accepted the wrong trusted server fingerprint.");
                }
                catch (ServerIdentityMismatchException)
                {
                    Check(store.Read(state => state.Invites.Single(invite => invite.Id == failedInvite.Invite.Id).Uses) == 0 &&
                        store.FindRegisteredDevice(invitedId) is null && store.FindPendingDevice(invitedId) is null,
                        "A mismatched server fingerprint cannot consume an invite or queue an enrollment");
                }
                finally { CryptographicOperations.ZeroMemory(invitedPrivate); }
                try
                {
                    using var badInviteIdentity = KeyAgreement.NewKey();
                    using var badInviteKem = HybridKem.Generate();
                    var badInvitePrivate = badInviteIdentity.ExportPkcs8PrivateKey();
                    try
                    {
                        using var socket = new TcpClient();
                        using var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                            DeviceIdentity.Id(badInviteIdentity.ExportSubjectPublicKeyInfo(), badInviteKem.ExportPublicKey()),
                            "Bad invite", badInvitePrivate, badInviteKem, deadline.Token, store.ServerId, new string('x', 32));
                        throw new InvalidOperationException("Accepted an invalid invite over TCP.");
                    }
                    finally { CryptographicOperations.ZeroMemory(badInvitePrivate); }
                }
                catch (RemoteException exception) when (exception.Code == "InvalidInvite")
                {
                    Check(true, "Invalid invite enrollment returns an encrypted rejection over TCP");
                }
            }
            finally { CryptographicOperations.ZeroMemory(privateKey); }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            CryptographicOperations.ZeroMemory(fixtureKey);
        }
        Console.WriteLine($"Invites: {passed} checks passed.");
    }
}
