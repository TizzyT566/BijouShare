using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class HybridNetworkSelfTests
{
    public static async Task RunAsync()
    {
        var count = 0;
        void Check(bool ok, string label)
        {
            if (!ok) throw new InvalidOperationException("FAIL: " + label);
            Console.WriteLine("PASS: " + label);
            count++;
        }
        using var clientKem = HybridKem.Generate();
        var root = Path.GetFullPath(Path.Combine("artifacts", "hybrid-network-tests", Guid.NewGuid().ToString("N")));
        var (store, options, approved, clientKey, _) = ServerSelfTests.CreateFixture(root, clientKem);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var token = timeout.Token;
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        using var server = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        await server.StartAsync(token);
        try
        {
            using var ephemeral = KeyAgreement.NewKey();
            using var ephemeralKem = HybridKem.Generate();
            var hello = new ClientHello(Wire.Version, approved.PublicIdentity!, RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
            {
                CryptoSuite = Wire.CryptoSuite, ClientPublicKey = approved.ClientPublicKey, DeviceName = approved.Name,
                IdentityMlKemPublicKey = clientKem.ExportPublicKey(), MlKemPublicKey = ephemeralKem.ExportPublicKey(), BinaryPayloads = true
            };
            async Task<bool> Closed(Stream stream)
            {
                try { return await stream.ReadAsync(new byte[1], token) == 0; }
                catch (IOException) { return true; }
            }
            async Task RejectHello(ClientHello invalid, string label)
            {
                var rev = store.Revision;
                using var socket = new TcpClient();
                await socket.ConnectAsync(IPAddress.Loopback, options.Port, token);
                await SecureTransport.WritePlainAsync(socket.GetStream(), invalid, token);
                Check(await Closed(socket.GetStream()) && store.Revision == rev, label);
            }
            await RejectHello(hello with { Version = 5 }, "Signed v5 cannot downgrade a v6 session");
            await RejectHello(hello with { CryptoSuite = null }, "A missing v6 suite cannot start a session");
            await RejectHello(hello with { MlKemPublicKey = null }, "Classical-only agreement is rejected");
            await RejectHello(hello with { IdentityMlKemPublicKey = null }, "The persistent client ML-KEM public key is mandatory");
            await RejectHello(hello with { IdentityMlKemPublicKey = ephemeralKem.ExportPublicKey() }, "Substituting the static client ML-KEM key invalidates the fingerprint");
            await RejectHello(hello with { MlKemPublicKey = hello.IdentityMlKemPublicKey }, "The ephemeral ML-KEM key must be freshly generated");
            await RejectHello(hello with { EphemeralPublicKey = Convert.FromBase64String(approved.ClientPublicKey) }, "The ephemeral ECDH key must differ from the persistent key");
            await RejectHello(hello with { MlKemPublicKey = Enumerable.Repeat((byte)255, HybridKem.PublicKeySize).ToArray() },
                "The native provider rejects noncanonical ML-KEM public keys before file access");

            using (var socket = new TcpClient())
            using (var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                approved.PublicIdentity!, approved.Name, clientKey, clientKem, token, store.ServerId))
            using (var session = new RpcClientSession(transport))
            {
                var list = await session.CallAsync(new() { Operation = "List" }, token);
                Check(list.Entries!.Any(e => e.Name == "Team") && transport.RemoteServerId == store.ServerId &&
                    KeyAgreement.Equals(Convert.FromBase64String(store.ServerPublicKey), transport.RemoteServerIdentityPublicKey) &&
                    KeyAgreement.Equals(Convert.FromBase64String(store.ServerMlKemPublicKey), transport.RemoteServerMlKemPublicKey),
                    "An enrolled device authenticates both link-bound server keys and lists its group shares");
            }
            using (var socket = new TcpClient())
            using (var transport = await AuthenticatedClient.ConnectAsync(socket, "127.0.0.1", options.Port,
                approved.PublicIdentity!, clientKey, clientKem, store.ServerId, token, binaryPayloads: false))
            {
                await transport.SendAsync(new RpcRequest { Operation = "Ping" }, token);
                var result = await transport.ReceiveAsync<RpcResponse>(token);
                Check(result.Error is null && !transport.BinaryPayloads, "Encrypted JSON file sessions use the same mandatory hybrid protocol");
            }

            async Task RejectPeer(Func<ServerHello, ServerHello> change, bool expectsExchange, string label,
                bool wrongKem = false, bool wrongEc = false, bool reflectedProof = false)
            {
                using var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                async Task<bool> Respond()
                {
                    using var socket = await listener.AcceptTcpClientAsync(token);
                    var stream = socket.GetStream();
                    var client = await SecureTransport.ReadPlainAsync<ClientHello>(stream, token);
                    using var secrets = new HandshakeSecrets();
                    using var dh = KeyAgreement.NewKey();
                    var toClient = HybridKem.Encapsulate(client.IdentityMlKemPublicKey!);
                    secrets.Keep(toClient.Secret);
                    var toEphemeral = HybridKem.Encapsulate(client.MlKemPublicKey!);
                    secrets.Keep(toEphemeral.Secret);
                    var original = new ServerHello(RandomNumberGenerator.GetBytes(32), dh.ExportSubjectPublicKeyInfo())
                    {
                        Version = Wire.Version, CryptoSuite = Wire.CryptoSuite, ServerName = store.ServerName, ServerId = store.ServerId,
                        GlobalIdentityPublicKey = Convert.FromBase64String(store.ServerPublicKey),
                        ServerMlKemPublicKey = Convert.FromBase64String(store.ServerMlKemPublicKey),
                        IdentityMlKemCiphertext = toClient.Ciphertext, MlKemCiphertext = toEphemeral.Ciphertext,
                        InviteEnrollment = true
                    };
                    await SecureTransport.WritePlainAsync(stream, change(original), token);
                    if (!expectsExchange) return await Closed(stream);
                    var exchange = await SecureTransport.ReadPlainAsync<ClientKeyExchange>(stream, token);
                    var keys = store.Read(state => (state.ProtectedServerPrivateKey, state.ProtectedServerMlKemSeed));
                    using var identity = wrongEc ? KeyAgreement.NewKey() : KeyAgreement.ImportPrivate(secrets.Keep(PrivateStorage.Unprotect(keys.ProtectedServerPrivateKey)));
                    using var kem = wrongKem ? HybridKem.Generate() : HybridKem.ImportPrivateSeed(secrets.Keep(PrivateStorage.Unprotect(keys.ProtectedServerMlKemSeed)));
                    var secret = secrets.Keep(KeyAgreement.SessionSecret(
                        secrets.Keep(KeyAgreement.Agree(identity, Convert.FromBase64String(client.ClientPublicKey!))),
                        secrets.Keep(KeyAgreement.Agree(dh, client.EphemeralPublicKey)), toClient.Secret,
                        secrets.Keep(kem.Decapsulate(exchange.MlKemCiphertext)), toEphemeral.Secret));
                    var proof = KeyAgreement.Proof(secret, KeyAgreement.Transcript(client, original, exchange), reflectedProof ? "client" : "server");
                    await SecureTransport.WritePlainAsync(stream, new ServerProof(proof), token);
                    return await Closed(stream);
                }
                var response = Respond();
                var rejected = false;
                using (var socket = new TcpClient())
                {
                    try
                    {
                        using var unexpected = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", port,
                            approved.PublicIdentity!, approved.Name, clientKey, clientKem, token, store.ServerId, new string('A', 32));
                    }
                    catch (CryptographicException) { rejected = true; }
                }
                Check(await response && rejected, label);
            }
            await RejectPeer(s => s with { Version = 5 }, false, "No exchange or invite is sent to a downgraded peer");
            await RejectPeer(s => s with { ServerId = new string('0',64) }, false, "A changed full server fingerprint prevents any key exchange or invite");
            await RejectPeer(s => s with { ServerMlKemPublicKey = ephemeralKem.ExportPublicKey() }, false, "Substituting the server ML-KEM public key invalidates the link");
            await RejectPeer(s => s with { MlKemCiphertext = null }, false, "A stripped ephemeral KEM challenge is rejected");
            await RejectPeer(s => s with { IdentityMlKemCiphertext = null }, false, "A stripped persistent KEM challenge is rejected");
            await RejectPeer(s => s with { ServerName = "ChangedName" }, true, "A modified display name fails key confirmation before any device proof or invite");
            await RejectPeer(s => s, true, "Possession of the correct ECDH server key alone cannot receive a client proof or invite", wrongKem: true);
            await RejectPeer(s => s, true, "Possession of the correct ML-KEM server key alone cannot receive a client proof or invite", wrongEc: true);
            await RejectPeer(s => s, true, "The client confirmation cannot be reflected as the server confirmation", reflectedProof: true);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            CryptographicOperations.ZeroMemory(clientKey);
        }
        Console.WriteLine($"Hybrid network: {count} checks passed.");
    }
}
