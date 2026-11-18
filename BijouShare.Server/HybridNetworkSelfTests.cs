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
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        var root = Path.GetFullPath(Path.Combine("artifacts", "hybrid-network-tests", Guid.NewGuid().ToString("N")));
        var (store, options, approved, privateKey, serverPin) = ServerSelfTests.CreateFixture(root);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        using var server = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        using var ephemeral = KeyAgreement.NewKey();
        using var unapprovedIdentity = KeyAgreement.NewKey();
        using var kem = HybridKem.Generate();
        var unapprovedId = Guid.NewGuid();
        var template = new ClientHello(Wire.Version, unapprovedId.ToString(), RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
        {
            CryptoSuite = Wire.CryptoSuite,
            MlKemPublicKey = kem.ExportPublicKey(),
            DeviceName = "Hybrid regression device",
            ClientPublicKey = Convert.ToBase64String(unapprovedIdentity.ExportSubjectPublicKeyInfo()),
            ServerIdentityMetadata = true,
            BinaryPayloads = true
        };
        await server.StartAsync(deadline.Token);
        try
        {
            async Task RejectHello(ClientHello hello, string label)
            {
                var revision = store.Revision;
                using var socket = new TcpClient();
                await socket.ConnectAsync(IPAddress.Loopback, options.Port, deadline.Token);
                await SecureTransport.WritePlainAsync(socket.GetStream(), hello, deadline.Token);
                var closed = false;
                try
                {
                    closed = await socket.GetStream().ReadAsync(new byte[1], deadline.Token) == 0;
                }
                catch (IOException) { closed = true; }
                Check(closed && store.Revision == revision && store.FindPendingDevice(unapprovedId) is null &&
                    store.FindRegisteredDevice(approved.Id)!.ClientPublicKey == approved.ClientPublicKey,
                    label);
            }

            await RejectHello(template with
            {
                Version = 2,
                DeviceId = approved.Id.ToString(),
                DeviceName = approved.Name,
                ClientPublicKey = approved.ClientPublicKey,
                CryptoSuite = null,
                MlKemPublicKey = null
            }, "An already approved identity cannot downgrade the server to a classical-only v2 handshake");
            await RejectHello(template with
            {
                CryptoSuite = null
            },
                "A v3 hello without its required cryptographic suite is rejected without queuing enrollment");
            await RejectHello(template with
            {
                MlKemPublicKey = null
            },
                "A v3 hello without an ML-KEM public key is rejected without queuing enrollment");
            await RejectHello(template with
            {
                MlKemPublicKey = new byte[HybridKem.PublicKeySize - 1]
            },
                "A truncated ML-KEM public key fails before enrollment or identity changes");
            await RejectHello(template with
            {
                MlKemPublicKey = Enumerable.Repeat((byte)255, HybridKem.PublicKeySize).ToArray()
            },
                "A full-size noncanonical ML-KEM public key is rejected by the native provider before enrollment");

            using (var socket = new TcpClient())
            using (var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", options.Port,
                approved.Id.ToString(), approved.Name, privateKey, serverPin, deadline.Token,
                Convert.FromBase64String(store.ServerPublicKey)))
            using (var rpc = new RpcClientSession(transport))
            {
                var response = await rpc.CallAsync(new()
                {
                    Operation = "Ping"
                }, deadline.Token);
                Check(transport.BinaryPayloads && response.Error is null &&
                    KeyAgreement.Equals(transport.RemoteIdentityPublicKey!, serverPin) && transport.RemoteServerId == store.ServerId,
                    "An approved v3 hybrid client authenticates against its unchanged persistent server pins");
            }
            using (var socket = new TcpClient())
            using (var transport = await AuthenticatedClient.ConnectAsync(socket, "127.0.0.1", options.Port,
                approved.Id.ToString(), privateKey, serverPin, deadline.Token, binaryPayloads: false))
            {
                await transport.SendAsync(new RpcRequest { Operation = "Ping" }, deadline.Token);
                var response = await transport.ReceiveAsync<RpcResponse>(deadline.Token);
                Check(!transport.BinaryPayloads && response.Error is null,
                    "Disabling binary file payloads still uses mandatory hybrid v3 key establishment");
            }

            foreach (var version in new[] { 2, Wire.Version })
            {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                try
                {
                    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    async Task<bool> ServeMissingKem()
                    {
                        using var accepted = await listener.AcceptTcpClientAsync(deadline.Token);
                        var hello = await SecureTransport.ReadPlainAsync<ClientHello>(accepted.GetStream(), deadline.Token);
                        using var fakeEphemeral = KeyAgreement.NewKey();
                        await SecureTransport.WritePlainAsync(accepted.GetStream(), new ServerHello(RandomNumberGenerator.GetBytes(32),
                            fakeEphemeral.ExportSubjectPublicKeyInfo(), new byte[32])
                        {
                            Version = version,
                            CryptoSuite = version == Wire.Version ? Wire.CryptoSuite : null
                        }, deadline.Token);
                        var closed = false;
                        try
                        {
                            closed = await accepted.GetStream().ReadAsync(new byte[1], deadline.Token) == 0;
                        }
                        catch (IOException) { closed = true; }
                        return hello.Version == Wire.Version && hello.CryptoSuite == Wire.CryptoSuite &&
                            hello.MlKemPublicKey is { Length: HybridKem.PublicKeySize } && closed;
                    }
                    var fake = ServeMissingKem();
                    var rejected = false;
                    using (var socket = new TcpClient())
                    {
                        try
                        {
                            using var unexpected = await AuthenticatedClient.ConnectDeviceAsync(socket, "127.0.0.1", port,
                                approved.Id.ToString(), approved.Name, privateKey, serverPin, deadline.Token,
                                Convert.FromBase64String(store.ServerPublicKey), new string('A', 32));
                        }
                        catch (CryptographicException) { rejected = true; }
                    }
                    Check(rejected && await fake && !listener.Pending() && store.FindPendingDevice(unapprovedId) is null,
                        version == 2
                            ? "The client rejects a classical-only server without retrying or transmitting a proof or invite"
                            : "The client rejects a v3 challenge missing ML-KEM ciphertext before transmitting a proof or invite");
                }
                finally { listener.Stop(); }
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            CryptographicOperations.ZeroMemory(privateKey);
        }
        Console.WriteLine($"Hybrid network: {count} checks passed.");
    }
}
