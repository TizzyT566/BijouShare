using System.Net;
using System.Net.Sockets;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class NetworkRelaySelfTests
{
    internal static async Task RunAsync(ServerOptions options, StateStore store, Device device, byte[] privateKey,
        HybridKem kem, Action<bool, string> check, CancellationToken token)
    {
        using var target = new TcpListener(IPAddress.Loopback, 0);
        target.Start();
        var port = ((IPEndPoint)target.LocalEndpoint).Port;
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        var share = new NetworkServiceShare(Guid.NewGuid(), "Fixture service", "127.0.0.1", port, NetworkServiceProtocol.Both, true);
        var rule = new AccessRule(Guid.NewGuid(), device.GroupIds[0], share.Id, "", Permission.None, Permission.None, false)
            { NetworkAllow = NetworkServiceAccess.Both };
        store.Update(s => { s.NetworkServices.Add(share); s.Rules.Add(rule); return true; });

        async Task<SecureTransport> Connect() {
            var client = new TcpClient();
            try { return await AuthenticatedClient.ConnectAsync(client, "127.0.0.1", options.Port, device.PublicIdentity,
                privateKey, kem, store.ServerId, token); }
            catch { client.Dispose(); throw; }
        }
        async Task<RpcResponse> Open(SecureTransport encrypted, NetworkServiceProtocol protocol)
        {
            await encrypted.SendAsync(new RpcRequest { Operation = "OpenNetworkService", RequestId = 1,
                Handle = share.Id, NetworkProtocol = protocol }, token);
            return await encrypted.ReceiveAsync<RpcResponse>(token);
        }
        void ChangeAccess(NetworkServiceAccess access) => store.Update(s =>
        {
            var index = s.Rules.FindIndex(r => r.Id == rule.Id);
            return s.Rules[index] = rule with { NetworkAllow = access };
        });
        async Task<bool> Closed(SecureTransport encrypted)
        {
            try { await encrypted.ReceiveAsync<RelayFrame>(token); return false; }
            catch (IOException) { return true; }
        }

        using (var encrypted = await Connect())
        using (var rpc = new RpcClientSession(encrypted))
        {
            var catalog = await rpc.CallAsync(new() { Operation = "ListNetworkServices" }, token);
            var files = await rpc.CallAsync(new() { Operation = "List" }, token);
            check(catalog.NetworkServices?.Any(n => n.Id == share.Id && n.Access == NetworkServiceAccess.Both && n.Port == port) == true
                && files.Entries!.All(n => n.Name != share.Name), "Authenticated service discovery is separate from the mounted file namespace");
        }
        using (var encrypted = await Connect())
        {
            check((await Open(encrypted, NetworkServiceProtocol.Tcp)).NetworkAccess == NetworkServiceAccess.Both,
                "Opening a dedicated encrypted TCP relay negotiates the effective directions");
            using var peer = await target.AcceptTcpClientAsync(token);
            var stream = peer.GetStream();
            await encrypted.SendAsync(new RelayFrame([1, 2]), token);
            await encrypted.SendAsync(new RelayFrame([3, 4, 5]), token);
            await encrypted.SendAsync(new RelayFrame([], true), token);
            var bytes = new byte[5];
            await stream.ReadExactlyAsync(bytes, token);
            check(bytes.SequenceEqual(new byte[] { 1, 2, 3, 4, 5 }) && await stream.ReadAsync(new byte[1], token) == 0,
                "TCP preserves stream order and propagates a client half-close to the service");
            await stream.WriteAsync(new byte[] { 8 }, token);
            peer.Client.Shutdown(SocketShutdown.Send);
            check((await encrypted.ReceiveAsync<RelayFrame>(token)) is { Data: [8], End: false } &&
                (await encrypted.ReceiveAsync<RelayFrame>(token)).End, "TCP forwards the service response after client EOF and signals its final EOF");
        }
        using (var a = await Connect())
        using (var b = await Connect())
        {
            await Open(a, NetworkServiceProtocol.Udp);
            await Open(b, NetworkServiceProtocol.Udp);
            await a.SendAsync(new RelayFrame([]), token);
            var empty = await udp.ReceiveAsync(token);
            await b.SendAsync(new RelayFrame([4, 5]), token);
            var other = await udp.ReceiveAsync(token);
            await udp.SendAsync(other.Buffer, other.RemoteEndPoint, token);
            await udp.SendAsync(empty.Buffer, empty.RemoteEndPoint, token);
            check(!empty.RemoteEndPoint.Equals(other.RemoteEndPoint) && (await a.ReceiveAsync<RelayFrame>(token)) is { Data.Length: 0, End: false } &&
                (await b.ReceiveAsync<RelayFrame>(token)) is { Data: [4, 5], End: false },
                "UDP preserves empty datagrams, message boundaries, and independent client peer associations");
            ChangeAccess(NetworkServiceAccess.Receive);
            check(await Closed(a) && await Closed(b), "Reducing permissions closes even idle network service associations");
        }
        using (var encrypted = await Connect())
        {
            check((await Open(encrypted, NetworkServiceProtocol.Tcp)).NetworkAccess == NetworkServiceAccess.Receive,
                "A new connection reflects the current receive-only rule");
            using var peer = await target.AcceptTcpClientAsync(token);
            await peer.GetStream().WriteAsync(new byte[] { 7 }, token);
            check((await encrypted.ReceiveAsync<RelayFrame>(token)).Data is [7], "Receive-only access forwards service responses");
            await encrypted.SendAsync(new RelayFrame([99]), token);
            check(await Closed(encrypted) && await peer.GetStream().ReadAsync(new byte[1], token) == 0,
                "A receive-only device cannot send a payload even if it bypasses the client listener");
        }
        ChangeAccess(NetworkServiceAccess.Send);
        using (var encrypted = await Connect())
        {
            await Open(encrypted, NetworkServiceProtocol.Tcp);
            using var peer = await target.AcceptTcpClientAsync(token);
            await peer.GetStream().WriteAsync(new byte[] { 99 }, token);
            check((await encrypted.ReceiveAsync<RelayFrame>(token)) is { End: true, Data.Length: 0 },
                "Send-only permission closes the return stream without forwarding a byte");
            await encrypted.SendAsync(new RelayFrame([17]), token);
            var value = new byte[1];
            await peer.GetStream().ReadExactlyAsync(value, token);
            check(value[0] == 17, "A send-only device can still deliver payloads after the return stream closes");
        }
        store.Update(s =>
        {
            s.NetworkServices.Remove(share);
            s.Rules.RemoveAll(r => r.Id == rule.Id);
            return true;
        });
        using (var encrypted = await Connect())
            check((await Open(encrypted, NetworkServiceProtocol.Tcp)).Error == "AccessDenied",
                "A deleted network service cannot be opened by a previously authorized device");
    }
}
