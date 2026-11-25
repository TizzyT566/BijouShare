using System.Net;
using System.Net.Sockets;
using BijouShare.Shared;

namespace BijouShare.Server;

// One dedicated authenticated transport carries one TCP stream or one UDP peer association.
internal sealed class NetworkRelayServer(StateStore store, AuditLog audit, ServerOptions options)
{
    private readonly object gate = new();
    private readonly Dictionary<Guid, int> active = [];

    internal async Task ServeAsync(SecureTransport transport, RpcRequest request, Device device, CancellationToken token)
    {
        var id = request.Handle;
        var protocol = request.NetworkProtocol;
        if (id == Guid.Empty || protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp) ||
            request.Path != "\\" || request.Destination != null || request.Data != null || request.InviteCode != null ||
            request.OutcomeId != 0 || request.RecoveryAttempt)
        {
            await Reject("InvalidParameter");
            return;
        }
        if (!TryReserve(device.Id))
        {
            await Reject("NetworkServiceBusy");
            return;
        }
        try
        {
            // Capture the revision before authorization so that a concurrent edit always forces a recheck.
            long checkedRevision = store.Revision;
            var target = store.AuthorizeNetworkService(device, id, protocol);
            void CheckPolicy()
            {
                var revision = store.Revision;
                if (Interlocked.Read(ref checkedRevision) == revision) return;
                var current = store.AuthorizeNetworkService(device, id, protocol);
                if (!StringComparer.OrdinalIgnoreCase.Equals(current.Host, target.Host) || current.Port != target.Port ||
                    (current.Permissions & target.Permissions) != target.Permissions)
                    throw new UnauthorizedAccessException();
                Interlocked.Exchange(ref checkedRevision, revision);
            }

            Socket remote;
            using (var opening = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                opening.CancelAfter(TimeSpan.FromSeconds(10));
                try { remote = await ConnectTargetAsync(target, protocol, CheckPolicy, opening.Token); }
                catch (Exception e) when (e is SocketException or IOException || e is OperationCanceledException && !token.IsCancellationRequested)
                {
                    await Reject("NetworkServiceUnavailable");
                    return;
                }
            }
            using (remote)
            {
                CheckPolicy();
                audit.Write(device.Name, "OpenNetworkService", id.ToString());
                await transport.SendAsync(new RpcResponse { RequestId = request.RequestId, NetworkAccess = target.Permissions }, token);
                try { await PumpAsync(remote, transport, protocol, target.Permissions, CheckPolicy, token); }
                catch (UnauthorizedAccessException)
                {
                    // After switching frame types an authorization change terminates the channel.
                    audit.Write(device.Name, "NetworkServiceAccess", id.ToString(), "AccessDenied");
                }
            }
        }
        catch (UnauthorizedAccessException) { await Reject("AccessDenied"); }
        finally
        {
            lock (gate)
            {
                if (--active[device.Id] == 0) active.Remove(device.Id);
            }
        }

        async Task Reject(string code)
        {
            audit.Write(device.Name, "OpenNetworkService", id.ToString(), code);
            await transport.SendAsync(RpcResponse.Fail(code) with { RequestId = request.RequestId }, token);
        }
    }

    private bool TryReserve(Guid deviceId)
    {
        lock (gate)
        {
            int count = active.GetValueOrDefault(deviceId);
            if (count >= Math.Clamp(options.MaxConnections / 2, 1, 32)) return false;
            active[deviceId] = count + 1;
            return true;
        }
    }

    private static async Task<Socket> ConnectTargetAsync(NetworkServiceTarget target, NetworkServiceProtocol protocol,
        Action checkPolicy, CancellationToken token)
    {
        var addresses = IPAddress.TryParse(target.Host, out var literal) ? [literal] :
            await Dns.GetHostAddressesAsync(target.Host, token);
        SocketException? lastError = null;
        foreach (var address in addresses.Where(StateStore.IsUnicastServiceAddress))
        {
            token.ThrowIfCancellationRequested();
            checkPolicy();
            bool tcp = protocol == NetworkServiceProtocol.Tcp;
            var socket = new Socket(address.AddressFamily, tcp ? SocketType.Stream : SocketType.Dgram,
                tcp ? ProtocolType.Tcp : ProtocolType.Udp);
            try
            {
                if (tcp) socket.NoDelay = true;
                // Connect to this verified address directly. UDP accepts replies only from this target.
                await socket.ConnectAsync(new IPEndPoint(address, target.Port), token);
                return socket;
            }
            catch (SocketException ex) { socket.Dispose(); lastError = ex; }
            catch { socket.Dispose(); throw; }
        }
        throw lastError ?? new SocketException((int)SocketError.HostUnreachable);
    }

    private static async Task PumpAsync(Socket remote, SecureTransport transport, NetworkServiceProtocol protocol,
        NetworkServiceAccess access, Action checkPolicy, CancellationToken token)
    {
        bool tcp = protocol == NetworkServiceProtocol.Tcp;
        int maxPayload = tcp ? RelayFrame.MaxStreamPayload : RelayFrame.MaxDatagramPayload;
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        var stop = lifetime.Token;
        long lastActive = Environment.TickCount64;
        var inbound = FromClientAsync();
        var outbound = ToClientAsync();
        var watcher = WatchPolicyAsync();
        Task? afterFin = null;
        try
        {
            // A TCP FIN ends one direction. A UDP association ends as a unit.
            var first = await Task.WhenAny(inbound, outbound, watcher);
            await first;
            if (tcp)
            {
                if (first == inbound && !outbound.IsCompleted)
                {
                    // The local app may disconnect while the target still has its send side open.
                    afterFin = ObservePeerAfterFinAsync();
                    await Task.WhenAny(outbound, watcher, afterFin).Unwrap();
                }
                else await Task.WhenAny(first == inbound ? outbound : inbound, watcher).Unwrap();
            }
            else if (first == outbound && !access.HasFlag(NetworkServiceAccess.Receive))
                await Task.WhenAny(inbound, watcher).Unwrap();
        }
        finally
        {
            await lifetime.CancelAsync();
            // A blocked sender or receiver must drain before the authenticated transport is disposed.
            try { await Task.WhenAll(inbound, outbound, watcher, afterFin ?? Task.CompletedTask); }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException or
                SocketException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException) { }
        }

        async Task ObservePeerAfterFinAsync()
        {
            await transport.ReceiveAsync<RelayFrame>(stop);
            throw new InvalidDataException("Unexpected data after the end of a TCP direction.");
        }

        async Task FromClientAsync()
        {
            while (true)
            {
                var frame = await transport.ReceiveAsync<RelayFrame>(stop);
                checkPolicy();
                if (frame.Data.Length > maxPayload || frame.End && frame.Data.Length != 0 || tcp && !frame.End && frame.Data.Length == 0)
                    throw new InvalidDataException("Invalid network service payload.");
                if (frame.End)
                {
                    if (tcp) remote.Shutdown(SocketShutdown.Send);
                    return;
                }
                if (!access.HasFlag(NetworkServiceAccess.Send)) throw new UnauthorizedAccessException();
                Interlocked.Exchange(ref lastActive, Environment.TickCount64);
                if (tcp)
                {
                    for (var sent = 0; sent < frame.Data.Length;)
                    {
                        checkPolicy();
                        var count = await remote.SendAsync(frame.Data.AsMemory(sent), SocketFlags.None, stop);
                        if (count == 0) throw new EndOfStreamException();
                        sent += count;
                    }
                }
                else if (await remote.SendAsync(frame.Data.AsMemory(), SocketFlags.None, stop) != frame.Data.Length)
                    throw new IOException("Incomplete UDP datagram.");
            }
        }

        async Task ToClientAsync()
        {
            if (access.HasFlag(NetworkServiceAccess.Receive))
            {
                var buffer = new byte[maxPayload];
                while (true)
                {
                    var count = await remote.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, stop);
                    checkPolicy();
                    if (tcp && count == 0) break;
                    Interlocked.Exchange(ref lastActive, Environment.TickCount64);
                    await transport.SendAsync(new RelayFrame(count == buffer.Length ? buffer : buffer[..count]), stop);
                }
            }
            if (tcp) await transport.SendAsync(new RelayFrame([], End: true), stop);
        }

        async Task WatchPolicyAsync()
        {
            var idleLimit = tcp ? TimeSpan.FromHours(2) : TimeSpan.FromMinutes(2);
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            while (await timer.WaitForNextTickAsync(stop))
            {
                checkPolicy();
                if (Environment.TickCount64 - Interlocked.Read(ref lastActive) >= idleLimit.TotalMilliseconds)
                    throw new IOException("Idle network service connection.");
            }
        }
    }
}
