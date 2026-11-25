using System.Net;
using System.Net.Sockets;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Threading.Channels;
using BijouShare.Shared;

namespace BijouShare.Client;

internal sealed class NetworkServiceListener
{
    private readonly ServerEndpoint endpoint;
    private readonly NetworkServiceDescriptor service;
    private readonly ClientSettings settings;
    private readonly SemaphoreSlim peerSlots;
    private readonly ILogger logger;
    private readonly CancellationTokenSource lifetime;
    private readonly CancellationToken token;
    private readonly Socket? tcp, udp;
    private readonly IDisposable? guard;
    private readonly object gate = new();
    private readonly HashSet<Task> peers = [];
    private readonly Dictionary<IPEndPoint, UdpPeer> datagrams = [];
    private int started, stopped, access;
    internal Task Completion { get; private set; } = Task.CompletedTask;

    private sealed class UdpPeer
    {
        // Datagram fan-in is bounded while the relay authenticates or the target is slow.
        internal readonly Channel<byte[]> Queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(8)
        { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.DropWrite });
        internal readonly CancellationTokenSource Idle = new(TimeSpan.FromMinutes(2));
        internal void Touch() => Idle.CancelAfter(TimeSpan.FromMinutes(2));
    }

    internal NetworkServiceListener(ServerEndpoint endpoint, NetworkServiceDescriptor service, int port, ClientSettings settings,
        SemaphoreSlim peerSlots, ILogger logger, Func<int, NetworkServiceProtocol, IDisposable>? acquireGuard = null)
    {
        this.endpoint = endpoint;
        this.service = service;
        access = (int)service.Access;
        this.settings = settings;
        this.peerSlots = peerSlots;
        this.logger = logger;
        lifetime = CancellationTokenSource.CreateLinkedTokenSource(settings.VerificationToken);
        token = lifetime.Token;
        try
        {
            try { guard = (acquireGuard ?? LocalListenerGuard.Acquire)(port, service.Protocol); }
            catch (IOException ex) { throw new ArgumentException(ex.Message, ex); }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied)
            {
                throw new ArgumentException($"Local port {port} is already in use or reserved by Windows. Choose another port.", ex);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or Win32Exception or OperationCanceledException or TimeoutException or InvalidOperationException)
            {
                throw new ArgumentException($"Windows could not protect local port {port}. Check that the BijouShare Client and Base Filtering Engine services are running.", ex);
            }
            if (service.Protocol.HasFlag(NetworkServiceProtocol.Tcp)) tcp = Bind(ProtocolType.Tcp);
            if (service.Protocol.HasFlag(NetworkServiceProtocol.Udp)) udp = Bind(ProtocolType.Udp);
        }
        catch
        {
            tcp?.Dispose();
            udp?.Dispose();
            guard?.Dispose();
            lifetime.Dispose();
            throw;
        }

        Socket Bind(ProtocolType protocol)
        {
            var socket = new Socket(AddressFamily.InterNetwork, protocol == ProtocolType.Tcp ? SocketType.Stream : SocketType.Dgram, protocol);
            try
            {
                socket.ExclusiveAddressUse = true;
                socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
                if (protocol == ProtocolType.Tcp) socket.Listen(32);
                return socket;
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                string reason = ex.SocketErrorCode switch
                {
                    SocketError.AddressAlreadyInUse => "is already in use. Choose another port.",
                    SocketError.AccessDenied => "is reserved or in use by another application. Choose another port.",
                    _ => $"could not be opened ({ex.SocketErrorCode})."
                };
                throw new ArgumentException($"Local {protocol.ToString().ToUpperInvariant()} port {port} {reason}", ex);
            }
        }
    }

    internal void Start()
    {
        Interlocked.Exchange(ref started, 1);
        Completion = RunAsync();
    }

    internal bool TryUpdate(ServerEndpoint other, NetworkServiceDescriptor? next)
    {
        if (token.IsCancellationRequested || !ReferenceEquals(endpoint, other) || next == null ||
            service.Protocol != next.Protocol || service.Port != next.Port) return false;
        int previous = Interlocked.CompareExchange(ref access, (int)next.Access, (int)NetworkServiceAccess.None);
        return previous == (int)NetworkServiceAccess.None || previous == (int)next.Access;
    }

    private NetworkServiceAccess Grant => (NetworkServiceAccess)Volatile.Read(ref access);

    internal void Stop()
    {
        if (Interlocked.Exchange(ref stopped, 1) != 0) return;
        lifetime.Cancel();
        tcp?.Dispose();
        udp?.Dispose();
        if (Volatile.Read(ref started) == 0) { guard?.Dispose(); lifetime.Dispose(); }
    }

    private async Task RunAsync()
    {
        async Task Guard(Func<Task> listen)
        {
            try { await listen(); }
            catch (Exception ex) when (IsPeerFailure(ex))
            {
                if (!token.IsCancellationRequested) logger.LogWarning("Network service listener stopped: {Error}", ex.Message);
            }
            finally { Stop(); }
        }
        try
        {
            await Task.WhenAll(tcp == null ? Task.CompletedTask : Guard(AcceptTcpAsync),
                udp == null ? Task.CompletedTask : Guard(AcceptUdpAsync));
        }
        finally
        {
            Stop();
            Task[] active;
            lock (gate) active = peers.ToArray();
            try { await Task.WhenAll(active); }
            finally { guard?.Dispose(); lifetime.Dispose(); }
        }
    }

    private static bool IsPeerFailure(Exception ex) => ex is IOException or SocketException or CryptographicException or
        OperationCanceledException or ObjectDisposedException or InvalidDataException or UnauthorizedAccessException or
        PlatformNotSupportedException or System.Text.Json.JsonException;

    private async Task AcceptTcpAsync()
    {
        while (!token.IsCancellationRequested)
        {
            var local = await tcp!.AcceptAsync(token);
            if (Grant == NetworkServiceAccess.None || local.RemoteEndPoint is not IPEndPoint source ||
                !IPAddress.IsLoopback(source.Address) || !peerSlots.Wait(0))
            {
                local.Dispose();
                continue;
            }
            Track(async () =>
            {
                using (local)
                {
                    local.NoDelay = true;
                    await WithRelayAsync(NetworkServiceProtocol.Tcp, (remote, access, stop) => TcpAsync(local, remote, access, stop), token);
                }
            });
        }
    }

    private void Track(Func<Task> operation)
    {
        async Task Run()
        {
            try { await operation(); }
            catch (Exception ex) when (IsPeerFailure(ex))
            {
                if (!token.IsCancellationRequested) logger.LogDebug("Network service association ended: {Error}", ex.Message);
            }
            finally { peerSlots.Release(); }
        }
        var task = Task.Run(Run);
        lock (gate) peers.Add(task);
        _ = task.ContinueWith(finished => { lock (gate) peers.Remove(finished); }, CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task WithRelayAsync(NetworkServiceProtocol protocol, Func<SecureTransport, NetworkServiceAccess, CancellationToken, Task> pump,
        CancellationToken stop)
    {
        using var socket = new TcpClient();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
        timeout.CancelAfter(TimeSpan.FromSeconds(settings.RequestTimeoutSeconds));
        using var remote = await ConnectAsync(socket, timeout.Token);
        if (!remote.SupportsNetworkServices) throw new RemoteException("Unsupported");
        await remote.SendAsync(new RpcRequest { Operation = "OpenNetworkService", RequestId = 1, Handle = service.Id, NetworkProtocol = protocol }, timeout.Token);
        var reply = await remote.ReceiveAsync<RpcResponse>(timeout.Token);
        if (reply.Error != null) throw new RemoteException(reply.Error);
        if (reply.RequestId != 1 || reply.NetworkAccess is not (NetworkServiceAccess.Send or NetworkServiceAccess.Receive or NetworkServiceAccess.Both))
            throw new InvalidDataException("Invalid network service acknowledgement.");
        // An old discovery response can only narrow the server's latest grant.
        var access = reply.NetworkAccess & Grant;
        if (access == NetworkServiceAccess.None) throw new UnauthorizedAccessException();
        await pump(remote, access, stop);
    }

    private async Task<SecureTransport> ConnectAsync(TcpClient socket, CancellationToken stop)
    {
        var privateKey = UserSecrets.Unprotect(settings.ProtectedPrivateKey);
        try
        {
            using var kem = settings.OpenIdentityKem();
            return await AuthenticatedClient.ConnectAsync(socket, settings.Host, settings.Port, settings.DeviceId, privateKey, kem,
                settings.TrustedServerId!, stop);
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    private static async Task TcpAsync(Socket local, SecureTransport remote, NetworkServiceAccess access, CancellationToken stop)
    {
        using var stream = new NetworkStream(local, ownsSocket: false);
        using var both = CancellationTokenSource.CreateLinkedTokenSource(stop);
        async Task Outgoing()
        {
            var buffer = new byte[RelayFrame.MaxStreamPayload];
            while (true)
            {
                var read = await stream.ReadAsync(buffer, both.Token);
                if (read == 0) { await remote.SendAsync(new RelayFrame([], true), both.Token); return; }
                if (!access.HasFlag(NetworkServiceAccess.Send)) throw new UnauthorizedAccessException();
                await remote.SendAsync(new RelayFrame(read == buffer.Length ? buffer : buffer[..read]), both.Token);
            }
        }
        async Task Incoming()
        {
            while (true)
            {
                var frame = await remote.ReceiveAsync<RelayFrame>(both.Token);
                if (frame.End) { local.Shutdown(SocketShutdown.Send); return; }
                if (!access.HasFlag(NetworkServiceAccess.Receive) || frame.Data.Length is 0 or > RelayFrame.MaxStreamPayload)
                    throw new InvalidDataException("Unexpected TCP relay payload.");
                await stream.WriteAsync(frame.Data, both.Token);
            }
        }
        await DuplexAsync(Outgoing(), Incoming(), both, allowHalfClose: true);
    }

    private async Task AcceptUdpAsync()
    {
        var buffer = new byte[RelayFrame.MaxDatagramPayload];
        while (!token.IsCancellationRequested)
        {
            SocketReceiveFromResult packet;
            try { packet = await udp!.ReceiveFromAsync(buffer.AsMemory(), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), token); }
            // Windows can report a late ICMP error from a local receiver that has already closed.
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset && !token.IsCancellationRequested) { continue; }
            var source = (IPEndPoint)packet.RemoteEndPoint;
            if (Grant == NetworkServiceAccess.None || !IPAddress.IsLoopback(source.Address)) continue;
            lock (gate)
            {
                if (!datagrams.TryGetValue(source, out var peer))
                {
                    if (!peerSlots.Wait(0)) continue;
                    datagrams[source] = peer = new();
                    Track(() => ServeUdpAsync(source, peer));
                }
                peer.Touch();
                if (Grant.HasFlag(NetworkServiceAccess.Send))
                    peer.Queue.Writer.TryWrite(buffer.AsSpan(0, packet.ReceivedBytes).ToArray());
            }
        }
    }

    private async Task ServeUdpAsync(IPEndPoint source, UdpPeer peer)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, peer.Idle.Token);
            await WithRelayAsync(NetworkServiceProtocol.Udp, async (remote, access, stop) =>
            {
                using var both = CancellationTokenSource.CreateLinkedTokenSource(stop);
                async Task Outgoing()
                {
                    await foreach (var bytes in peer.Queue.Reader.ReadAllAsync(both.Token))
                        if (access.HasFlag(NetworkServiceAccess.Send))
                            await remote.SendAsync(new RelayFrame(bytes), both.Token);
                }
                async Task Incoming()
                {
                    while (true)
                    {
                        var frame = await remote.ReceiveAsync<RelayFrame>(both.Token);
                        if (frame.End) return;
                        if (!access.HasFlag(NetworkServiceAccess.Receive) || frame.Data.Length > RelayFrame.MaxDatagramPayload || !IPAddress.IsLoopback(source.Address))
                            throw new UnauthorizedAccessException();
                        await udp!.SendToAsync(frame.Data.AsMemory(), SocketFlags.None, source, both.Token);
                        peer.Touch();
                    }
                }
                await DuplexAsync(Outgoing(), Incoming(), both, allowHalfClose: false);
            }, linked.Token);
        }
        finally
        {
            lock (gate)
            {
                datagrams.Remove(source);
                peer.Queue.Writer.TryComplete();
                peer.Idle.Dispose();
            }
        }
    }

    private static async Task DuplexAsync(Task outgoing, Task incoming, CancellationTokenSource stop, bool allowHalfClose)
    {
        var first = await Task.WhenAny(outgoing, incoming);
        if (!allowHalfClose || !first.IsCompletedSuccessfully) await stop.CancelAsync();
        await Task.WhenAll(outgoing, incoming);
    }
}
