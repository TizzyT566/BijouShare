using System.Net.Sockets;
using System.Security.Cryptography;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed record RemoteReply(RpcResponse Response, long Generation);
public interface IRemoteConnection
{
    int MaxTransferSize => Wire.LegacyMaxChunk;
    int MaxTransferSizeFor(string path) => MaxTransferSize;
    RemoteReply Call(RpcRequest request, long? expectedGeneration = null);
    Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default);
}

public sealed class RemoteConnection(ClientSettings settings, ILogger<RemoteConnection> logger) : IRemoteConnection, IDisposable
{
    private sealed record Connection(TcpClient Socket, RpcClientSession Session, long Generation) : IDisposable
    {
        public void Dispose()
        {
            Session.Dispose();
            Socket.Dispose();
        }
    }
    private readonly SemaphoreSlim connectGate = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private Connection? connection;
    private long generation;
    private int disposed;
    public string DeviceName { get; private set; } = "";
    public int MaxTransferSize => Volatile.Read(ref connection)?.Session.BinaryPayloads == true ? Wire.MaxChunk : Wire.LegacyMaxChunk;
    public RemoteReply Call(RpcRequest request, long? expectedGeneration = null) =>
        CallAsync(request, expectedGeneration).GetAwaiter().GetResult();

    public async Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(settings.RequestTimeoutSeconds, 5, 45)));
        Connection? active = null;
        try
        {
            active = await GetConnectionAsync(expectedGeneration, timeout.Token);
            var response = await active.Session.CallAsync(request, timeout.Token);
            return new(response, active.Generation);
        }
        catch (RemoteException) { throw; }
        catch (ServerIdentityMismatchException) { throw; }
        catch (PlatformNotSupportedException) { throw new RemoteException("HybridUnavailable"); }
        catch (OperationCanceledException) when (!lifetime.IsCancellationRequested && active?.Session.IsClosed != true)
        {
            // The bounded session can cancel a queued request before it sends anything.
            // Its unrelated in-flight operations must keep their authenticated connection.
            logger.LogDebug("File request canceled before transmission");
            throw new RemoteException("Timeout");
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or CryptographicException or System.Text.Json.JsonException or ObjectDisposedException)
        {
            if (active is not null)
                Disconnect(active);
            if (!lifetime.IsCancellationRequested)
                logger.LogWarning("File connection failed: {Reason}", ex.Message);
            throw new RemoteException("Disconnected"); // An uncertain write is never replayed.
        }
    }

    private async Task<Connection> GetConnectionAsync(long? expectedGeneration, CancellationToken token)
    {
        var active = Volatile.Read(ref connection);
        if (active?.Session.IsClosed == true)
        {
            Disconnect(active);
            active = null;
        }
        if (expectedGeneration is not null && (active is null || active.Generation != expectedGeneration))
            throw new RemoteException("InvalidHandle");
        if (active is not null)
            return active;
        await connectGate.WaitAsync(token);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            active = connection;
            if (active is null)
            {
                active = await ConnectAsync(token);
                Volatile.Write(ref connection, active);
            }
            return active;
        }
        finally { connectGate.Release(); }
    }

    private async Task<Connection> ConnectAsync(CancellationToken token)
    {
        if (!settings.IsConfigured)
            throw new InvalidOperationException("Configure the LAN server address with --server first.");
        var privateKey = PrivateStorage.Unprotect(settings.ProtectedPrivateKey);
        try
        {
            var pinned = string.IsNullOrEmpty(settings.ServerPublicKey) ? null : Convert.FromBase64String(settings.ServerPublicKey);
            var globalPin = settings.ServerIdentityPublicKey is { } identityKey ? Convert.FromBase64String(identityKey) : null;
            var inviteCode = settings.GetInviteCode();
            var socket = new TcpClient();
            try
            {
                var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, settings.Host, settings.Port, settings.DeviceId,
                    settings.DeviceName, privateKey, pinned, token, globalPin, inviteCode);
                try
                {
                    if (settings.TrustApprovedServer(transport.RemoteIdentityPublicKey ?? throw new CryptographicException("Missing server identity."), transport.RemoteServerId, transport.RemoteServerName, transport.RemoteServerIdentityPublicKey))
                        logger.LogInformation("Pinned approved server identity {Fingerprint}", KeyAgreement.Fingerprint(settings.ServerPublicKey));
                    settings.ClearInviteCode(inviteCode);
                }
                catch { transport.Dispose(); throw; }
                var session = new RpcClientSession(transport);
                DeviceName = session.DeviceName ?? throw new InvalidDataException("Server did not identify this device.");
                logger.LogInformation("Authenticated device {Device}; key establishment P-256 + ML-KEM-768 ({Provider}); transfer mode {Mode}",
                    DeviceName, HybridKem.ProviderName, session.BinaryPayloads ? "pipelined AES-GCM binary" : "AES-GCM JSON");
                return new(socket, session, ++generation);
            }
            catch { socket.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    private void Disconnect(Connection active)
    {
        if (Interlocked.CompareExchange(ref connection, null, active) == active)
            active.Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        lifetime.Cancel();
        connectGate.Wait();
        try
        {
            Interlocked.Exchange(ref connection, null)?.Dispose();
        }
        finally { connectGate.Release(); }
    }
}
