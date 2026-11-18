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
    private sealed record Connection(TcpClient Socket, RpcClientSession Session, string ServerId, long Generation) : IDisposable
    {
        public void Dispose()
        {
            Session.Dispose();
            Socket.Dispose();
        }
    }
    private readonly SemaphoreSlim connectGate = new(1, 1);
    private readonly CancellationTokenSource lifetime = CancellationTokenSource.CreateLinkedTokenSource(settings.VerificationToken);
    private Connection? connection;
    private long generation;
    private int disposed;
    public string DeviceName { get; private set; } = "";
    public int MaxTransferSize => Volatile.Read(ref connection)?.Session.BinaryPayloads == true ? Wire.MaxChunk : Wire.LegacyMaxChunk;
    public RemoteReply Call(RpcRequest request, long? expectedGeneration = null) =>
        CallAsync(request, expectedGeneration).GetAwaiter().GetResult();

    public Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default) =>
        CallForIdentityAsync(request, expectedGeneration, null, token);

    internal async Task<RemoteReply> CallForIdentityAsync(RpcRequest request, long? expectedGeneration, string? routeIdentity, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(settings.RequestTimeoutSeconds, 5, 45)));
        Connection? active = null;
        try
        {
            active = await GetConnectionAsync(expectedGeneration, timeout.Token);
            if (!settings.IsVerificationCurrent || routeIdentity is not null && routeIdentity != active.ServerId)
                throw new RemoteException("InvalidHandle");
            var response = await active.Session.CallAsync(request, timeout.Token);
            return new(response, active.Generation);
        }
        catch (RemoteException) { throw; }
        catch (ServerIdentityMismatchException) { throw; }
        catch (PlatformNotSupportedException) { throw new RemoteException("HybridUnavailable"); }
        catch (CryptographicException ex) when (active is null)
        {
            logger.LogWarning("Authentication failed for {Host}:{Port}: {Reason}", settings.Host, settings.Port, ex.Message);
            throw;
        }
        catch (OperationCanceledException) when (!lifetime.IsCancellationRequested && settings.IsVerificationCurrent && active?.Session.IsClosed != true)
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
        if (settings.TrustedServerId is not { } expectedId)
            throw new RemoteException("ServerLinkRequired");
        var privateKey = UserSecrets.Unprotect(settings.ProtectedPrivateKey);
        try
        {
            using var identityKem = settings.OpenIdentityKem();
            var inviteCode = settings.GetInviteCode();
            var socket = new TcpClient();
            try
            {
                var transport = await AuthenticatedClient.ConnectDeviceAsync(socket, settings.Host, settings.Port, settings.DeviceId,
                    settings.DeviceName, privateKey, identityKem, token, expectedId, inviteCode);
                try
                {
                    settings.RememberServerIdentity(transport.RemoteServerId, transport.RemoteServerName,
                        transport.RemoteServerIdentityPublicKey, transport.RemoteServerMlKemPublicKey);
                    settings.ClearInviteCode(inviteCode);
                }
                catch { transport.Dispose(); throw; }
                var session = new RpcClientSession(transport);
                DeviceName = session.DeviceName ?? throw new InvalidDataException("Server did not identify this device.");
                logger.LogInformation("Authenticated device {Device} and server {Server} using P-256 ECDH and ML-KEM-768 ({Provider}). Transfer mode {Mode}",
                    DeviceName, transport.RemoteServerName, HybridKem.ProviderName, session.BinaryPayloads ? "pipelined AES-GCM binary" : "AES-GCM JSON");
                return new(socket, session, transport.RemoteServerId!, ++generation);
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
        finally
        {
            connectGate.Release();
            lifetime.Dispose();
        }
    }
}
