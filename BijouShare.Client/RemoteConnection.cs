using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
    private sealed record Connection(TcpClient Socket, RpcClientSession Session, string ServerId, long Generation, Guid Ticket,
        UnclaimedOpens? Unclaimed) : IDisposable
    {
        public void Dispose()
        {
            Session.Dispose();
            Socket.Dispose();
        }
    }
    // One instance per logical lease, shared across its authenticated sockets.
    private sealed class UnclaimedOpens
    {
        private readonly HashSet<long> abandoned = [];
        private readonly SemaphoreSlim drain = new(1, 1);
        private int reserved;

        internal void Reserve()
        {
            lock (abandoned)
            {
                // Reserve space before dispatch: even a full queue cannot strand a newly opened writer.
                if (reserved >= 512 + 16) // Per-session handle limit plus the transport's in-flight window.
                    throw new RemoteException("TooManyOpenFiles");
                reserved++;
            }
        }

        internal void Finish(long outcomeId, bool abandon)
        {
            lock (abandoned)
            {
                if (abandon) abandoned.Add(outcomeId);
                else reserved--;
            }
        }

        internal async Task DrainAsync(RpcClientSession session, CancellationToken token)
        {
            lock (abandoned) { if (abandoned.Count == 0) return; }
            await drain.WaitAsync(token);
            try
            {
                long[] pending;
                lock (abandoned) pending = [.. abandoned];
                foreach (var id in pending)
                {
                    // Idempotent by original Open ID. A lost acknowledgement stays queued.
                    await session.CallAsync(new() { Operation = "AbandonOpen", OutcomeId = id }, token);
                    lock (abandoned) { abandoned.Remove(id); reserved--; }
                }
            }
            finally { drain.Release(); }
        }
    }
    private readonly SemaphoreSlim connectGate = new(1, 1);
    private readonly object activityGate = new();
    private readonly CancellationTokenSource lifetime = CancellationTokenSource.CreateLinkedTokenSource(settings.VerificationToken);
    private Connection? connection;
    // Both fields are updated under connectGate, only after the authenticated server confirms the lease.
    private Guid ticket;
    private long generation;
    private UnclaimedOpens? unclaimed;
    private long nextOutcomeId;
    private int callers;
    private int disposed;
    public string DeviceName { get; private set; } = "";
    public int MaxTransferSize => Volatile.Read(ref connection)?.Session.BinaryPayloads == true ? Wire.MaxChunk : Wire.LegacyMaxChunk;
    public RemoteReply Call(RpcRequest request, long? expectedGeneration = null) =>
        CallAsync(request, expectedGeneration).GetAwaiter().GetResult();

    public Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default) =>
        CallForIdentityAsync(request, expectedGeneration, null, token);

    internal async Task<RemoteReply> CallForIdentityAsync(RpcRequest request, long? expectedGeneration, string? routeIdentity, CancellationToken token)
    {
        CancellationToken shutdown;
        lock (activityGate)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            shutdown = lifetime.Token;
            callers++;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token, shutdown);
        var budget = TimeSpan.FromSeconds(Math.Clamp(settings.RequestTimeoutSeconds, 5, 45));
        var started = Stopwatch.GetTimestamp();
        if (!QueryUnbiasedInterruptTime(out var awakeStart)) awakeStart = -1;
        timeout.CancelAfter(budget);
        Connection? active = null;
        UnclaimedOpens? openReservation = null;
        var abandon = true;
        var recovering = false;
        try
        {
            active = await GetConnectionAsync(expectedGeneration, routeIdentity, timeout.Token);
            if (request.Operation == "ListNetworkServices" && !active.Session.SupportsNetworkServices)
                throw new RemoteException("Unsupported");
            if (active.Unclaimed is { } opens && request.Operation is "Ping" or "Open")
            {
                await opens.DrainAsync(active.Session, timeout.Token);
                if (request.Operation == "Open")
                {
                    opens.Reserve();
                    openReservation = opens;
                }
            }
            if (active.Ticket != Guid.Empty && request.TracksOutcome)
                request = request with { OutcomeId = Interlocked.Increment(ref nextOutcomeId) };
            RpcResponse response;
            try
            {
                // Windows cancellation timers pause while suspended. Keep the sub-deadline on the same clock.
                var elapsed = awakeStart >= 0 && QueryUnbiasedInterruptTime(out var now) && now >= awakeStart
                    ? TimeSpan.FromTicks(now - awakeStart)
                    : Stopwatch.GetElapsedTime(started);
                response = await DispatchAsync(active, request, budget - elapsed, timeout.Token);
            }
            catch (Exception ex) when (!timeout.IsCancellationRequested && ex is not RemoteException &&
                (IsTransportLoss(ex) || active.Session.Failure is { } failure && (IsTransportLoss(failure) || failure is OperationCanceledException)))
            {
                recovering = true;
                // Acknowledgements can be lost after a write commits. Resolve tracked operations
                // on their original lease before considering another execution.
                var sameLease = expectedGeneration.HasValue || request.Handle != Guid.Empty ||
                    request.OutcomeId != 0 || request.Operation == "List" && request.Offset != 0;
                if (sameLease && active.Ticket == Guid.Empty)
                    throw;
                if (request.OutcomeId == 0 && request.Operation is not ("Ping" or "Space" or "Stat" or "Security" or "List" or "Read" or "CanDelete"))
                    throw;

                var requiredGeneration = sameLease ? active.Generation : (long?)null;
                Disconnect(active);
                active = null;
                try { active = await GetConnectionAsync(requiredGeneration, routeIdentity, timeout.Token); }
                catch (RemoteException unavailable) when (request.OutcomeId != 0 && unavailable.Code == "InvalidHandle")
                {
                    // A fresh lease cannot say whether a mutation completed on the expired one.
                    throw new RemoteException("OutcomeUnknown");
                }
                response = request.OutcomeId == 0
                    ? await active.Session.CallAsync(request, timeout.Token)
                    : await RecoverOutcomeAsync(active, request, timeout.Token);
            }
            abandon = false;
            return new(response, active.Generation);
        }
        catch (RemoteException ex)
        {
            abandon = recovering || ex.Code is "Timeout" or "Disconnected" or "OutcomeUnknown";
            throw;
        }
        catch (ServerIdentityMismatchException) { throw; }
        catch (PlatformNotSupportedException) { throw new RemoteException("HybridUnavailable"); }
        catch (CryptographicException ex) when (active is null)
        {
            logger.LogWarning("Authentication failed for {Host}:{Port}: {Reason}", settings.Host, settings.Port, ex.Message);
            throw;
        }
        catch (OperationCanceledException) when (!shutdown.IsCancellationRequested && settings.IsVerificationCurrent &&
            (token.IsCancellationRequested || active is { Session.IsClosed: false }))
        {
            // An unsent request can expire in a busy session without invalidating other file handles.
            // An expired reconnect deadline with no live session falls through to Disconnected.
            logger.LogDebug("File request canceled or timed out");
            throw new RemoteException("Timeout");
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or CryptographicException or
            InvalidDataException or System.Text.Json.JsonException or ObjectDisposedException)
        {
            if (active is not null)
                Disconnect(active);
            if (!shutdown.IsCancellationRequested)
                logger.LogWarning("File connection failed: {Reason}", ex.Message);
            throw new RemoteException("Disconnected"); // An uncertain write is never replayed.
        }
        finally
        {
            // Only the callback which will never hand its result to Dokan can release the Open.
            openReservation?.Finish(request.OutcomeId, abandon);
            lock (activityGate) callers--;
        }
    }

    private static async Task<RpcResponse> RecoverOutcomeAsync(Connection active, RpcRequest original, CancellationToken token)
    {
        try
        {
            return await active.Session.CallAsync(new() { Operation = "GetOutcome", OutcomeId = original.OutcomeId }, token);
        }
        catch (RemoteException ex) when (ex.Code == "OutcomeNotExecuted")
        {
            // The server rechecks this ID atomically if the original is admitted in the meantime.
            return await active.Session.CallAsync(original with { RecoveryAttempt = true }, token);
        }
    }

    private static async Task<RpcResponse> DispatchAsync(Connection active, RpcRequest request, TimeSpan remaining, CancellationToken token)
    {
        if (remaining <= TimeSpan.Zero)
            throw new OperationCanceledException(token);
        if (active.Ticket == Guid.Empty)
            return await active.Session.CallAsync(request, token);
        // Leave time to reauthenticate and recover a receipt if this socket silently drops packets.
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(token);
        attempt.CancelAfter(remaining * (2.0 / 3.0));
        try { return await active.Session.CallAsync(request, attempt.Token); }
        catch (OperationCanceledException) when (attempt.IsCancellationRequested && !token.IsCancellationRequested && !active.Session.IsClosed)
        {
            // A queued request canceled before getting an ID never went on the wire.
            return await active.Session.CallAsync(request, token);
        }
    }

    private static bool IsTransportLoss(Exception error) => error.GetBaseException() is SocketException or EndOfStreamException;

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryUnbiasedInterruptTime(out long ticks);

    private async Task<Connection> GetConnectionAsync(long? expectedGeneration, string? routeIdentity, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var active = Volatile.Read(ref connection);
        if (active is not null && !active.Session.IsClosed)
            return CheckIdentityAndGeneration(active);
        await connectGate.WaitAsync(token);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            active = Volatile.Read(ref connection);
            if (active?.Session.IsClosed == true)
            {
                Disconnect(active);
                active = null;
            }
            if (active is null)
            {
                if (expectedGeneration.HasValue && (expectedGeneration != generation || ticket == Guid.Empty))
                    throw new RemoteException("InvalidHandle");
                active = generation == 0 ? await ConnectAsync(token) : await ReconnectAsync(token);
                Volatile.Write(ref connection, active);
            }
            return CheckIdentityAndGeneration(active);
        }
        finally { connectGate.Release(); }

        Connection CheckIdentityAndGeneration(Connection established)
        {
            if (!settings.IsVerificationCurrent || routeIdentity is not null && routeIdentity != established.ServerId ||
                expectedGeneration.HasValue && expectedGeneration != established.Generation)
                throw new RemoteException("InvalidHandle");
            return established;
        }
    }

    private async Task<Connection> ReconnectAsync(CancellationToken token)
    {
        // The adapter and routing table can take a few seconds to return after Windows wakes.
        // Serialize attempts under connectGate; other callbacks keep their own original deadlines.
        var delayMs = 150;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(token);
            attempt.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(settings.RequestTimeoutSeconds / 3, 2, 8)));
            try { return await ConnectAsync(attempt.Token); }
            catch (Exception ex) when (!token.IsCancellationRequested && (IsTransportLoss(ex) ||
                ex is OperationCanceledException && attempt.IsCancellationRequested))
            {
                await Task.Delay(delayMs, token);
                delayMs = Math.Min(1000, delayMs * 2);
            }
        }
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
                Guid confirmed = Guid.Empty;
                try
                {
                    DeviceName = session.DeviceName ?? throw new InvalidDataException("Server did not identify this device.");
                    if (transport.SupportsSessionResume)
                    {
                        var lease = await session.CallAsync(new() { Operation = "ResumeSession", Handle = ticket }, token);
                        confirmed = lease.Handle;
                        if (confirmed == Guid.Empty)
                            throw new InvalidDataException("Server did not confirm the file session.");
                    }
                }
                catch { session.Dispose(); throw; }
                if (confirmed == Guid.Empty || confirmed != ticket)
                {
                    ++generation;
                    unclaimed = confirmed == Guid.Empty ? null : new();
                }
                ticket = confirmed;
                try
                {
                    if (unclaimed is not null)
                        await unclaimed.DrainAsync(session, token);
                }
                catch { session.Dispose(); throw; }
                logger.LogInformation("Authenticated device {Device} and server {Server} using P-256 ECDH and ML-KEM-768 ({Provider}). Transfer mode {Mode}",
                    DeviceName, transport.RemoteServerName, HybridKem.ProviderName, session.BinaryPayloads ? "pipelined AES-GCM binary" : "AES-GCM JSON");
                return new(socket, session, transport.RemoteServerId!, generation, confirmed, unclaimed);
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

    internal void PrepareAfterWake()
    {
        lock (activityGate)
        {
            if (callers == 0 && Volatile.Read(ref connection) is { Ticket: var current } active && current != Guid.Empty)
                Disconnect(active);
        }
    }

    public void Dispose()
    {
        lock (activityGate)
        {
            if (disposed != 0) return;
            Volatile.Write(ref disposed, 1);
        }
        lifetime.Cancel();
        connectGate.Wait();
        try
        {
            using var active = Interlocked.Exchange(ref connection, null);
            ticket = Guid.Empty;
            unclaimed = null;
            if (active is not null && active.Ticket != Guid.Empty && !active.Session.IsClosed)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                try { active.Session.CallAsync(new() { Operation = "EndSession" }, cleanup.Token).GetAwaiter().GetResult(); }
                catch (Exception error) when (error is IOException or SocketException or OperationCanceledException or
                    CryptographicException or ObjectDisposedException or InvalidDataException or System.Text.Json.JsonException)
                { logger.LogDebug("The disconnected server will expire the file session."); }
            }
        }
        finally
        {
            connectGate.Release();
            lifetime.Dispose();
        }
    }
}
