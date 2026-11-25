using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed class FileServer(ServerOptions options, StateStore store, FileService files,
    AuditLog audit, ILogger<FileServer> logger, ServerTransfers? transfers = null) : BackgroundService
{
    private readonly ConcurrentDictionary<Guid, Task> connections = new();
    private readonly FileSessionLeases leases = new(store, files, TimeProvider.System);
    private readonly NetworkRelayServer networkRelays = new(store, audit, options);
    private readonly object listenerGate = new();
    private TcpListener? listener;
    private TaskCompletionSource portChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool stopped;
    private long lastFailureAudit;
    private int suppressedFailures;
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.Port is < 1 or > 65535 || options.MaxConnections is < 1 or > 4096 ||
            !IPAddress.TryParse(options.ListenAddress, out _))
            throw new ArgumentException("Invalid file server configuration.");
        await base.StartAsync(cancellationToken);
    }
    internal sealed class PortChange(FileServer server, TcpListener candidate, int port) : IDisposable
    {
        private TcpListener? pending = candidate;

        internal void Commit()
        {
            var replacement = Interlocked.Exchange(ref pending, null);
            if (replacement is not null)
                server.Activate(replacement, port);
        }

        public void Dispose() => Interlocked.Exchange(ref pending, null)?.Stop();
    }

    internal PortChange PreparePort(int port)
    {
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), "Ports must be between 1 and 65535.");
        return new(this, Bind(port), port);
    }

    private TcpListener Bind(int port)
    {
        var candidate = new TcpListener(IPAddress.Parse(options.ListenAddress), port) { ExclusiveAddressUse = true };
        try
        {
            candidate.Start();
            return candidate;
        }
        catch
        {
            candidate.Stop();
            throw;
        }
    }

    private void Activate(TcpListener replacement, int port)
    {
        lock (listenerGate)
        {
            options.Port = port;
            if (stopped)
            {
                replacement.Stop();
                return;
            }
            var previous = listener;
            listener = replacement;
            previous?.Stop();
            portChanged.SetResult();
            portChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        logger.LogInformation("Encrypted file server listening on {Address}:{Port}", options.ListenAddress, port);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var sessions = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var sweep = leases.RunAsync(sessions.Token);
        try
        {
            while (!store.IsInitialized)
                await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            var retryDelay = TimeSpan.FromSeconds(2);
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpListener? accepting = null;
                TcpClient client;
                try
                {
                    ValueTask<TcpClient> pending;
                    lock (listenerGate)
                    {
                        if (listener is null)
                        {
                            listener = Bind(options.Port);
                            logger.LogInformation("Encrypted file server listening on {Address}:{Port}", options.ListenAddress, options.Port);
                        }
                        accepting = listener;
                        pending = accepting.AcceptTcpClientAsync(stoppingToken);
                    }
                    client = await pending;
                }
                catch (Exception ex) when (accepting is not null && ex is SocketException or OperationCanceledException or ObjectDisposedException
                    && !ReferenceEquals(accepting, Volatile.Read(ref listener))) { continue; }
                // Windows can report a peer that disappeared before accept completed.
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted) { continue; }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressNotAvailable
                    or SocketError.AddressAlreadyInUse or SocketError.AccessDenied or SocketError.NetworkDown or SocketError.NetworkReset)
                {
                    Task changed;
                    lock (listenerGate)
                    {
                        if (!ReferenceEquals(listener, accepting))
                            continue;
                        listener?.Stop();
                        listener = null;
                        changed = portChanged.Task;
                    }
                    logger.LogWarning("File listener {Address}:{Port} is unavailable ({Reason}). Retrying in {Seconds} seconds.",
                        options.ListenAddress, options.Port, ex.SocketErrorCode, retryDelay.TotalSeconds);
                    try { await changed.WaitAsync(retryDelay, stoppingToken); }
                    catch (TimeoutException) { }
                    retryDelay = TimeSpan.FromSeconds(Math.Min(30, retryDelay.TotalSeconds * 2));
                    continue;
                }
                retryDelay = TimeSpan.FromSeconds(2);
                if (connections.Count >= options.MaxConnections)
                {
                    client.Dispose();
                    continue;
                }
                client.NoDelay = true;
                var session = Guid.NewGuid();
                var task = ServeAsync(client, session, sessions.Token);
                connections[session] = task;
                _ = task.ContinueWith(_ => { connections.TryRemove(session, out var ignored); },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch when (!stoppingToken.IsCancellationRequested) { Environment.ExitCode = 1; throw; }
        finally
        {
            lock (listenerGate)
            {
                stopped = true;
                listener?.Stop();
                listener = null;
            }
            await sessions.CancelAsync();
            try { await Task.WhenAll(connections.Values.Append(sweep)); }
            finally { leases.Sweep(shutdown: true); }
        }
    }
    private async Task ServeAsync(TcpClient client, Guid session, CancellationToken stoppingToken)
    {
        using (client)
        {
            var remoteEndpoint = client.Client.RemoteEndPoint;
            string actor = "unenrolled";
            var authenticated = false;
            var pipelineOwnsSession = false;
            try
            {
                var stream = client.GetStream();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                var hello = await SecureTransport.ReadPlainAsync<ClientHello>(stream, timeout.Token);
                if (hello.Version != Wire.Version || hello.CryptoSuite != Wire.CryptoSuite ||
                    hello.MlKemPublicKey is not { Length: HybridKem.PublicKeySize } ||
                    hello.IdentityMlKemPublicKey is not { Length: HybridKem.PublicKeySize } ||
                    hello.Nonce is not { Length: 32 } || hello.EphemeralPublicKey is not { Length: >= 64 and <= 160 } ||
                    hello.ClientPublicKey is not { Length: > 0 and <= 256 } || hello.DeviceId is not { Length: 64 } ||
                    hello.MlKemPublicKey.AsSpan().SequenceEqual(hello.IdentityMlKemPublicKey))
                    throw new UnauthorizedAccessException();
                var registration = hello.DeviceName is not null;
                if (hello.InviteEnrollment && !registration)
                    throw new UnauthorizedAccessException();
                if (hello.DeviceName is { } name && (string.IsNullOrWhiteSpace(name) || name.Length > 100 ||
                    name != name.Trim() || name.Any(char.IsControl)))
                    throw new UnauthorizedAccessException();
                var clientPublic = Convert.FromBase64String(hello.ClientPublicKey);
                var publicIdentity = DeviceIdentity.Id(clientPublic, hello.IdentityMlKemPublicKey);
                if (!string.Equals(hello.DeviceId, publicIdentity, StringComparison.Ordinal) ||
                    Convert.ToBase64String(clientPublic) != hello.ClientPublicKey || clientPublic.AsSpan().SequenceEqual(hello.EphemeralPublicKey))
                    throw new UnauthorizedAccessException("The device ID does not match its public keys.");
                var kemPublicText = Convert.ToBase64String(hello.IdentityMlKemPublicKey);
                var registered = store.FindRegisteredDevice(publicIdentity);
                var pending = registered is null;
                if ((!registration && pending) || (registered is not null &&
                    (registered.ClientPublicKey != hello.ClientPublicKey || registered.ClientMlKemPublicKey != kemPublicText)))
                    throw new UnauthorizedAccessException();
                byte[] material;
                using (var ephemeral = KeyAgreement.NewKey())
                using (var secrets = new HandshakeSecrets())
                {
                    var metadata = store.Read(state => (state.ServerId, state.ServerName, state.ServerPublicKey, state.ServerMlKemPublicKey,
                        state.ProtectedServerPrivateKey, state.ProtectedServerMlKemSeed));
                    var ephemeralEc = secrets.Keep(KeyAgreement.Agree(ephemeral, hello.EphemeralPublicKey));
                    var ephemeralChallenge = HybridKem.Encapsulate(hello.MlKemPublicKey);
                    secrets.Keep(ephemeralChallenge.Secret);
                    var clientChallenge = HybridKem.Encapsulate(hello.IdentityMlKemPublicKey);
                    secrets.Keep(clientChallenge.Secret);
                    var response = new ServerHello(RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
                    {
                        Version = Wire.Version,
                        CryptoSuite = Wire.CryptoSuite,
                        ServerId = metadata.ServerId,
                        ServerName = metadata.ServerName,
                        GlobalIdentityPublicKey = Convert.FromBase64String(metadata.ServerPublicKey),
                        ServerMlKemPublicKey = Convert.FromBase64String(metadata.ServerMlKemPublicKey),
                        MlKemCiphertext = ephemeralChallenge.Ciphertext,
                        IdentityMlKemCiphertext = clientChallenge.Ciphertext,
                        PendingApproval = pending,
                        InviteEnrollment = hello.InviteEnrollment
                    };
                    await SecureTransport.WritePlainAsync(stream, response, timeout.Token);
                    var exchange = await SecureTransport.ReadPlainAsync<ClientKeyExchange>(stream, timeout.Token);
                    if (exchange.MlKemCiphertext is not { Length: HybridKem.CiphertextSize })
                        throw new UnauthorizedAccessException();
                    byte[] serverKem;
                    var kemSeed = PrivateStorage.Unprotect(metadata.ProtectedServerMlKemSeed);
                    try
                    {
                        using var identityKem = HybridKem.ImportPrivateSeed(kemSeed);
                        serverKem = secrets.Keep(identityKem.Decapsulate(exchange.MlKemCiphertext));
                    }
                    finally { CryptographicOperations.ZeroMemory(kemSeed); }
                    byte[] staticEc;
                    var ecPrivate = PrivateStorage.Unprotect(metadata.ProtectedServerPrivateKey);
                    try
                    {
                        using var identity = KeyAgreement.ImportPrivate(ecPrivate);
                        staticEc = secrets.Keep(KeyAgreement.Agree(identity, clientPublic));
                    }
                    finally { CryptographicOperations.ZeroMemory(ecPrivate); }
                    var secret = secrets.Keep(KeyAgreement.SessionSecret(staticEc, ephemeralEc, clientChallenge.Secret, serverKem, ephemeralChallenge.Secret));
                    var transcript = KeyAgreement.Transcript(hello, response, exchange);
                    await SecureTransport.WritePlainAsync(stream, new ServerProof(KeyAgreement.Proof(secret, transcript, "server")), timeout.Token);
                    var proof = await SecureTransport.ReadPlainAsync<ClientProof>(stream, timeout.Token);
                    if (!KeyAgreement.Equals(KeyAgreement.Proof(secret, transcript, "client"), proof.Proof))
                        throw new UnauthorizedAccessException();
                    material = KeyAgreement.SessionMaterial(secret, transcript);
                }
                SecureTransport secure;
                try
                {
                    secure = new SecureTransport(stream, material, true, hello.BinaryPayloads);
                }
                finally { CryptographicOperations.ZeroMemory(material); }
                using var transport = secure;
                if (hello.InviteEnrollment)
                {
                    // The bearer code is sent only inside the mutually authenticated AES session.
                    var enrollment = await transport.ReceiveAsync<RpcRequest>(timeout.Token);
                    try
                    {
                        if (enrollment.Operation != "Enroll" || enrollment.InviteCode is not { Length: 32 } || enrollment.Data is not null)
                            throw new RemoteException("InvalidInvite");
                        if (pending)
                        {
                            registered = store.RedeemInvite(new EnrollmentRequest(publicIdentity, hello.DeviceName!, hello.ClientPublicKey, kemPublicText), enrollment.InviteCode);
                            audit.Write(registered.Name, "DeviceInviteApproved", publicIdentity);
                        }
                    }
                    catch (RemoteException ex)
                    {
                        var error = ex.Code == "InvalidInvite" && store.Read(s => s.InviteOnly) ? "InviteRequired" : ex.Code;
                        await transport.SendAsync(RpcResponse.Fail(error), timeout.Token);
                        return;
                    }
                    finally { enrollment.ReleasePayload(); }
                }
                if (registered is null)
                {
                    var result = "PendingApproval";
                    var prior = store.FindPendingDevice(publicIdentity);
                    try
                    {
                        // Only proven possession can add a request to the administrator's queue.
                        if (store.QueueRegistration(new EnrollmentRequest(publicIdentity, hello.DeviceName!, hello.ClientPublicKey, kemPublicText)))
                            result = "Disconnected"; // Approved during this pending handshake. Retry with a new challenge.
                        else if (prior is null)
                            audit.Write(hello.DeviceName!, "DeviceRequested", publicIdentity);
                        else if (prior.Name != hello.DeviceName)
                            audit.Write(hello.DeviceName!, "DeviceRenamed", publicIdentity);
                    }
                    catch (RemoteException ex) { result = ex.Code; }
                    catch (UnauthorizedAccessException)
                    {
                        result = store.FindPendingDevice(publicIdentity)?.Rejected == true ? "DeviceRejected" : "ConfigurationError";
                    }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException) { result = "ConfigurationError"; }
                    await transport.SendAsync(RpcResponse.Fail(result), timeout.Token);
                    return;
                }
                var device = registered!;
                var deviceId = device.Id;
                if (!device.Enabled)
                {
                    await transport.SendAsync(RpcResponse.Fail("DeviceBlocked"), timeout.Token);
                    return;
                }
                if (registration)
                    store.UpdateAuthenticatedDeviceName(device, hello.DeviceName!);
                // Attach counters under the enrollment lock so a concurrent forget cannot recreate an old record.
                var (readyIdentity, counters) = store.Read(_ =>
                {
                    var current = store.Identity(deviceId);
                    if (!current.HasSameIdentity(device))
                        throw new UnauthorizedAccessException();
                    return (current, transfers?.ForDevice(current));
                });
                if (readyIdentity.Name != device.Name)
                    audit.Write(readyIdentity.Name, "DeviceRenamed", publicIdentity);
                await transport.SendAsync(new RpcResponse
                {
                    SupportsSessionResume = hello.BinaryPayloads,
                    SupportsNetworkServices = hello.BinaryPayloads,
                    DeviceName = readyIdentity.Name,
                    UserName = registration ? null : readyIdentity.Name
                }, timeout.Token);
                actor = readyIdentity.Name;
                authenticated = true;
                audit.Write(actor, "Connect", publicIdentity);
                if (hello.BinaryPayloads)
                {
                    pipelineOwnsSession = true;
                    await ServePipelinedAsync(transport, session, deviceId, device, actor, counters, stoppingToken);
                    return;
                }
                while (!stoppingToken.IsCancellationRequested)
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(90));
                    var request = await transport.ReceiveAsync<RpcRequest>(timeout.Token);
                    var result = ExecuteFileRequest(session, device, actor, request, counters);
                    await transport.SendAsync(result, timeout.Token);
                    counters?.ReadSent(result);
                    try
                    {
                        var current = store.Identity(deviceId);
                        if (!current.HasSameIdentity(device))
                            break;
                    }
                    catch (UnauthorizedAccessException) { break; }
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or
                CryptographicException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException or FormatException)
            {
                logger.LogDebug("File session ended: {Reason}", ex.GetType().Name);
                if (!authenticated && !stoppingToken.IsCancellationRequested)
                    AuditAuthenticationFailure(remoteEndpoint);
            }
            catch (PlatformNotSupportedException ex) { logger.LogError("Hybrid key establishment is unavailable: {Reason}", ex.Message); }
            catch (Exception ex) { logger.LogError(ex, "File session failed"); }
            finally
            {
                if (!pipelineOwnsSession) files.ReleaseSession(session);
                if (authenticated) audit.Write(actor, "Disconnect", session.ToString());
            }
        }
    }
    private RpcResponse ExecuteFileRequest(Guid session, Device device, string actor, RpcRequest request,
        ServerTransfers.Counters? counters, OperationReceipts? receipts = null)
    {
        try
        {
            request.Validate();
            if (request.Operation == "ListNetworkServices")
                return new RpcResponse { NetworkServices = store.ListNetworkServices(device) };
            var response = files.Execute(session, device.Id, request, device, receipts, counters);
            if (request.Operation == "List" && request.BasicDirectoryInfo && response.Entries is { } entries)
                return response with { Entries = null, Items = entries.ConvertAll(DirectoryItem.FromEntry) };
            return response;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            var code = FileService.ErrorCode(ex);
            var detail = ex switch
            {
                FileAccessDenial or FileSharingConflict => ex.Message,
                IOException when code == "SharingViolation" => "Windows reported a sharing or lock conflict on the backing storage.",
                _ => null
            };
            audit.Write(actor, request.Operation, request.Path, code, detail);
            return RpcResponse.Fail(code);
        }
    }

    private async Task ServePipelinedAsync(SecureTransport transport, Guid session, Guid deviceId, Device device,
        string actor, ServerTransfers.Counters? counters, CancellationToken stoppingToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var owner = new FileSessionLeases.Owner(lifetime);
        FileSessionLeases.Lease? lease = null;
        using var window = new SemaphoreSlim(16, 16);
        var work = new List<Task>();
        var reads = new List<Task>();
        Task barrier = Task.CompletedTask;
        long previousId = 0;
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                idle.CancelAfter(TimeSpan.FromSeconds(90));
                var request = await transport.ReceiveAsync<RpcRequest>(idle.Token);
                try
                {
                    if (request.RequestId <= previousId)
                        throw new InvalidDataException("Invalid RPC request sequence.");
                    var first = previousId == 0;
                    previousId = request.RequestId;
                    if (first && request.Operation == "OpenNetworkService")
                    {
                        await networkRelays.ServeAsync(transport, request, device, lifetime.Token);
                        request.ReleasePayload();
                        return;
                    }
                    if (first && request.Operation == "ResumeSession")
                    {
                        if (request.Data is not null || request.InviteCode is not null)
                            throw new InvalidDataException("Invalid session negotiation.");
                        lease = await leases.AttachAsync(device, request.Handle, owner, idle.Token);
                        session = lease.FileSession;
                        await transport.SendAsync(new RpcResponse { RequestId = request.RequestId, Handle = lease.Ticket }, idle.Token);
                        request.ReleasePayload();
                        continue;
                    }
                    if (lease is not null && request.Operation == "EndSession")
                    {
                        if (request.Data is not null || request.InviteCode is not null ||
                            request.Handle != Guid.Empty && request.Handle != lease.Ticket)
                            throw new InvalidDataException("Invalid session close.");
                        await Task.WhenAll(work).WaitAsync(idle.Token);
                        leases.Detach(lease, owner, end: true);
                        await transport.SendAsync(new RpcResponse { RequestId = request.RequestId }, idle.Token);
                        request.ReleasePayload();
                        return;
                    }
                    await window.WaitAsync(lifetime.Token);
                }
                catch { request.ReleasePayload(); throw; }
                var dependencies = request.Operation is "Read" or "Stat" or "Security" or "Space" or "Ping"
                    ? barrier : Task.WhenAll(reads.Append(barrier));
                var task = Task.Run(async () =>
                {
                    RpcResponse? response = null;
                    try
                    {
                        await dependencies;
                        lifetime.Token.ThrowIfCancellationRequested();
                        response = ExecuteFileRequest(session, device, actor, request with
                        {
                            BorrowReadBuffer = true
                        }, counters, lease?.Receipts);
                        await transport.SendAsync(response with
                        {
                            RequestId = request.RequestId
                        }, lifetime.Token);
                        counters?.ReadSent(response);
                        var current = store.Identity(deviceId);
                        if (!current.HasSameIdentity(device))
                            lifetime.Cancel();
                    }
                    catch { lifetime.Cancel(); throw; }
                    finally { response?.ReleasePayload(); request.ReleasePayload(); window.Release(); }
                });
                work.RemoveAll(item => item.IsCompletedSuccessfully);
                work.Add(task);
                if (request.Operation is "Read" or "Stat" or "Security" or "Space" or "Ping")
                {
                    reads.RemoveAll(item => item.IsCompletedSuccessfully);
                    reads.Add(task);
                }
                else
                {
                    barrier = task;
                    reads.Clear();
                }
            }
        }
        finally
        {
            await lifetime.CancelAsync();
            try
            {
                await Task.WhenAll(work);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException or ObjectDisposedException)
            {
                logger.LogDebug("Pipelined file session ended: {Reason}", ex.GetType().Name);
            }
            finally
            {
                if (lease is null) files.ReleaseSession(session);
                else leases.Detach(lease, owner, end: stoppingToken.IsCancellationRequested);
            }
        }
    }
    private void AuditAuthenticationFailure(EndPoint? endpoint)
    {
        // Preserve failed authentication evidence without allowing unauthenticated sockets to flood disk logs.
        var now = DateTime.UtcNow.Ticks;
        var previous = Interlocked.Read(ref lastFailureAudit);
        if (now - previous >= TimeSpan.TicksPerSecond && Interlocked.CompareExchange(ref lastFailureAudit, now, previous) == previous)
        {
            var suppressed = Interlocked.Exchange(ref suppressedFailures, 0);
            audit.Write("unverified", "Authenticate", endpoint?.ToString() ?? "unknown", suppressed == 0 ? "Denied" : $"Denied; {suppressed} similar failures suppressed");
        }
        else
            Interlocked.Increment(ref suppressedFailures);
    }
}
