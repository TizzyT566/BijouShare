using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed class FileServer(ServerOptions options, StateStore store, FileService files,
    AuditLog audit, ILogger<FileServer> logger) : BackgroundService
{
    private readonly ConcurrentDictionary<Guid, Task> connections = new();
    private long lastFailureAudit;
    private int suppressedFailures;
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.Port is < 1 or > 65535 || options.MaxConnections is < 1 or > 4096 ||
            !IPAddress.TryParse(options.ListenAddress, out _))
            throw new ArgumentException("Invalid file server configuration.");
        await base.StartAsync(cancellationToken);
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!store.IsInitialized)
                await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            var retryDelay = TimeSpan.FromSeconds(2);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ListenAsync(stoppingToken);
                    return;
                }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressNotAvailable
                    or SocketError.NetworkDown or SocketError.NetworkReset)
                {
                    logger.LogWarning("File listener {Address}:{Port} is unavailable ({Reason}). Retrying in {Seconds} seconds.",
                        options.ListenAddress, options.Port, ex.SocketErrorCode, retryDelay.TotalSeconds);
                    await Task.Delay(retryDelay, stoppingToken);
                    retryDelay = TimeSpan.FromSeconds(Math.Min(30, retryDelay.TotalSeconds * 2));
                }
            }
        }
        catch when (!stoppingToken.IsCancellationRequested) { Environment.ExitCode = 1; throw; }
    }
    private async Task ListenAsync(CancellationToken stoppingToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        using var listener = new TcpListener(IPAddress.Parse(options.ListenAddress), options.Port);
        listener.Start();
        logger.LogInformation("Encrypted file server listening on {Address}:{Port}", options.ListenAddress, options.Port);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(lifetime.Token); }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
                {
                    // Windows can report a peer that disappeared before accept completed.
                    continue;
                }
                if (connections.Count >= options.MaxConnections)
                {
                    client.Dispose();
                    continue;
                }
                client.NoDelay = true;
                var session = Guid.NewGuid();
                var task = ServeAsync(client, session, lifetime.Token);
                connections[session] = task;
                _ = task.ContinueWith(_ => { connections.TryRemove(session, out var ignored); },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            listener.Stop();
            await lifetime.CancelAsync(); // An unexpected listener failure must also close existing sessions.
            await Task.WhenAll(connections.Values);
        }
    }
    private async Task ServeAsync(TcpClient client, Guid session, CancellationToken stoppingToken)
    {
        using (client)
        {
            var remoteEndpoint = client.Client.RemoteEndPoint;
            string actor = "unenrolled";
            var authenticated = false;
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
                        await transport.SendAsync(RpcResponse.Fail(ex.Code), timeout.Token);
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
                        store.QueueRegistration(new EnrollmentRequest(publicIdentity, hello.DeviceName!, hello.ClientPublicKey, kemPublicText));
                        if (prior is null)
                            audit.Write(hello.DeviceName!, "DeviceRequested", publicIdentity);
                        else if (prior.Name != hello.DeviceName)
                            audit.Write(hello.DeviceName!, "DeviceRenamed", publicIdentity);
                    }
                    catch (UnauthorizedAccessException) { result = store.FindPendingDevice(publicIdentity)?.Rejected == true ? "DeviceRejected" : "DeviceBlocked"; }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException) { result = "DeviceBlocked"; }
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
                var readyIdentity = registration
                    ? store.UpdateAuthenticatedDeviceName(device, hello.DeviceName!)
                    : store.Identity(deviceId);
                if (!readyIdentity.HasSameIdentity(device))
                    throw new UnauthorizedAccessException();
                if (readyIdentity.Name != device.Name)
                    audit.Write(readyIdentity.Name, "DeviceRenamed", publicIdentity);
                await transport.SendAsync(new RpcResponse
                {
                    DeviceName = readyIdentity.Name,
                    UserName = registration ? null : readyIdentity.Name
                }, timeout.Token);
                actor = readyIdentity.Name;
                authenticated = true;
                audit.Write(actor, "Connect", publicIdentity);
                if (hello.BinaryPayloads)
                {
                    await ServePipelinedAsync(transport, session, deviceId, device, actor, stoppingToken);
                    return;
                }
                while (!stoppingToken.IsCancellationRequested)
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(90));
                    var request = await transport.ReceiveAsync<RpcRequest>(timeout.Token);
                    var result = ExecuteFileRequest(session, device, actor, request);
                    await transport.SendAsync(result, timeout.Token);
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
            finally { files.ReleaseSession(session); if (authenticated) audit.Write(actor, "Disconnect", session.ToString()); }
        }
    }
    private RpcResponse ExecuteFileRequest(Guid session, Device device, string actor, RpcRequest request)
    {
        try
        {
            request.Validate();
            return files.Execute(session, device.Id, request, device);
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
        string actor, CancellationToken stoppingToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
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
                    previousId = request.RequestId;
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
                        });
                        await transport.SendAsync(response with
                        {
                            RequestId = request.RequestId
                        }, lifetime.Token);
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
