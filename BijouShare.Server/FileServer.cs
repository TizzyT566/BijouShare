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
            await ListenAsync(stoppingToken);
        }
        catch when (!stoppingToken.IsCancellationRequested) { Environment.ExitCode = 1; throw; }
    }
    private async Task ListenAsync(CancellationToken stoppingToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var listener = new TcpListener(IPAddress.Parse(options.ListenAddress), options.Port);
        listener.Start();
        logger.LogInformation("Encrypted file server listening on {Address}:{Port}", options.ListenAddress, options.Port);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(lifetime.Token);
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
                    hello.Nonce is not { Length: 32 } || hello.EphemeralPublicKey is not { Length: >= 64 and <= 160 } ||
                    !Guid.TryParse(hello.DeviceId, out var deviceId))
                    throw new UnauthorizedAccessException();
                var registration = hello.ClientPublicKey is not null || hello.DeviceName is not null;
                if (hello.InviteEnrollment && (!registration || !hello.ServerIdentityMetadata))
                    throw new UnauthorizedAccessException();
                if (registration && (string.IsNullOrWhiteSpace(hello.DeviceName) || hello.DeviceName.Length > 100 ||
                    hello.DeviceName != hello.DeviceName.Trim() || hello.DeviceName.Any(char.IsControl) ||
                    hello.ClientPublicKey is not { Length: > 0 and <= 256 } || deviceId == Guid.Empty))
                    throw new UnauthorizedAccessException();
                var registered = registration ? store.FindRegisteredDevice(deviceId) : store.Identity(deviceId);
                var clientPublic = Convert.FromBase64String(registration ? hello.ClientPublicKey! : registered!.ClientPublicKey);
                using (KeyAgreement.ImportPublic(clientPublic))
                {
                }
                if (registered is not null && !KeyAgreement.Equals(Convert.FromBase64String(registered.ClientPublicKey), clientPublic))
                    throw new UnauthorizedAccessException("The device ID belongs to a different public key.");
                var pending = registered is null;
                byte[] material;
                {
                    using var ephemeral = KeyAgreement.NewKey();
                    byte[] serverIdentity;
                    byte[] identitySecret;
                    if (pending)
                    {
                        serverIdentity = ephemeral.ExportSubjectPublicKeyInfo();
                        identitySecret = KeyAgreement.Agree(ephemeral, clientPublic);
                    }
                    else
                    {
                        serverIdentity = Convert.FromBase64String(registered!.ServerPublicKey);
                        var privateKey = PrivateStorage.Unprotect(registered.ProtectedServerPrivateKey);
                        try
                        {
                            using var identity = KeyAgreement.ImportPrivate(privateKey);
                            identitySecret = KeyAgreement.Agree(identity, clientPublic);
                        }
                        finally { CryptographicOperations.ZeroMemory(privateKey); }
                    }
                    byte[]? ephemeralSecret = null;
                    byte[]? kemSecret = null;
                    try
                    {
                        ephemeralSecret = KeyAgreement.Agree(ephemeral, hello.EphemeralPublicKey);
                        var encapsulation = HybridKem.Encapsulate(hello.MlKemPublicKey);
                        kemSecret = encapsulation.Secret;
                        var serverMetadata = hello.ServerIdentityMetadata
                            ? store.Read(state => (Id: state.ServerId, Name: state.ServerName, PublicKey: state.ServerPublicKey, ProtectedPrivateKey: state.ProtectedServerPrivateKey))
                            : ((string Id, string Name, string PublicKey, byte[] ProtectedPrivateKey)?)null;
                        var response = new ServerHello(RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo(), [])
                        {
                            Version = Wire.Version,
                            CryptoSuite = Wire.CryptoSuite,
                            MlKemCiphertext = encapsulation.Ciphertext,
                            InviteEnrollment = hello.InviteEnrollment,
                            ServerId = serverMetadata?.Id,
                            ServerName = serverMetadata?.Name,
                            GlobalIdentityPublicKey = serverMetadata is { } metadata ? Convert.FromBase64String(metadata.PublicKey) : null,
                            IdentityPublicKey = registration ? serverIdentity : null,
                            PendingApproval = pending
                        };
                        var transcript = KeyAgreement.Transcript(hello, response, serverIdentity);
                        response = response with
                        {
                            Proof = KeyAgreement.HybridProof(identitySecret, ephemeralSecret, kemSecret, transcript, "server")
                        };
                        if (hello.ServerIdentityMetadata)
                        {
                            var globalPrivate = PrivateStorage.Unprotect(serverMetadata!.Value.ProtectedPrivateKey);
                            try
                            {
                                using var globalIdentity = KeyAgreement.ImportPrivate(globalPrivate);
                                var globalSecret = KeyAgreement.Agree(globalIdentity, clientPublic);
                                try
                                {
                                    response = response with
                                    {
                                        ServerIdentityProof = KeyAgreement.HybridProof(globalSecret, ephemeralSecret, kemSecret, transcript, "server-identity")
                                    };
                                }
                                finally { CryptographicOperations.ZeroMemory(globalSecret); }
                            }
                            finally { CryptographicOperations.ZeroMemory(globalPrivate); }
                        }
                        await SecureTransport.WritePlainAsync(stream, response, timeout.Token);
                        var proof = await SecureTransport.ReadPlainAsync<ClientProof>(stream, timeout.Token);
                        if (proof.Proof is not { Length: 32 } || !KeyAgreement.Equals(KeyAgreement.HybridProof(identitySecret, ephemeralSecret, kemSecret, transcript, "client"), proof.Proof))
                            throw new UnauthorizedAccessException();
                        material = KeyAgreement.SessionMaterial(identitySecret, ephemeralSecret, kemSecret, transcript);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(identitySecret);
                        if (ephemeralSecret is not null)
                            CryptographicOperations.ZeroMemory(ephemeralSecret);
                        if (kemSecret is not null)
                            CryptographicOperations.ZeroMemory(kemSecret);
                    }
                } // Dispose the ECDHE private key before entering the long-lived file session.
                SecureTransport secure;
                try
                {
                    secure = new SecureTransport(stream, material, true, hello.BinaryPayloads);
                }
                finally { CryptographicOperations.ZeroMemory(material); }
                using var transport = secure;
                string? enrollmentPublicKey = null;
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
                            registered = store.RedeemInvite(new EnrollmentRequest(hello.DeviceId, hello.DeviceName!, hello.ClientPublicKey!), enrollment.InviteCode);
                            enrollmentPublicKey = registered.ServerPublicKey;
                            audit.Write(registered.Name, "DeviceInviteApproved", deviceId.ToString());
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
                    var prior = store.FindPendingDevice(deviceId);
                    try
                    {
                        // Only proven possession can add a request to the administrator's queue.
                        store.QueueRegistration(new EnrollmentRequest(hello.DeviceId, hello.DeviceName!, hello.ClientPublicKey!));
                        if (prior is null)
                            audit.Write(hello.DeviceName!, "DeviceRequested", deviceId.ToString());
                        else if (prior.Name != hello.DeviceName)
                            audit.Write(hello.DeviceName!, "DeviceRenamed", deviceId.ToString());
                    }
                    catch (UnauthorizedAccessException) { result = store.FindPendingDevice(deviceId)?.Rejected == true ? "DeviceRejected" : "DeviceBlocked"; }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException) { result = "DeviceBlocked"; }
                    await transport.SendAsync(RpcResponse.Fail(result), timeout.Token);
                    return;
                }
                var device = registered!;
                if (!device.Enabled)
                {
                    await transport.SendAsync(RpcResponse.Fail("DeviceBlocked"), timeout.Token);
                    return;
                }
                var readyIdentity = registration
                    ? store.UpdateAuthenticatedDeviceName(device, hello.DeviceName!)
                    : store.Identity(deviceId);
                if (!SameIdentity(readyIdentity, device))
                    throw new UnauthorizedAccessException();
                if (readyIdentity.Name != device.Name)
                    audit.Write(readyIdentity.Name, "DeviceRenamed", deviceId.ToString());
                await transport.SendAsync(new RpcResponse
                {
                    DeviceName = readyIdentity.Name,
                    UserName = registration ? null : readyIdentity.Name,
                    EnrollmentServerPublicKey = enrollmentPublicKey
                }, timeout.Token);
                actor = readyIdentity.Name;
                authenticated = true;
                audit.Write(actor, "Connect", deviceId.ToString());
                if (hello.BinaryPayloads)
                {
                    await ServePipelinedAsync(transport, session, deviceId, device, actor, stoppingToken);
                    return;
                }
                while (!stoppingToken.IsCancellationRequested)
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(90));
                    var request = await transport.ReceiveAsync<RpcRequest>(timeout.Token);
                    RpcResponse result;
                    try
                    {
                        request.Validate();
                        result = files.Execute(session, deviceId, request, device);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
                    {
                        result = RpcResponse.Fail(FileService.ErrorCode(ex));
                        audit.Write(actor, request.Operation, request.Path, result.Error!);
                    }
                    await transport.SendAsync(result, timeout.Token);
                    try
                    {
                        var current = store.Identity(deviceId);
                        if (!SameIdentity(current, device))
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
    private static bool SameIdentity(Device current, Device authenticated) => current.Id == authenticated.Id &&
        current.ClientPublicKey == authenticated.ClientPublicKey && current.ServerPublicKey == authenticated.ServerPublicKey;
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
                        try
                        {
                            request.Validate();
                            response = files.Execute(session, deviceId, request with
                            {
                                BorrowReadBuffer = true
                            }, device);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
                        {
                            response = RpcResponse.Fail(FileService.ErrorCode(ex));
                            audit.Write(actor, request.Operation, request.Path, response.Error!);
                        }
                        await transport.SendAsync(response with
                        {
                            RequestId = request.RequestId
                        }, lifetime.Token);
                        var current = store.Identity(deviceId);
                        if (!SameIdentity(current, device))
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
