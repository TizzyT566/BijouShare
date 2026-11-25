using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed record ServerConnectionStatus(string Name, bool Connected, string? Error);

/// <summary>One drive namespace, with an independent authenticated connection beneath each server folder.</summary>
public sealed class MultiServerConnection : IRemoteConnection, IDisposable
{
    private sealed class Target(string label, IRemoteConnection connection, Func<string?> folderName, Func<string?> identity)
    {
        public string Address { get; } = label;
        public string Name => FolderName ?? Address;
        public string? FolderName => folderName();
        public string? Identity => identity();
        public IRemoteConnection Connection { get; } = connection;
        public readonly object Gate = new();
        public Task? Probe;
        public ServerConnectionStatus Status = new(label, false, "Waiting");
        public long FreeBytes;
        public long TotalBytes;
        public ServerEndpoint? Endpoint { get; init; }
        public Func<Target>? Reconnect { get; init; }
        public CancellationToken VerificationToken { get; init; }
        public int Removed;
        public long FailureRevision;
        public bool InviteNoticeSent;
        public bool RevocationReported;
        public bool HasConnected;
        public string? AuthenticatedIdentity;
        public long? DisconnectedAt;
        public long RecoveryUntil;
        public readonly ConcurrentDictionary<DeferredClose, byte> DeferredCloses = new();
        public readonly SemaphoreSlim Closing = new(1, 1);
        public long CloseGeneration;
    }

    private static Target CreateTarget(ClientSettings settings, ServerEndpoint endpoint, ILoggerFactory loggerFactory)
    {
        var view = settings.ForServer(endpoint);
        var connection = new RemoteConnection(view, loggerFactory.CreateLogger<RemoteConnection>());
        var address = endpoint.Host.Contains(':') ? $"[{endpoint.Host}]:{endpoint.Port}" : $"{endpoint.Host}:{endpoint.Port}";
        return new Target(address, connection, () => endpoint.FolderName,
            () => endpoint.PresentedServerId)
        {
            Endpoint = endpoint,
            Reconnect = () => CreateTarget(settings, endpoint, loggerFactory),
            VerificationToken = view.VerificationToken
        };
    }
    private sealed record Handle(Target Server, Guid RemoteHandle, long Generation, string FolderName, string? Identity);
    private readonly record struct DeferredClose(Guid Handle, long Generation, string? Identity);
    private const int MaximumDeferredCloses = 512; // The server's per-session open handle limit.
    private sealed record Route(Target Server, string Name, string? Identity);
    private sealed record RouteStamp(string? Name, string? Identity, bool Connected, long RetainUntil);
    private sealed record RouteTable(Dictionary<string, Route> Names, HashSet<string> Conflicts, Route[] Entries,
        long ExpiresAt = long.MaxValue);
    private Target[] targets;
    private readonly string? mountPoint;
    private readonly object routeGate = new();
    private readonly Func<long> milliseconds;
    internal const int WakeRecoveryMilliseconds = 30_000;
    private const int DisconnectGraceMilliseconds = 4_000;
    private RouteStamp[] routeStamps = [];
    private RouteTable routes = new(new(StringComparer.OrdinalIgnoreCase), new(StringComparer.OrdinalIgnoreCase), []);
    private readonly ConcurrentDictionary<Guid, Handle> handles = new();
    private readonly CancellationTokenSource lifetime = new();
    private int disposed;
    internal event Action<string>? InviteRequired;
    internal event Action? EnrollmentRevoked;
    private static readonly DateTime NamespaceTime = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private const Permission NamespacePermissions = Permission.ListDirectory | Permission.ReadAttributes | Permission.ReadPermissions;

    public MultiServerConnection(ClientSettings settings, ILoggerFactory loggerFactory)
        : this(settings, loggerFactory, settings.MountPoint)
    {
    }

    internal MultiServerConnection(ClientSettings settings, ILoggerFactory loggerFactory, string mountPoint)
        : this(Array.Empty<(string, IRemoteConnection, Func<string?>, Func<string?>)>())
    {
        this.mountPoint = mountPoint;
        if (settings.SetupComplete)
            Synchronize(settings, loggerFactory);
    }

    internal MultiServerConnection(IEnumerable<(string Name, IRemoteConnection Connection)> servers)
        : this(servers.Select(server => (ValidateName(server.Name), server.Connection,
            (Func<string?>)(() => server.Name), (Func<string?>)(() => null))))
    {
    }

    internal MultiServerConnection(IEnumerable<(string Label, IRemoteConnection Connection, Func<string?> FolderName, Func<string?> Identity)> servers,
        Func<long>? milliseconds = null)
    {
        this.milliseconds = milliseconds ?? (() => Environment.TickCount64);
        targets = servers.Select(server => new Target(server.Label, server.Connection, server.FolderName, server.Identity)).ToArray();
        RefreshRoutes();
    }

    // Publish an immutable target snapshot so Explorer can keep using the drive while servers change.
    public void Synchronize(ClientSettings settings, ILoggerFactory loggerFactory, bool reconnectAll = false, ServerEndpoint? reconnect = null)
    {
        var removed = new List<Target>();
        lock (routeGate)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            var existing = Volatile.Read(ref targets);
            var next = settings.ServerSnapshot(mountPoint).Select(server =>
            {
                var retained = existing.SingleOrDefault(target => ReferenceEquals(target.Endpoint, server));
                if (retained is not null && !retained.VerificationToken.IsCancellationRequested &&
                    !reconnectAll && !ReferenceEquals(reconnect, server))
                    return retained;
                var replacement = CreateTarget(settings, server, loggerFactory);
                if (retained is not null)
                {
                    replacement.RevocationReported = retained.RevocationReported;
                    if (!ReferenceEquals(reconnect, server))
                        replacement.InviteNoticeSent = retained.InviteNoticeSent;
                }
                return replacement;
            }).ToArray();
            removed.AddRange(existing.Except(next));
            foreach (var target in removed)
                Volatile.Write(ref target.Removed, 1);
            Volatile.Write(ref targets, next);
            routeStamps = [];
            if (next.Length == 0)
                Volatile.Write(ref routes, new(new(StringComparer.OrdinalIgnoreCase), new(StringComparer.OrdinalIgnoreCase), []));
            else
                RefreshRoutes();
            foreach (var handle in handles.Where(pair => removed.Contains(pair.Value.Server)))
                handles.TryRemove(handle.Key, out _);
        }
        foreach (var target in removed)
            (target.Connection as IDisposable)?.Dispose();
    }

    internal IRemoteConnection? ConnectionFor(ServerEndpoint endpoint) =>
        Volatile.Read(ref targets).FirstOrDefault(target => ReferenceEquals(target.Endpoint, endpoint))?.Connection;

    public ServerConnectionStatus StatusFor(ServerEndpoint endpoint)
    {
        var target = Volatile.Read(ref targets).SingleOrDefault(target => ReferenceEquals(target.Endpoint, endpoint));
        if (target is null)
            return new(endpoint.FolderName ?? endpoint.Host, false, "Waiting");
        if (Volatile.Read(ref routes).Conflicts.Contains(target.Name))
            return new(target.Name, false, "ServerIdentityConflict");
        return Volatile.Read(ref target.Status) with
        {
            Name = target.Name
        };
    }

    internal static string ValidateName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 255 || value != value.Trim() || value is "." or ".." ||
            value.EndsWith('.') || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            Regex.IsMatch(value, @"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            throw new ArgumentException("Use an ordinary Windows folder name for each server.");
        return value;
    }

    public IReadOnlyList<ServerConnectionStatus> Statuses
    {
        get
        {
            var snapshot = Volatile.Read(ref routes);
            return Volatile.Read(ref targets).Select(target => snapshot.Conflicts.Contains(target.Name)
                    ? new ServerConnectionStatus(target.Name, false, "ServerIdentityConflict")
                    : Volatile.Read(ref target.Status) with
                    {
                        Name = target.Name
                    })
                .GroupBy(status => status.Name, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.OrderByDescending(status => status.Connected).First()).ToArray();
        }
    }
    public int MaxTransferSize => Wire.MaxChunk;
    private RouteTable CurrentRoutes
    {
        get
        {
            var current = Volatile.Read(ref routes);
            if (current.ExpiresAt == long.MaxValue || milliseconds() < current.ExpiresAt)
                return current;
            RefreshRoutes();
            return Volatile.Read(ref routes);
        }
    }
    internal bool HasRecoveringFolders => CurrentRoutes.ExpiresAt != long.MaxValue;
    internal string[] MountedServerFolders => CurrentRoutes.Entries.Select(entry => entry.Name).ToArray();
    public int MaxTransferSizeFor(string path)
    {
        try
        {
            return Parse(path).Server?.Connection.MaxTransferSize ?? Wire.MaxChunk;
        }
        catch (RemoteException ex) when (ex.Code == "NotFound") { return Wire.LegacyMaxChunk; } // Retained handles can refer to an older server name.
    }

    private void RefreshRoutes()
    {
        lock (routeGate)
        {
            var current = Volatile.Read(ref targets);
            var now = milliseconds();
            long RetainUntil(Target target) => target.DisconnectedAt.HasValue && target.RecoveryUntil > now &&
                !target.VerificationToken.IsCancellationRequested && target.AuthenticatedIdentity is { } id && id == target.Identity
                    ? target.RecoveryUntil : 0;
            var changed = routeStamps.Length != current.Length;
            for (var index = 0; !changed && index < current.Length; index++)
            {
                var target = current[index];
                changed = routeStamps[index].Name != target.FolderName || routeStamps[index].Identity != target.Identity ||
                    routeStamps[index].Connected != target.Status.Connected || routeStamps[index].RetainUntil != RetainUntil(target);
            }
            if (!changed)
                return;
            var stamps = current.Select(target => new RouteStamp(target.FolderName, target.Identity, target.Status.Connected, RetainUntil(target))).ToArray();
            var names = new Dictionary<string, Route>(StringComparer.OrdinalIgnoreCase);
            var conflicts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var candidates = current.Select((target, index) => stamps[index].Name is { } name
                ? new Route(target, ValidateName(name), stamps[index].Identity) : null).Where(route => route is not null).Select(route => route!);
            foreach (var group in candidates.GroupBy(route => route.Name, StringComparer.OrdinalIgnoreCase))
            {
                var entries = group.ToArray();
                if (entries.Length > 1 && (entries.Any(entry => entry.Identity is null) || entries.Select(entry => entry.Identity).Distinct(StringComparer.Ordinal).Count() != 1))
                {
                    conflicts.Add(group.Key);
                    continue;
                } // A short display-ID collision must never choose an arbitrary server.
                // Prefer a live endpoint. Keep its pinned name routable briefly while Wi-Fi returns.
                var chosen = entries.FirstOrDefault(entry => entry.Server.Status.Connected) ??
                    entries.FirstOrDefault(entry => RetainUntil(entry.Server) != 0);
                if (chosen is not null)
                    names.Add(chosen.Name, chosen);
            }
            routeStamps = stamps;
            var expiresAt = stamps.Where(stamp => stamp.RetainUntil != 0).Select(stamp => stamp.RetainUntil).DefaultIfEmpty(long.MaxValue).Min();
            Volatile.Write(ref routes, new(names, conflicts, names.Values.ToArray(), expiresAt));
        }
    }

    internal void RequestRefresh() => StartProbes(queue: true);

    private List<Task> StartProbes(bool queue = false, bool retryOnly = false)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        // Rebuild endpoints invalidated by a settings change.
        foreach (var target in Volatile.Read(ref targets))
            if (target.VerificationToken.IsCancellationRequested)
                ReplaceConnection(target);
        return Volatile.Read(ref targets).Where(target => !retryOnly ||
            Volatile.Read(ref target.Status).Error is "Waiting" or "Disconnected" or "Timeout").Select(target =>
        {
            lock (target.Gate)
            {
                if (target.Probe is null || target.Probe.IsCompleted)
                    target.Probe = queue ? Task.Run(() => ProbeAsync(target)) : ProbeAsync(target);
                return target.Probe;
            }
        }).ToList();
    }

    // Probe every endpoint independently. A slow/offline endpoint cannot delay mounting a healthy one.
    public Task<IReadOnlyList<ServerConnectionStatus>> RefreshAsync(CancellationToken token) => RefreshAsync(token, retryOnly: false);

    internal async Task<IReadOnlyList<ServerConnectionStatus>> RefreshAsync(CancellationToken token, bool retryOnly)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token);
        var probes = StartProbes(retryOnly: retryOnly);
        var pause = Task.Delay(TimeSpan.FromSeconds(1), linked.Token);
        while (probes.Count > 0)
        {
            var completed = await Task.WhenAny(probes.Append(pause));
            linked.Token.ThrowIfCancellationRequested();
            if (completed == pause)
                break;
            await completed;
            probes.Remove(completed);
            if (Statuses.Any(status => status.Connected))
                break;
        }
        return Statuses;
    }

    internal Task<IReadOnlyList<ServerConnectionStatus>> RecoverAfterResumeAsync(CancellationToken token, bool resumed = true)
    {
        var now = milliseconds();
        foreach (var target in Volatile.Read(ref targets))
        {
            token.ThrowIfCancellationRequested();
            bool known;
            lock (routeGate)
            {
                known = target.HasConnected;
                if (target.Status.Connected || target.DisconnectedAt.HasValue && target.RecoveryUntil > now)
                    // Repeated Windows notifications cannot extend a continuing outage indefinitely.
                    target.RecoveryUntil = (target.DisconnectedAt ?? now) + WakeRecoveryMilliseconds;
            }
            if (!known)
                ReplaceConnection(target);
            else if (resumed && target.Connection is RemoteConnection remote)
                remote.PrepareAfterWake();
        }
        RefreshRoutes();
        return RefreshAsync(token);
    }

    internal void ResetAfterUnmount()
    {
        // Windows has abandoned the mount's handles. Closing each session releases server-side writer leases.
        foreach (var target in Volatile.Read(ref targets))
            ReplaceConnection(target);
    }

    private void ReplaceConnection(Target target)
    {
        if (target.Reconnect is not { } reconnect)
            return;
        lock (routeGate)
        {
            var current = Volatile.Read(ref targets);
            var index = Array.IndexOf(current, target);
            if (index < 0 || Volatile.Read(ref disposed) != 0)
                return;
            var next = (Target[])current.Clone();
            // The profile may have removed this endpoint while its heartbeat was queued.
            try { next[index] = reconnect(); }
            catch (ArgumentException) when (target.VerificationToken.IsCancellationRequested) { return; }
            next[index].InviteNoticeSent = target.InviteNoticeSent;
            next[index].RevocationReported = target.RevocationReported;
            Volatile.Write(ref target.Removed, 1);
            Volatile.Write(ref targets, next);
            routeStamps = [];
            RefreshRoutes();
            foreach (var handle in handles.Where(pair => pair.Value.Server == target))
                handles.TryRemove(handle.Key, out _);
        }
        // Close old sockets and cancel any handshakes started before the adapter came back.
        (target.Connection as IDisposable)?.Dispose();
    }

    private async Task ProbeAsync(Target target)
    {
        var revision = Volatile.Read(ref target.FailureRevision);
        try
        {
            var ping = await target.Connection.CallAsync(new()
            {
                Operation = "Ping"
            }, token: lifetime.Token);
            if (target.FolderName is null)
            {
                MarkUnavailable(target, "ServerUpgradeRequired");
                return;
            }
            if (!target.DeferredCloses.IsEmpty)
            {
                lock (routeGate)
                    AdvanceCloseGeneration(target, ping.Generation);
                await ReleaseDeferredClosesAsync(target, lifetime.Token);
            }
            var space = (await target.Connection.CallAsync(new()
            {
                Operation = "Space"
            }, token: lifetime.Token)).Response;
            Interlocked.Exchange(ref target.FreeBytes, Math.Max(0, space.FreeBytes));
            Interlocked.Exchange(ref target.TotalBytes, Math.Max(0, space.TotalBytes));
            lock (routeGate)
            {
                // A newer IO failure takes precedence over a probe that was already in flight.
                if (target.FailureRevision == revision && Volatile.Read(ref target.Removed) == 0 && Volatile.Read(ref disposed) == 0)
                {
                    target.InviteNoticeSent = false;
                    target.RevocationReported = false;
                    target.HasConnected = true;
                    target.AuthenticatedIdentity = target.Identity;
                    if (target.DisconnectedAt.HasValue)
                        target.RecoveryUntil = 0;
                    target.DisconnectedAt = null;
                    Volatile.Write(ref target.Status, new(target.Name, true, null));
                    RefreshRoutes();
                }
            }
        }
        catch (RemoteException ex) when (ex.Code == "Timeout" && Volatile.Read(ref target.Status).Connected)
        {
            // A timeout before transmission says nothing about the authenticated connection.
        }
        catch (RemoteException ex) { MarkUnavailable(target, ex.Code == "OutcomeUnknown" ? "Disconnected" : ex.Code); }
        catch (ServerIdentityMismatchException) { MarkUnavailable(target, "ServerIdentityChanged"); }
        catch (CryptographicException) { MarkUnavailable(target, "AuthenticationFailed"); }
        catch (UnauthorizedAccessException) { MarkUnavailable(target, "ConfigurationError"); }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            MarkUnavailable(target, "Disconnected");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            MarkUnavailable(target, "ConfigurationError");
        }
        finally { RefreshRoutes(); }
    }

    private void MarkUnavailable(Target target, string error)
    {
        var notify = false;
        var revoked = false;
        lock (routeGate)
        {
            if (Volatile.Read(ref target.Removed) != 0 || Volatile.Read(ref disposed) != 0 || target.VerificationToken.IsCancellationRequested)
                return;
            target.FailureRevision++;
            if (error is "Disconnected" or "Timeout")
            {
                if (target.Status.Connected && target.AuthenticatedIdentity is not null)
                {
                    // I/O may notice the adapter loss before Windows signals the worker.
                    var now = milliseconds();
                    target.DisconnectedAt = now;
                    target.RecoveryUntil = Math.Max(target.RecoveryUntil, now + DisconnectGraceMilliseconds);
                }
            }
            else
            {
                target.DisconnectedAt = null;
                target.RecoveryUntil = 0;
                if (RetiresLease(error))
                    target.DeferredCloses.Clear();
            }
            if (error == "InviteRequired" && !target.InviteNoticeSent)
            {
                target.InviteNoticeSent = true;
                notify = true;
            }
            // These enrollment responses follow the pinned server's encrypted handshake.
            // A stored folder identity is populated only after a previous admission.
            if (!target.RevocationReported && (target.HasConnected || target.Endpoint?.FolderName is not null) &&
                error is "DeviceBlocked" or "DeviceRejected" or "PendingApproval" or "InviteRequired")
            {
                target.RevocationReported = true;
                revoked = true;
            }
            Volatile.Write(ref target.Status, new(target.Name, false, error));
            RefreshRoutes();
        }
        if (revoked)
        {
            try { EnrollmentRevoked?.Invoke(); }
            catch
            {
                // A failed grant-store write must be retried on the next authenticated rejection.
                lock (routeGate) target.RevocationReported = false;
                throw;
            }
        }
        if (notify)
            InviteRequired?.Invoke(target.Address);
    }

    public RemoteReply Call(RpcRequest request, long? expectedGeneration = null) =>
        CallAsync(request, expectedGeneration).GetAwaiter().GetResult();

    public async Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token);
        (Target? Server, string Path, string? Identity) route;
        Handle? mapped = null;
        if (request.Handle != Guid.Empty)
        {
            if (request.Operation == "Open" || !handles.TryGetValue(request.Handle, out mapped) || expectedGeneration != mapped.Generation)
                throw new RemoteException("InvalidHandle");
            var parts = NormalizePath(request.Path);
            if (Volatile.Read(ref mapped.Server.Removed) != 0 || mapped.Identity != mapped.Server.Identity || parts.Length > 0 &&
                !parts[0].Equals(mapped.FolderName, StringComparison.OrdinalIgnoreCase) &&
                !parts[0].Equals(mapped.Server.FolderName, StringComparison.OrdinalIgnoreCase))
                throw new RemoteException("InvalidHandle");
            route = (mapped.Server, parts.Length <= 1 ? "/" : "/" + string.Join('/', parts.Skip(1)), mapped.Identity);
        }
        else
            route = Parse(request.Path);
        if (mapped?.RemoteHandle == Guid.Empty && route.Path != "/")
            throw new RemoteException("InvalidHandle");
        if ((mapped is null || mapped.RemoteHandle == Guid.Empty) && (route.Server is null || route.Path == "/"))
        {
            if (request.Operation == "List" && route.Server is not null)
                return await Forward(route.Server, request with
                {
                    Path = "/", Handle = Guid.Empty
                }, null, route.Identity, linked.Token);
            var result = new RemoteReply(Namespace(request, route.Server), 0);
            if (mapped is not null && request.Operation == "Close")
                handles.TryRemove(request.Handle, out _);
            return request.Operation == "Open" && route.Server is not null
                ? RetainHandle(route.Server, route.Identity, request.Path, result) : result;
        }
        var target = route.Server ?? throw new RemoteException("InvalidHandle");
        var destination = request.Destination;
        if (destination is not null)
        {
            var other = Parse(destination);
            if (other.Identity != route.Identity || other.Server != target)
                throw new RemoteException("NotSameDevice");
            if (other.Path == "/")
                throw new RemoteException("AccessDenied");
            destination = other.Path;
        }
        var forwarded = request with
        {
            Path = route.Path,
            Destination = destination,
            Handle = mapped?.RemoteHandle ?? Guid.Empty
        };
        if (mapped is not null && request.Operation == "Close")
        {
            if (!handles.TryRemove(request.Handle, out _))
                throw new RemoteException("InvalidHandle");
            try { return await Forward(target, forwarded, mapped.Generation, route.Identity, linked.Token); }
            catch (Exception ex) when (ex is OperationCanceledException or RemoteException { Code: "Disconnected" or "Timeout" or "OutcomeUnknown" })
            {
                RememberClose(mapped);
                throw;
            }
        }
        if (request.Operation == "Open" && !target.DeferredCloses.IsEmpty)
            await ReleaseDeferredClosesAsync(target, linked.Token);
        var reply = await Forward(target, forwarded, mapped?.Generation, route.Identity, linked.Token);
        return request.Operation == "Open" && reply.Response.Handle != Guid.Empty
            ? RetainHandle(target, route.Identity, request.Path, reply) : reply;
    }

    // Windows abandons its local handle after Close even when the server was unreachable.
    // Keep only the remote handle and original lease. A later pathname could refer to a replacement file.
    private void RememberClose(Handle handle)
    {
        var target = handle.Server;
        lock (routeGate)
        {
            if (disposed != 0 || target.Removed != 0 || target.VerificationToken.IsCancellationRequested ||
                target.Identity != handle.Identity || target.CloseGeneration > handle.Generation || RetiresLease(target.Status.Error))
                return;
            AdvanceCloseGeneration(target, handle.Generation);
            var close = new DeferredClose(handle.RemoteHandle, handle.Generation, handle.Identity);
            if (target.DeferredCloses.ContainsKey(close))
                return;
            if (target.DeferredCloses.Count < MaximumDeferredCloses)
            {
                target.DeferredCloses.TryAdd(close, 0);
                return;
            }
        }
        // An inconsistent peer exceeded its session limit. Retire the whole lease.
        ReplaceConnection(target);
    }

    private static bool RetiresLease(string? error) => error is "DeviceBlocked" or "DeviceRejected" or "PendingApproval"
        or "InviteRequired" or "InvalidInvite" or "InviteUnsupported" or "ServerLinkRequired" or "ServerIdentityChanged"
        or "AuthenticationFailed" or "ServerUpgradeRequired";

    private static void AdvanceCloseGeneration(Target target, long generation)
    {
        if (generation <= target.CloseGeneration)
            return;
        target.CloseGeneration = generation;
        target.DeferredCloses.Clear();
    }

    private async Task ReleaseDeferredClosesAsync(Target target, CancellationToken token)
    {
        if (target.DeferredCloses.IsEmpty)
            return;
        // Reserve time for the caller's own network request inside Dokan's 60-second deadline.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            await target.Closing.WaitAsync(deadline.Token);
            try
            {
                var pending = target.DeferredCloses.Keys;
                if (pending.Count == 0)
                    return;
                var options = new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = deadline.Token };
                await Parallel.ForEachAsync(pending, options, async (close, cancellation) =>
                {
                    if (!target.DeferredCloses.ContainsKey(close))
                        return;
                    try
                    {
                        await Forward(target, new() { Operation = "Close", Handle = close.Handle },
                            close.Generation, close.Identity, cancellation);
                    }
                    catch (RemoteException ex) when (ex.Code == "InvalidHandle") { } // Already closed, or the lease ended.
                    target.DeferredCloses.TryRemove(close, out _);
                });
            }
            finally { target.Closing.Release(); }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        {
            throw new RemoteException("Timeout");
        }
    }

    private RemoteReply RetainHandle(Target target, string? identity, string path, RemoteReply reply)
    {
        var local = Guid.NewGuid();
        lock (routeGate)
        {
            if (Volatile.Read(ref target.Removed) != 0 || Volatile.Read(ref disposed) != 0 ||
                target.Identity != identity)
                throw new RemoteException("InvalidHandle");
            if (!handles.TryAdd(local, new(target, reply.Response.Handle, reply.Generation, NormalizePath(path)[0], identity)))
                throw new IOException("Cannot retain file handle.");
        }
        return new(reply.Response with { Handle = local }, reply.Generation);
    }

    private async Task<RemoteReply> Forward(Target target, RpcRequest request, long? generation, string? routeIdentity, CancellationToken token)
    {
        if (Volatile.Read(ref target.Removed) != 0 || target.Identity != routeIdentity)
            throw new RemoteException("InvalidHandle");
        try
        {
            // The socket may reconnect to a different identity while this request is queued.
            var result = target.Connection is RemoteConnection remote
                ? await remote.CallForIdentityAsync(request, generation, routeIdentity, token)
                : await target.Connection.CallAsync(request, generation, token);
            if (Volatile.Read(ref target.Removed) != 0 || target.Identity != routeIdentity)
                throw new RemoteException("InvalidHandle");
            // Existing IO can complete after another request detects a disconnect.
            // Only a fresh successful probe may restore an offline root folder.
            return result;
        }
        catch (RemoteException ex) when (ex.Code is "Disconnected" or "DeviceBlocked" or "DeviceRejected" or "PendingApproval" or "InviteRequired" or "InvalidInvite" or "InviteUnsupported" or "HybridUnavailable" or "ServerLinkRequired")
        {
            MarkUnavailable(target, ex.Code);
            throw;
        }
        catch (CryptographicException ex)
        {
            var error = ex is ServerIdentityMismatchException ? "ServerIdentityChanged" : "AuthenticationFailed";
            MarkUnavailable(target, error);
            throw new RemoteException(error);
        }
        finally { RefreshRoutes(); }
    }

    private RpcResponse Namespace(RpcRequest request, Target? target)
    {
        var entry = DirectoryEntry(target?.Name ?? "");
        switch (request.Operation)
        {
            case "Ping":
                return new();
            case "Stat":
                return new()
                {
                    Entry = entry,
                    Existed = true
                };
            case "Security":
                return new()
                {
                    Permissions = NamespacePermissions
                };
            case "Open":
                if (!Enum.IsDefined(request.Mode))
                    throw new RemoteException("InvalidParameter");
                if (request.Mode == FileMode.CreateNew)
                    throw new RemoteException("Exists");
                const uint writable = AccessMask.GenericWrite | AccessMask.GenericAll | AccessMask.WriteData | AccessMask.AppendData |
                    AccessMask.WriteEa | AccessMask.WriteAttributes | AccessMask.Delete | AccessMask.DeleteChild | AccessMask.WriteDac | AccessMask.WriteOwner;
                // SetVolumeLabelW opens the volume root with FILE_WRITE_DATA | SYNCHRONIZE.
                // Windows may include FILE_READ_ATTRIBUTES on an ordinary root handle.
                // The driver handles the label; data writes to the namespace still fail.
                const uint labelOpen = AccessMask.WriteData | 0x100000;
                bool opensVolumeLabel = target is null && request.Mode == FileMode.Open &&
                    (request.Access & ~AccessMask.ReadAttributes) == labelOpen;
                if (request.DeleteOnClose || request.Mode is not (FileMode.Open or FileMode.OpenOrCreate) ||
                    ((request.Access & writable) != 0 && !opensVolumeLabel))
                    throw new RemoteException("AccessDenied");
                return new()
                {
                    Entry = entry,
                    Existed = true
                };
            case "List":
                if (request.Offset is < 0 or > int.MaxValue || request.Count is < 0 or > 256)
                    throw new RemoteException("InvalidParameter");
                var count = request.Count == 0 ? 256 : request.Count;
                var visible = CurrentRoutes.Entries;
                var entries = visible.Skip((int)request.Offset).Take(count).Select(server => DirectoryEntry(server.Name)).ToList();
                return new()
                {
                    Entries = entries,
                    Length = request.Offset + entries.Count,
                    More = request.Offset + entries.Count < visible.Length
                };
            case "Space":
                var selected = target is null ? CurrentRoutes.Entries.Select(entry => entry.Server) : new[] { target };
                long free = 0, total = 0;
                foreach (var server in selected.Where(server => Volatile.Read(ref server.Status).Connected))
                {
                    free = AddSaturated(free, Interlocked.Read(ref server.FreeBytes));
                    total = AddSaturated(total, Interlocked.Read(ref server.TotalBytes));
                }
                return new()
                {
                    FreeBytes = Math.Min(free, total),
                    TotalBytes = total
                };
            case "Cleanup" or "Close":
                if (request.DeleteOnClose)
                    throw new RemoteException("AccessDenied");
                return new();
            case "Read" or "Write":
                throw new RemoteException("IsDirectory");
            default:
                throw new RemoteException("AccessDenied");
        }
    }

    private static long AddSaturated(long left, long right) => right > long.MaxValue - left ? long.MaxValue : left + right;
    private static RemoteEntry DirectoryEntry(string name) => new(name, FileAttributes.Directory,
        0, NamespaceTime, NamespaceTime, NamespaceTime, NamespacePermissions);

    private (Target? Server, string Path, string? Identity) Parse(string path)
    {
        var parts = NormalizePath(path);
        if (parts.Length == 0)
            return (null, "/", null);
        var snapshot = CurrentRoutes;
        if (snapshot.Conflicts.Contains(parts[0]))
            throw new RemoteException("ServerIdentityConflict");
        if (!snapshot.Names.TryGetValue(parts[0], out var route))
            throw new RemoteException("NotFound");
        return (route.Server, parts.Length == 1 ? "/" : "/" + string.Join('/', parts.Skip(1)), route.Identity);
    }

    private static string[] NormalizePath(string path)
    {
        if (path is null || path.Length > 4096)
            throw new RemoteException("InvalidParameter");
        path = path.Replace('\\', '/');
        if (path.StartsWith("//", StringComparison.Ordinal))
            throw new RemoteException("InvalidParameter");
        path = path.Trim('/');
        if (path.Length == 0)
            return [];
        var parts = path.Split('/');
        foreach (var part in parts)
        {
            // Child filenames may legitimately begin with spaces; only configured aliases are trimmed names.
            if (part.Length is 0 or > 255 || part is "." or ".." || part.EndsWith('.') || part.EndsWith(' ') ||
                part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                Regex.IsMatch(part, @"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                throw new RemoteException("InvalidParameter");
        }
        return parts;
    }

    public void Dispose()
    {
        Target[] closing;
        lock (routeGate)
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;
            closing = Volatile.Read(ref targets);
            foreach (var target in closing)
                Volatile.Write(ref target.Removed, 1);
            Volatile.Write(ref targets, []);
            Volatile.Write(ref routes, new(new(StringComparer.OrdinalIgnoreCase), new(StringComparer.OrdinalIgnoreCase), []));
        }
        lifetime.Cancel();
        handles.Clear();
        foreach (var target in closing)
            (target.Connection as IDisposable)?.Dispose();
    }
}
