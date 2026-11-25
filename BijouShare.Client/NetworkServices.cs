using System.Net.Sockets;
using System.Security.Cryptography;
using BijouShare.Shared;

namespace BijouShare.Client;

internal sealed class NetworkServices(ClientSettings settings, DriveConnections connections, ILoggerFactory loggers,
    Func<int, NetworkServiceProtocol, IDisposable>? acquireGuard = null) : BackgroundService
{
    private sealed record Catalog(ServerEndpoint Endpoint, string Name, NetworkServiceDescriptor[] Services, string? Error, bool Confirmed);
    internal sealed record ServiceRow(string ServerId, string ServerName, Guid ShareId, string Name, string Protocol,
        bool Send, bool Receive, bool Enabled, int? LocalPort, int SuggestedPort, bool Listening, string? Error);
    private readonly object gate = new();
    private readonly Dictionary<string, Catalog> catalogs = [];
    private readonly Dictionary<(string, Guid), NetworkServiceListener> listeners = [];
    private readonly HashSet<Task> draining = [];
    private readonly Dictionary<(string, Guid), string> errors = [];
    // A local UDP source or TCP connection consumes one slot before it can initiate a handshake.
    private readonly SemaphoreSlim peerSlots = new(64, 64);
    private readonly SemaphoreSlim wake = new(0, 1);
    private readonly Dictionary<ServerEndpoint, RemoteConnection> standalone = [];
    private long watchUntil;
    private bool stopping;

    internal object Snapshot()
    {
        var now = Environment.TickCount64;
        if (Interlocked.Exchange(ref watchUntil, now + 20_000) < now)
        {
            try { wake.Release(); }
            catch (SemaphoreFullException) { }
        }
        lock (gate)
        {
            var rows = new List<ServiceRow>();
            var saved = settings.NetworkListenerSnapshot().ToDictionary(s => (s.ServerId, s.ShareId));
            foreach (var (serverId, catalog) in catalogs)
                foreach (var service in catalog.Services)
                {
                    var key = (serverId, service.Id);
                    saved.Remove(key, out var preference);
                    if (catalog.Error != null && preference == null) continue;
                    rows.Add(Row(serverId, catalog.Name, service, preference, catalog.Error));
                }
            foreach (var (key, preference) in saved)
            {
                catalogs.TryGetValue(key.ServerId, out var catalog);
                rows.Add(Row(key.ServerId, catalog?.Name ?? preference.ServerName,
                    new(preference.ShareId, preference.Name, preference.Protocol, preference.SuggestedPort, NetworkServiceAccess.None),
                    preference, catalog?.Error ?? "Waiting for this service to become available."));
            }
            return new
            {
                services = rows.OrderBy(s => s.ServerName, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ThenBy(s => s.ShareId).ToArray(),
                servers = settings.ServerSnapshot().DistinctBy(s => s.TrustedServerId).Select(s =>
                {
                    catalogs.TryGetValue(s.TrustedServerId!, out var catalog);
                    return new { serverId = s.TrustedServerId, serverName = catalog?.Name ?? s.Name,
                        error = catalog == null ? "Checking available services…" : catalog.Error };
                }).ToArray()
            };
        }
    }

    private ServiceRow Row(string serverId, string serverName, NetworkServiceDescriptor service, NetworkListenerSetting? saved, string? error)
    {
        var key = (serverId, service.Id);
        return new(serverId, serverName, service.Id, service.Name, service.Protocol switch
        {
            NetworkServiceProtocol.Tcp => "TCP", NetworkServiceProtocol.Udp => "UDP", _ => "Both"
        }, service.Access.HasFlag(NetworkServiceAccess.Send), service.Access.HasFlag(NetworkServiceAccess.Receive),
            saved != null, saved?.LocalPort, service.Port, listeners.ContainsKey(key), errors.GetValueOrDefault(key) ?? error);
    }

    internal Task SetEnabledAsync(string serverId, Guid shareId, bool enable, int? port)
    {
        ServerIdentityNaming.ValidateId(serverId);
        if (shareId == Guid.Empty) throw new ArgumentException("Select a network service.");
        lock (gate)
        {
            if (stopping) throw new ArgumentException("The client is shutting down.");
            var key = (serverId, shareId);
            if (!enable)
            {
                settings.ChangeNetworkListener(serverId, shareId, null);
                return StopListener(key);
            }
            if (port is null or < 1 or > 65535) throw new ArgumentException("Enter a local port from 1 to 65535.");
            var saved = settings.NetworkListenerSnapshot();
            var previous = saved.FirstOrDefault(s => s.ServerId == serverId && s.ShareId == shareId);
            if (previous != null)
            {
                if (previous.LocalPort != port) throw new ArgumentException("Disable this service before changing its local port.");
                return Task.CompletedTask;
            }
            if (!catalogs.TryGetValue(serverId, out var catalog) || catalog.Error != null ||
                catalog.Services.FirstOrDefault(s => s.Id == shareId) is not { } service)
                throw new ArgumentException("This network service is unavailable. Check the connection and its group permissions.");
            var preference = new NetworkListenerSetting(serverId, shareId, catalog.Name, service.Name, service.Protocol, service.Port, port.Value);
            if (saved.Length >= ClientSettings.MaximumNetworkListeners)
                throw new ArgumentException($"Disable a listener before enabling more than {ClientSettings.MaximumNetworkListeners} network services.");
            if (saved.Any(other => other.LocalPort == port && (other.Protocol & service.Protocol) != 0))
                throw new ArgumentException($"Local port {port} is already assigned to another enabled network service.");
            var listener = Bind(catalog, service, port.Value);
            try { settings.ChangeNetworkListener(serverId, shareId, preference); }
            catch { listener.Stop(); throw; }
            listeners.Add(key, listener);
            listener.Start();
            errors.Remove(key);
            return Task.CompletedTask;
        }
    }

    private NetworkServiceListener Bind(Catalog catalog, NetworkServiceDescriptor service, int port)
    {
        var view = settings.ForServer(catalog.Endpoint);
        return new(catalog.Endpoint, service, port, view, peerSlots, loggers.CreateLogger<NetworkServiceListener>(), acquireGuard);
    }

    private Task StopListener((string, Guid) key)
    {
        errors.Remove(key);
        if (!listeners.Remove(key, out var listener)) return Task.CompletedTask;
        listener.Stop();
        var completion = listener.Completion;
        draining.Add(completion);
        _ = completion.ContinueWith(task => { lock (gate) draining.Remove(task); }, CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return completion;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var refreshes = new Dictionary<string, Task>();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (settings.SetupComplete)
                {
                    var watched = Volatile.Read(ref watchUntil) >= Environment.TickCount64;
                    var enabledServers = settings.NetworkListenerSnapshot().Select(p => p.ServerId).ToHashSet();
                    var endpoints = settings.ServerSnapshot().Where(s => watched || enabledServers.Contains(s.TrustedServerId!)).GroupBy(s => s.TrustedServerId!)
                        .Select(g => g.OrderByDescending(s => connections.StatusFor(s).Connected).First()).ToArray();
                    var ids = endpoints.Select(e => e.TrustedServerId!).ToHashSet();
                    lock (gate)
                        foreach (var removed in catalogs.Keys.Where(id => !ids.Contains(id)).ToArray())
                        {
                            catalogs.Remove(removed);
                            foreach (var key in listeners.Keys.Where(k => k.Item1 == removed).ToArray()) _ = StopListener(key);
                        }
                    foreach (var removed in standalone.Keys.Except(endpoints).ToArray())
                    {
                        standalone[removed].Dispose();
                        standalone.Remove(removed);
                    }
                    foreach (var completed in refreshes.Where(p => p.Value.IsCompleted).ToArray())
                    {
                        await completed.Value;
                        refreshes.Remove(completed.Key);
                    }
                    foreach (var endpoint in endpoints)
                    {
                        if (refreshes.ContainsKey(endpoint.TrustedServerId!)) continue;
                        lock (gate)
                            if (!catalogs.ContainsKey(endpoint.TrustedServerId!) && enabledServers.Contains(endpoint.TrustedServerId!))
                                ApplyCatalog(endpoint, [], "Local port reserved. Waiting for the server to confirm access.");
                        var fileConnection = connections.ConnectionFor(endpoint);
                        if (fileConnection != null && standalone.Remove(endpoint, out var formerlyStandalone)) formerlyStandalone.Dispose();
                        if (fileConnection == null && !standalone.ContainsKey(endpoint))
                        {
                            try { standalone[endpoint] = new(settings.ForServer(endpoint), loggers.CreateLogger<RemoteConnection>()); }
                            catch (ArgumentException) when (!settings.ServerSnapshot().Contains(endpoint)) { continue; }
                        }
                        refreshes.Add(endpoint.TrustedServerId!, RefreshAsync(endpoint, fileConnection ?? standalone[endpoint], stoppingToken));
                    }
                }
                await wake.WaitAsync(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            Task[] closing;
            lock (gate)
            {
                stopping = true;
                foreach (var key in listeners.Keys.ToArray()) _ = StopListener(key);
                closing = draining.ToArray();
            }
            await Task.WhenAll(closing);
            foreach (var connection in standalone.Values) connection.Dispose();
            await Task.WhenAll(refreshes.Values);
        }
    }

    private async Task RefreshAsync(ServerEndpoint endpoint, IRemoteConnection connection, CancellationToken token)
    {
        NetworkServiceDescriptor[] services = [];
        string? error = null;
        bool transient = false;
        try
        {
            var reply = await connection.CallAsync(new() { Operation = "ListNetworkServices" }, token: token);
            services = reply.Response.NetworkServices ?? throw new RemoteException("Unsupported");
            if (services.Any(s => s == null || s.Id == Guid.Empty || s.Port is < 1 or > 65535 ||
                string.IsNullOrWhiteSpace(s.Name) || s.Name.Length > 100 || s.Name.Any(char.IsControl) ||
                !Enum.IsDefined(s.Protocol) || s.Access == NetworkServiceAccess.None || !Enum.IsDefined(s.Access)) ||
                services.DistinctBy(s => s.Id).Count() != services.Length)
                throw new InvalidDataException("Invalid network service catalog.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or CryptographicException or InvalidDataException or
            OperationCanceledException or UnauthorizedAccessException or ObjectDisposedException or PlatformNotSupportedException)
        {
            if (token.IsCancellationRequested) return;
            services = [];
            transient = ex is RemoteException remote ? remote.Code is "Disconnected" or "Timeout" :
                ex is SocketException or OperationCanceledException or ObjectDisposedException || ex is IOException && ex is not InvalidDataException;
            error = ex is RemoteException { Code: "Unsupported" } ? "This server version does not support network services."
                : transient ? "Waiting for the server's service list. Retrying automatically."
                : "Network services unavailable. Check the server identity, enrollment and permissions.";
        }
        ApplyCatalog(endpoint, services, error, transient);
    }

    internal void ApplyCatalog(ServerEndpoint endpoint, NetworkServiceDescriptor[] services, string? error, bool transient = true)
    {
        var id = endpoint.TrustedServerId!;
        lock (gate)
        {
            var configured = settings.ServerSnapshot();
            if (stopping || !configured.Contains(endpoint)) return;
            catalogs.TryGetValue(id, out var previous);
            // A failed poll says nothing about independent authenticated relay streams. Keep the previous grant
            // until an authoritative catalog changes it. After startup reserve the port with forwarding closed.
            bool unavailable = error != null && transient;
            if (unavailable)
            {
                services = previous?.Services ?? [];
                if (previous != null && configured.Contains(previous.Endpoint)) endpoint = previous.Endpoint;
            }
            var catalog = new Catalog(endpoint, endpoint.PresentedServerName ?? endpoint.Name, services, error,
                !unavailable || previous?.Confirmed == true);
            catalogs[id] = catalog;
            var saved = settings.NetworkListenerSnapshot().Where(s => s.ServerId == id).ToArray();
            foreach (var preference in saved)
            {
                var key = (id, preference.ShareId);
                var service = services.FirstOrDefault(s => s.Id == preference.ShareId);
                if (service == null && !catalog.Confirmed)
                    service = new(preference.ShareId, preference.Name, preference.Protocol, preference.SuggestedPort, NetworkServiceAccess.None);
                if (listeners.TryGetValue(key, out var current) && !current.TryUpdate(endpoint, service)) _ = StopListener(key);
                if (service == null || listeners.ContainsKey(key)) continue;
                try
                {
                    var listener = Bind(catalog, service, preference.LocalPort);
                    listeners.Add(key, listener);
                    listener.Start();
                    errors.Remove(key);
                }
                catch (ArgumentException ex) { errors[key] = ex.Message; }
            }
        }
    }
}
