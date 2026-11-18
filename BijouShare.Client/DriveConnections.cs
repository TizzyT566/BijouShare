namespace BijouShare.Client;

/// <summary>Each mounted drive owns its namespace, sessions and open file handles.</summary>
public sealed class DriveConnections : IDisposable
{
    private readonly ClientSettings settings;
    private readonly ILoggerFactory loggers;
    private readonly object gate = new();
    private readonly Dictionary<string, MultiServerConnection> routers = new(StringComparer.OrdinalIgnoreCase);
    private bool disposed;

    public DriveConnections(ClientSettings settings, ILoggerFactory loggers)
    {
        this.settings = settings;
        this.loggers = loggers;
        Synchronize();
    }

    public MultiServerConnection ForDrive(string letter)
    {
        lock (gate)
            return routers.TryGetValue(letter, out var router) ? router : throw new ArgumentException("Unknown drive.");
    }

    internal KeyValuePair<string, MultiServerConnection>[] Snapshot()
    {
        lock (gate)
            return routers.ToArray();
    }

    public void Synchronize(bool reconnectAll = false, ServerEndpoint? reconnect = null)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var letters = settings.DriveSnapshot();
            foreach (var removed in routers.Keys.Except(letters).ToArray())
            {
                routers[removed].Dispose();
                routers.Remove(removed);
            }
            foreach (var letter in letters)
            {
                if (!routers.TryGetValue(letter, out var router))
                    routers.Add(letter, new MultiServerConnection(settings, loggers, letter));
                else if (settings.SetupComplete)
                    router.Synchronize(settings, loggers, reconnectAll, reconnect);
            }
        }
    }

    public ServerConnectionStatus StatusFor(ServerEndpoint endpoint)
    {
        lock (gate)
            return routers.TryGetValue(endpoint.MountPoint ?? settings.MountPoint, out var router)
                ? router.StatusFor(endpoint) : new(endpoint.Name, false, "Waiting");
    }

    public void RequestRefresh()
    {
        lock (gate)
            foreach (var router in routers.Values)
                router.RequestRefresh();
    }

    public async Task<IReadOnlyList<ServerConnectionStatus>> RefreshAsync(CancellationToken token)
    {
        Task<IReadOnlyList<ServerConnectionStatus>>[] pending;
        lock (gate)
            pending = routers.Values.Select(router => router.RefreshAsync(token)).ToArray();
        return (await Task.WhenAll(pending)).SelectMany(statuses => statuses).ToArray();
    }

    public void Dispose()
    {
        lock (gate)
        {
            disposed = true;
            foreach (var router in routers.Values)
                router.Dispose();
            routers.Clear();
        }
    }
}
