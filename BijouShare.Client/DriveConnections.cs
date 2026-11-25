namespace BijouShare.Client;

/// <summary>Each mounted drive owns its namespace, sessions and open file handles.</summary>
public sealed class DriveConnections : IDisposable
{
    private readonly ClientSettings settings;
    private readonly ILoggerFactory loggers;
    private readonly ClientDriveState? driveState;
    private readonly object gate = new();
    private readonly Dictionary<string, MultiServerConnection> routers = new(StringComparer.OrdinalIgnoreCase);
    private bool disposed;
    internal event Action<string, string>? InviteRequired;

    public DriveConnections(ClientSettings settings, ILoggerFactory loggers, ClientDriveState? driveState = null)
    {
        this.settings = settings;
        this.loggers = loggers;
        this.driveState = driveState;
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
                {
                    router = new MultiServerConnection(settings, loggers, letter);
                    router.InviteRequired += address => InviteRequired?.Invoke(letter, address);
                    router.EnrollmentRevoked += () => driveState?.RevokeElevated(letter, settings, serverKick: true);
                    routers.Add(letter, router);
                }
                else if (settings.SetupComplete)
                    router.Synchronize(settings, loggers, reconnectAll, reconnect);
            }
        }
    }

    internal IRemoteConnection? ConnectionFor(ServerEndpoint endpoint)
    {
        lock (gate) return routers.GetValueOrDefault(endpoint.MountPoint ?? settings.MountPoint)?.ConnectionFor(endpoint);
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
