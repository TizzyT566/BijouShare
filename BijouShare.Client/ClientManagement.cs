using BijouShare.Shared;

namespace BijouShare.Client;

public sealed class ClientDriveState
{
    public string? MountedPoint
    {
        get; set;
    }
    public string? Error
    {
        get; set;
    }
}

public sealed class ClientManagement(ClientSettings settings, MultiServerConnection connections,
    ILoggerFactory loggerFactory, ClientDriveState drive)
{
    private readonly SemaphoreSlim changes = new(1, 1);

    public object Snapshot() => new
    {
        settings.DeviceId,
        settings.DeviceName,
        settings.SetupComplete,
        settings.MountPoint,
        settings.ManagementPort,
        cryptoSuite = Wire.CryptoSuite,
        cryptoProvider = HybridKem.ProviderName,
        cryptoSupported = HybridKem.IsSupported,
        mountedPoint = drive.MountedPoint,
        driveError = drive.Error,
        restartRequired = drive.MountedPoint is { } mounted && mounted != settings.MountPoint,
        availableDriveLetters = AvailableDriveLetters(),
        servers = settings.ServerSnapshot().Select(endpoint =>
        {
            var status = connections.StatusFor(endpoint);
            return new
            {
                endpoint.Host,
                endpoint.Port,
                endpoint.ServerName,
                endpoint.ServerId,
                folderName = endpoint.FolderName,
                fingerprint = endpoint.ServerKeyFingerprint,
                status.Connected,
                status.Error
            };
        }).ToArray()
    };

    public static string[] AvailableDriveLetters()
    {
        var occupied = Directory.GetLogicalDrives();
        return Enumerable.Range('A', 'Z' - 'A' + 1).Select(letter => (char)letter + ":\\")
            .Where(letter => !occupied.Contains(letter, StringComparer.OrdinalIgnoreCase)).ToArray();
    }

    public async Task AddServerAsync(WadUri link, CancellationToken token = default)
    {
        await changes.WaitAsync(token);
        try
        {
            var endpoint = settings.AddServer(link.Host, link.Port, link.InviteCode);
            if (settings.SetupComplete)
                connections.Synchronize(settings, loggerFactory, reconnect: endpoint);
        }
        finally { changes.Release(); }
        if (settings.SetupComplete)
            await connections.RefreshAsync(token);
    }

    public async Task RemoveServerAsync(string host, int port, CancellationToken token = default)
    {
        await changes.WaitAsync(token);
        try
        {
            settings.RemoveServer(host, port);
            connections.Synchronize(settings, loggerFactory);
        }
        finally { changes.Release(); }
    }

    public async Task UpdateDeviceAsync(string name, string mountPoint, CancellationToken token = default)
    {
        await changes.WaitAsync(token);
        try
        {
            var mount = ClientSettings.NormalizeMountPoint(mountPoint);
            if (mount != drive.MountedPoint && !AvailableDriveLetters().Contains(mount, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("That drive letter is already in use. Choose an available letter.");
            var rename = settings.DeviceName != name;
            settings.UpdateDevice(name, mount);
            connections.Synchronize(settings, loggerFactory, reconnectAll: rename);
        }
        finally { changes.Release(); }
        await connections.RefreshAsync(token);
    }

    public Task<IReadOnlyList<ServerConnectionStatus>> RefreshAsync(CancellationToken token = default) => settings.SetupComplete
        ? connections.RefreshAsync(token)
        : Task.FromResult<IReadOnlyList<ServerConnectionStatus>>([]);
}
