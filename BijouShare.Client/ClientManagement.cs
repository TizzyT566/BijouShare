using System.Collections.Concurrent;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed class ClientDriveState
{
    private sealed record Status(bool Mounted, string? Error, MountAliasPipe? Alias = null, bool ExplorerElevation = false);
    private readonly ConcurrentDictionary<string, Status> statuses = new(StringComparer.OrdinalIgnoreCase);

    public void SetMounted(string letter) => statuses[letter] = new(true, null);
    internal void SetMounted(string letter, MountAliasPipe alias, bool explorerElevation) =>
        statuses[letter] = new(true, null, alias, explorerElevation);
    public void SetError(string letter, string? error) => statuses[letter] = new(false, error);
    public void Remove(string letter) => statuses.TryRemove(letter, out _);
    public bool IsMounted(string letter) => statuses.TryGetValue(letter, out var status) && status.Mounted;
    public string? ErrorFor(string letter) => statuses.TryGetValue(letter, out var status) ? status.Error : null;
    internal bool SupportsExplorerElevation(string letter) => statuses.GetValueOrDefault(letter)?.ExplorerElevation == true;
    internal (string State, string? Error) ElevatedStatus(string letter) => statuses.GetValueOrDefault(letter)?.Alias?.Status ?? ("Disabled", null);
    internal void EnableElevated(string letter)
    {
        var alias = statuses.GetValueOrDefault(letter)?.Alias ?? throw new ArgumentException("Mount this drive before allowing elevated apps.");
        alias.Enable();
    }
    internal void RevokeElevated(string letter, ClientSettings settings, bool serverKick = false)
    {
        if (statuses.GetValueOrDefault(letter)?.Alias is { } alias) alias.Disable(serverKick);
        else MountAliasPipe.Forget(settings, letter);
    }
}

public sealed class ClientManagement(ClientSettings settings, DriveConnections connections, ClientDriveState drive)
{
    private readonly SemaphoreSlim changes = new(1, 1);

    public object Snapshot()
    {
        var drives = settings.DriveSnapshot();
        var primary = drives.FirstOrDefault();
        return new
        {
            settings.DeviceId,
            settings.DeviceName,
            settings.SetupComplete,
            mountPoint = primary,
            canOfferElevatedAccess = MountAliasPipe.CanOfferElevatedAccess,
            drives = drives.Select(mountPoint =>
            {
                var elevated = drive.ElevatedStatus(mountPoint);
                return new
                {
                    mountPoint,
                    name = settings.GetDriveName(mountPoint),
                    mounted = drive.IsMounted(mountPoint),
                    error = drive.ErrorFor(mountPoint),
                    elevatedAccess = elevated.State,
                    elevatedAccessSaved = settings.ElevatedGrant(mountPoint).HasValue,
                    explorerElevation = drive.SupportsExplorerElevation(mountPoint),
                    elevatedError = elevated.Error
                };
            }).ToArray(),
            cryptoSuite = Wire.CryptoSuite,
            cryptoProvider = HybridKem.ProviderName,
            cryptoSupported = HybridKem.IsSupported && System.Security.Cryptography.SHA3_256.IsSupported,
            availableDriveLetters = AvailableDriveLetters().Except(drives).ToArray(),
            servers = settings.ServerSnapshot().Select(endpoint =>
            {
                var status = connections.StatusFor(endpoint);
                return new
                {
                    mountPoint = endpoint.MountPoint ?? primary,
                    endpoint.Host,
                    endpoint.Port,
                    serverName = endpoint.PresentedServerName,
                    endpoint.TrustedServerId,
                    folderName = endpoint.FolderName,
                    status.Connected,
                    status.Error
                };
            }).ToArray()
        };
    }

    public static string[] AvailableDriveLetters()
    {
        var occupied = Directory.GetLogicalDrives();
        return Enumerable.Range('A', 'Z' - 'A' + 1).Select(letter => (char)letter + ":\\")
            .Where(letter => !occupied.Contains(letter, StringComparer.OrdinalIgnoreCase)).ToArray();
    }

    public Task AddServerAsync(WadUri link, CancellationToken token = default) => AddServerAsync(link, null, token);

    public async Task AddServerAsync(WadUri link, string? mountPoint, CancellationToken token = default)
    {
        await changes.WaitAsync(token);
        try
        {
            var endpoint = settings.AddServer(link.Host, link.Port, link.InviteCode, mountPoint, link.TrustedServerId);
            if (settings.SetupComplete)
            {
                var connected = connections.StatusFor(endpoint).Connected;
                connections.Synchronize(reconnect: connected ? null : endpoint);
                if (connected)
                    settings.ForServer(endpoint).ClearInviteCode(link.InviteCode);
                connections.RequestRefresh();
            }
        }
        finally { changes.Release(); }
    }

    public async Task RemoveServerAsync(string host, int port, string? mountPoint = null, CancellationToken token = default)
    {
        await changes.WaitAsync(token);
        try
        {
            settings.RemoveServer(host, port, mountPoint);
            if (settings.SetupComplete)
                connections.Synchronize();
        }
        finally { changes.Release(); }
    }

    private static void RequireFreeLetter(string letter)
    {
        if (!AvailableDriveLetters().Contains(letter, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("That drive letter is already in use. Choose an available letter.");
    }

    public async Task UpdateDeviceAsync(string name, CancellationToken token = default)
    {
        await changes.WaitAsync(token);
        try
        {
            var rename = settings.DeviceName != name;
            settings.UpdateDevice(name);
            connections.Synchronize(reconnectAll: rename);
            connections.RequestRefresh();
        }
        finally { changes.Release(); }
    }

    public enum DriveChange { Add, Rename, Remove }

    public async Task SetElevatedAccessAsync(string mountPoint, bool enabled, CancellationToken token)
    {
        await changes.WaitAsync(token);
        try
        {
            var mount = ClientSettings.NormalizeMountPoint(mountPoint);
            if (!settings.SetupComplete || !settings.DriveSnapshot().Contains(mount))
                throw new ArgumentException("Choose a configured drive.");
            if (enabled)
                drive.EnableElevated(mount);
            else
                drive.RevokeElevated(mount, settings);
        }
        finally { changes.Release(); }
    }

    public async Task ChangeDriveAsync(string mountPoint, DriveChange change, string? name, CancellationToken token)
    {
        await changes.WaitAsync(token);
        try
        {
            if (!settings.SetupComplete)
                throw new ArgumentException("Complete device setup first.");
            var mount = ClientSettings.NormalizeMountPoint(mountPoint);
            switch (change)
            {
                case DriveChange.Rename:
                    settings.RenameDrive(mount, name ?? "");
                    return;
                case DriveChange.Add:
                    RequireFreeLetter(mount);
                    settings.AddDrive(mount, name ?? "");
                    break;
                case DriveChange.Remove:
                    if (settings.ServerSnapshot(mount).Length == 0)
                        drive.RevokeElevated(mount, settings);
                    settings.RemoveDrive(mount);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(change));
            }
            connections.Synchronize();
            if (change == DriveChange.Add)
                connections.RequestRefresh();
        }
        finally { changes.Release(); }
    }

    public async Task RefreshAsync(CancellationToken token = default)
    {
        if (settings.SetupComplete)
            await connections.RefreshAsync(token);
    }
}
