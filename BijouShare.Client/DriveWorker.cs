using DokanNet;
using DokanNet.Logging;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed class DriveWorker(ClientSettings settings, MultiServerConnection connection, DriveOperations operations,
    ClientDriveState driveState, ILogger<DriveWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var attemptedMount = settings.MountPoint;
            try
            {
                await MountAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                if (driveState.Error != exception.Message)
                    logger.LogError("The shared drive could not be mounted: {Reason}. Correct its setting in the client management page; mounting will retry.", exception.Message);
                driveState.Error = exception.Message;
                for (var attempt = 0; attempt < 20 && settings.MountPoint == attemptedMount; attempt++)
                    await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            }
        }
    }
    private async Task MountAsync(CancellationToken stoppingToken)
    {
        while (!settings.SetupComplete)
            await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
        stoppingToken.ThrowIfCancellationRequested();
        var mountPoint = settings.MountPoint;
        if (mountPoint.Length != 3 || !char.IsAsciiLetter(mountPoint[0]) || mountPoint[1..] != ":\\")
            throw new ArgumentException("MountPoint must be an unused drive letter, such as N:\\.");
        if (Directory.GetLogicalDrives().Any(drive => drive.Equals(mountPoint, StringComparison.OrdinalIgnoreCase)))
            throw new IOException($"Drive {mountPoint} is already in use. Choose an unused drive letter.");
        using var dokan = new Dokan(new NullLogger());
        using var instance = new DokanInstanceBuilder(dokan).ConfigureOptions(o =>
        {
            o.MountPoint = mountPoint;
            // Without CurrentSession, a service's drive is visible to interactive sessions on this machine.
            o.Options = DokanOptions.FixedDrive | DokanOptions.UserModeLock;
            o.TimeOut = TimeSpan.FromSeconds(60);
        }).Build(operations);
        driveState.Error = null;
        driveState.MountedPoint = mountPoint;
        using var heartbeatCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var heartbeat = HeartbeatAsync(heartbeatCancellation.Token);
        var notifications = NotifyNamespaceAsync(instance, mountPoint, heartbeatCancellation.Token);
        using var unmount = stoppingToken.Register(() =>
        {
            connection.Dispose(); // Cancel outstanding network I/O before waiting for the driver to unmount.
            dokan.RemoveMountPoint(mountPoint);
        });
        try
        {
            await instance.WaitForFileSystemClosedAsync(uint.MaxValue);
        }
        finally
        {
            driveState.MountedPoint = null;
            await heartbeatCancellation.CancelAsync();
            await heartbeat;
            await notifications;
        }
        if (!stoppingToken.IsCancellationRequested)
            throw new IOException("The virtual drive was unexpectedly unmounted.");
    }
    private async Task NotifyNamespaceAsync(DokanInstance instance, string mountPoint, CancellationToken token)
    {
        var previous = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!token.IsCancellationRequested)
        {
            var current = connection.MountedServerFolders.ToHashSet(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var removed in previous.Except(current))
                    instance.NotifyDelete(Path.Combine(mountPoint, removed), true);
                foreach (var added in current.Except(previous))
                    instance.NotifyCreate(Path.Combine(mountPoint, added), true);
            }
            catch (ObjectDisposedException) when (token.IsCancellationRequested) { break; }
            previous = current;
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
        }
    }
    private async Task HeartbeatAsync(CancellationToken token)
    {
        var previous = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (!token.IsCancellationRequested)
        {
            try
            {
                LogStatuses(await connection.RefreshAsync(token), previous);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) when (token.IsCancellationRequested) { break; }
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), token);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    private void LogStatuses(IReadOnlyList<ServerConnectionStatus> statuses, Dictionary<string, string> previous)
    {
        foreach (var status in statuses)
        {
            var state = status.Connected ? "Connected" : status.Error ?? "Waiting";
            if (previous.GetValueOrDefault(status.Name) == state)
                continue;
            previous[status.Name] = state;
            var message = state switch
            {
                "Connected" => "Connected",
                "PendingApproval" => "Awaiting administrator approval",
                "InvalidInvite" => "The invitation is invalid, expired, revoked, or has no uses remaining; obtain a new invitation",
                "InviteUnsupported" => "This server does not support invitation enrollment; upgrade it or request manual approval",
                "DeviceRejected" or "DeviceBlocked" => "Blocked until an administrator approves or enables this device",
                "ServerIdentityChanged" => "Server identity changed; verify the server before resetting its pinned key",
                "ServerIdentityConflict" => "Server folder ID collision; access is blocked to keep server identities separate",
                "ServerUpgradeRequired" => "Upgrade this server to provide an authenticated server name and ID",
                "AuthenticationFailed" => "Server authentication failed",
                "HybridUnavailable" => "Native Windows CNG ML-KEM support is required; update Windows before connecting",
                "ConfigurationError" => "Cannot access or persist this server's client configuration",
                _ => "Waiting for server connection"
            };
            logger.LogInformation("Server {Server}: {State}", status.Name, message);
        }
    }
}
