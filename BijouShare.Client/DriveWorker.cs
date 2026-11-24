using DokanNet;
using DokanNet.Logging;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed class DriveWorker(ClientSettings settings, DriveConnections connections, ILoggerFactory loggers,
    ClientDriveState driveState, ILogger<DriveWorker> logger, TransferMeter transfers) : BackgroundService
{
    private sealed record Mount(MultiServerConnection Router, CancellationTokenSource Stop, Task Worker);
    private readonly SemaphoreSlim mountGate = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // DokanInit and DokanShutdown apply to the whole process. Keep one Dokan instance alive
        // until the last mount has finished using the driver.
        while (!stoppingToken.IsCancellationRequested)
        {
            if (!settings.SetupComplete || settings.DriveSnapshot().Length == 0)
            {
                await Task.Delay(250, stoppingToken);
                continue;
            }
            try
            {
                using var dokan = new Dokan(new NullLogger());
                await ManageMountsAsync(dokan, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                foreach (var point in settings.DriveSnapshot())
                    driveState.SetError(point, ex.Message);
                logger.LogWarning("Cannot start Dokan: {Reason}", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private async Task ManageMountsAsync(Dokan dokan, CancellationToken token)
    {
        var active = new Dictionary<string, Mount>();
        try
        {
            while (!token.IsCancellationRequested)
            {
                var wanted = connections.Snapshot();
                if (wanted.Length == 0)
                    return;
                foreach (var (letter, mount) in active.ToArray())
                {
                    if (wanted.Any(item => item.Key == letter && item.Value == mount.Router) && !mount.Worker.IsCompleted)
                        continue;
                    await StopMountAsync(mount);
                    active.Remove(letter);
                }
                foreach (var (letter, router) in wanted)
                {
                    if (active.ContainsKey(letter))
                        continue;
                    var cancel = CancellationTokenSource.CreateLinkedTokenSource(token);
                    active.Add(letter, new Mount(router, cancel, Task.Run(() => RunMountAsync(dokan, letter, router, cancel.Token))));
                }
                await Task.Delay(250, token);
            }
        }
        finally
        {
            await Task.WhenAll(active.Values.Select(StopMountAsync));
        }
    }

    private static async Task StopMountAsync(Mount mount)
    {
        try
        {
            await mount.Stop.CancelAsync();
            await mount.Worker;
        }
        catch (OperationCanceledException) when (mount.Stop.IsCancellationRequested) { }
        finally { mount.Stop.Dispose(); }
    }

    private async Task RunMountAsync(Dokan dokan, string mountPoint, MultiServerConnection connection, CancellationToken token)
    {
        try
        {
            using var changes = new ConnectionChangeMonitor(logger);
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await MountAsync(dokan, mountPoint, connection, changes, token);
                }
                catch (Exception exception) when (!token.IsCancellationRequested)
                {
                    if (driveState.ErrorFor(mountPoint) != exception.Message)
                        logger.LogWarning("Drive {Mount} is unavailable: {Reason}", mountPoint, exception.Message);
                    driveState.SetError(mountPoint, exception.Message);
                    await Task.Delay(TimeSpan.FromSeconds(5), token);
                }
            }
        }
        finally { driveState.Remove(mountPoint); }
    }

    private async Task MountAsync(Dokan dokan, string mountPoint, MultiServerConnection connection,
        ConnectionChangeMonitor changes, CancellationToken stoppingToken)
    {
        if (Directory.GetLogicalDrives().Any(drive => drive.Equals(mountPoint, StringComparison.OrdinalIgnoreCase)))
            throw new IOException($"Drive {mountPoint} is already in use. Choose an unused drive letter.");
        var initialName = settings.GetDriveName(mountPoint);
        using var directory = CreatePrivateDirectory(mountPoint);
        var access = directory is null ? null : new MountLogonAccess();
        var operations = new DriveOperations(connection, loggers.CreateLogger<DriveOperations>(), initialName, transfers) { LogonAccess = access };
        var mounted = await CreateMountAsync(dokan, mountPoint, directory, operations, initialName, stoppingToken);
        using var instance = mounted.Instance;
        using var label = mounted.Label;
        using var letter = mounted.Letter;
        using var heartbeatCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var heartbeat = HeartbeatAsync(connection, changes, heartbeatCancellation.Token);
        var alias = new MountAliasPipe(mountPoint[0], label.RootHandle, access, settings);
        try
        {
            driveState.SetMounted(mountPoint, alias, directory is not null);
            if (letter is not null) MountedDriveLabel.NotifyDriveLetter(mountPoint, added: true);
            await MonitorMountAsync(connection, instance, mountPoint, directory?.MountPath ?? mountPoint, changes, label, alias, stoppingToken);
        }
        finally
        {
            // Cancel pending consent before the mount disappears from the management state.
            var closing = alias.DisposeAsync();
            driveState.Remove(mountPoint);
            await closing;
            if (instance.IsFileSystemRunning() && settings.DriveSnapshot().Contains(mountPoint))
                label.Synchronize(settings, logger);
            await heartbeatCancellation.CancelAsync();
            try { await heartbeat; }
            finally
            {
                if (letter is not null)
                {
                    letter.Dispose();
                    MountedDriveLabel.NotifyDriveLetter(mountPoint, added: false);
                }
                if (!stoppingToken.IsCancellationRequested)
                    connection.ResetAfterUnmount();
            }
        }
        if (!stoppingToken.IsCancellationRequested)
            throw new IOException("The virtual drive was unexpectedly unmounted.");
    }

    private PrivateMountDirectory? CreatePrivateDirectory(string mountPoint)
    {
        if (!ElevatedDriveAlias.HasLinkedElevation || settings.SettingsPath is not { } path) return null;
        try { return PrivateMountDirectory.Create(Path.GetDirectoryName(path)!, mountPoint[0]); }
        catch (NotSupportedException ex)
        {
            logger.LogInformation("Mounting {Mount} in the current logon without a Windows volume path: {Reason}", mountPoint, ex.Message);
            return null;
        }
    }

    private async Task<(DokanInstance Instance, MountedDriveLabel Label, IDisposable? Letter)> CreateMountAsync(
        Dokan dokan, string mountPoint, PrivateMountDirectory? directory, DriveOperations operations, string initialName, CancellationToken token)
    {
        await mountGate.WaitAsync(token);
        DokanInstance? instance = null;
        MountedDriveLabel? label = null;
        IDisposable? letter = null;
        var root = directory?.MountPath ?? mountPoint;
        try
        {
            instance = new DokanInstanceBuilder(dokan).ConfigureOptions(o =>
            {
                o.MountPoint = root;
                o.Options = DokanOptions.FixedDrive | DokanOptions.UserModeLock | DokanOptions.CurrentSession;
                if (directory is not null) o.Options |= DokanOptions.MountManager;
                UserDriveSecurity.Configure(o);
                o.TimeOut = TimeSpan.FromSeconds(60);
            }).Build(operations);

            // The drive letter may appear before Windows can open its volume. Finish
            // the first directory query before publishing the mount or starting another.
            for (var attempt = 0; ; attempt++)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    CheckRootReadable(root);
                    break;
                }
                catch (IOException) when (attempt < 20) { await Task.Delay(200, token); }
            }
            label = new MountedDriveLabel(mountPoint, initialName, operations, root);
            if (directory is not null)
            {
                letter = ElevatedDriveAlias.MountPrivateLetter(mountPoint, root, label.RootHandle);
                CheckRootReadable(mountPoint);
            }
            return (instance, label, letter);
        }
        catch
        {
            letter?.Dispose();
            label?.Dispose();
            instance?.Dispose();
            throw;
        }
        finally { mountGate.Release(); }
    }
    private static void CheckRootReadable(string mountPoint)
    {
        // The virtual root is local even when every server is offline. An empty result is healthy.
        using var entries = Directory.EnumerateFileSystemEntries(mountPoint).GetEnumerator();
        entries.MoveNext();
    }

    private async Task MonitorMountAsync(MultiServerConnection connection, DokanInstance instance, string mountPoint,
        string notificationRoot, ConnectionChangeMonitor changes, MountedDriveLabel label, MountAliasPipe alias, CancellationToken token)
    {
        var previous = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var absentSamples = 0;
        var nextRootCheck = Environment.TickCount64 + 15_000;
        var lastTick = Environment.TickCount64;
        var failedRootCheck = false;
        while (!token.IsCancellationRequested && instance.IsFileSystemRunning())
        {
            var tick = Environment.TickCount64;
            alias.RestoreIfDue();
            if (tick - lastTick > 45_000)
                changes.NoteResume(tick);
            lastTick = tick;
            // A power transition can remove the DOS mapping while the driver instance
            // remains alive. Give Windows time to republish the letter before remounting.
            if (Directory.GetLogicalDrives().Contains(mountPoint, StringComparer.OrdinalIgnoreCase))
                absentSamples = 0;
            else if (++absentSamples >= 3 && !changes.WaitingForVolume(tick))
                throw new IOException($"Windows removed the shared drive letter {mountPoint}.");

            // A drive letter and driver instance can both survive an unusable volume.
            if (absentSamples == 0 && Environment.TickCount64 >= nextRootCheck)
            {
                try
                {
                    CheckRootReadable(mountPoint);
                    failedRootCheck = false;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    if (failedRootCheck && !changes.WaitingForVolume(Environment.TickCount64))
                        throw new IOException($"Windows cannot open the mounted drive {mountPoint}. BijouShare will remount it.", ex);
                    failedRootCheck = true;
                }
                nextRootCheck = Environment.TickCount64 + (failedRootCheck ? 2_000 : 15_000);
            }
            if (absentSamples == 0)
                label.Synchronize(settings, logger);
            var current = connection.MountedServerFolders.ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var removed in previous.Except(current, previous.Comparer).ToArray())
                if (instance.NotifyDelete(Path.Combine(notificationRoot, removed), true))
                    previous.Remove(removed);
            foreach (var added in current.Except(previous, previous.Comparer))
                if (instance.NotifyCreate(Path.Combine(notificationRoot, added), true))
                    previous.Add(added);
            await Task.Delay(TimeSpan.FromSeconds(1), token);
        }
    }
    private async Task HeartbeatAsync(MultiServerConnection connection, ConnectionChangeMonitor changes, CancellationToken token)
    {
        var previous = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        long lastProbe = Environment.TickCount64 - 15_000, lastRetry = lastProbe;
        long eagerUntil = 0, lastResume = -5_000, lastChange = -2_000;
        var lastTick = Environment.TickCount64;
        while (!token.IsCancellationRequested)
        {
            var events = changes.TakeChanges();
            // A long gap also catches missed power notifications and Modern Standby.
            var tick = Environment.TickCount64;
            var resumed = (events.HasFlag(ConnectionChangeMonitor.Change.Resume) || tick - lastTick > 45_000) &&
                tick - lastResume >= 5_000;
            lastTick = tick;
            // Windows often reports availability and several address changes for one adapter transition.
            var changed = resumed || events.HasFlag(ConnectionChangeMonitor.Change.Network) && tick - lastChange >= 2_000;
            if (resumed)
                lastResume = tick;
            if (changed)
            {
                lastChange = tick;
                eagerUntil = tick + MultiServerConnection.WakeRecoveryMilliseconds;
            }
            var fullProbe = changed || tick - lastProbe >= 15_000;
            if (fullProbe || tick - lastRetry >= 2_000 && (tick < eagerUntil || connection.HasRecoveringFolders))
            {
                try
                {
                    var statuses = changed
                        ? await connection.RecoverAfterResumeAsync(token, resumed)
                        : await connection.RefreshAsync(token, retryOnly: !fullProbe);
                    LogStatuses(statuses, previous);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (ObjectDisposedException) when (token.IsCancellationRequested) { break; }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Connection check failed. The client will retry.");
                }
                lastRetry = Environment.TickCount64;
                if (fullProbe)
                    lastProbe = lastRetry;
            }
            try
            {
                await changes.WaitAsync(token);
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
                "ServerLinkRequired" => "Add a current connection link from this server",
                "HybridUnavailable" => "Update Windows to a version with native CNG support for ML-KEM-768",
                "ConfigurationError" => "The client or server could not access its saved configuration",
                _ => "Waiting for server connection"
            };
            logger.LogInformation("Server {Server}: {State}", status.Name, message);
        }
    }
}
