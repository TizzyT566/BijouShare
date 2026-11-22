using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

// A live alias belongs to one mount. Windows keeps the separate approval used
// by the installed service to restore an alias after the next sign-in or remount.
internal sealed class MountAliasPipe(char letter, SafeFileHandle mountedRoot, MountLogonAccess? access = null,
    ClientSettings? settings = null) : IAsyncDisposable
{
    private readonly object gate = new();
    private static readonly SemaphoreSlim ElevationPrompt = new(1, 1);
    private Request? request;
    private string? error;
    private bool disposed;
    private long retryAt;
    private bool withdrawing;

    private sealed class Request(Guid grant, bool restoring)
    {
        public Guid Grant { get; } = grant;
        public bool Restoring { get; } = restoring;
        public readonly CancellationTokenSource Stop = new();
        public Task Worker = Task.CompletedTask;
        public bool Enabled;
    }

    internal (string State, string? Error) Status
    {
        get
        {
            lock (gate)
                return (request is null ? "Disabled" : request.Enabled && !request.Stop.IsCancellationRequested ? "Enabled" :
                    request.Restoring ? "Restoring" : "Pending", error);
        }
    }

    internal static string InstalledClient => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "BijouShare", "Client", "BijouShare.Client.exe");

    internal static bool IsInstalledClient => Environment.Is64BitProcess &&
        string.Equals(Environment.ProcessPath, InstalledClient, StringComparison.OrdinalIgnoreCase);

    internal static bool CanOfferElevatedAccess { get; } = IsInstalledClient && ElevatedDriveAlias.HasLinkedElevation;

    internal void Enable()
    {
        if (!CanOfferElevatedAccess)
            throw new ArgumentException("Open the installed BijouShare Client from the normal session of a Windows administrator account.");
        if (letter is < 'A' or > 'Z')
            throw new ArgumentException("Choose a drive letter from A through Z for elevated apps.");
        lock (gate)
        {
            if (disposed) throw new ArgumentException("This drive was unmounted.");
            if (request?.Stop.IsCancellationRequested == true)
                throw new ArgumentException("The previous drive request is closing. Try again in a moment.");
            if (request is not null) return;
            withdrawing = false;
            var saved = settings?.ElevatedGrant(letter + ":");
            if (saved is { } prior && !ElevatedDriveConsent.IsApproved(UserDriveSecurity.Owner, letter, prior))
            {
                settings!.ClearElevatedGrant(letter + ":", prior);
                saved = null;
            }
            Start(saved ?? Guid.NewGuid(), restoring: saved.HasValue);
        }
    }

    private void Start(Guid grant, bool restoring)
    {
        error = null;
        var next = new Request(grant, restoring);
        request = next;
        next.Worker = Task.Run(() => ServeAsync(next));
    }

    internal void RestoreIfDue()
    {
        lock (gate)
        {
            if (disposed || withdrawing || request is not null || Environment.TickCount64 < retryAt ||
                !CanOfferElevatedAccess || settings?.ElevatedGrant(letter + ":") is not { } saved) return;
            Start(saved, restoring: true);
        }
    }

    internal static void Forget(ClientSettings settings, string mountPoint)
    {
        if (settings.ElevatedGrant(mountPoint) is not { } grant) return;
        ElevatedDriveConsent.Revoke(UserDriveSecurity.Owner, mountPoint[0], grant);
        settings.ClearElevatedGrant(mountPoint, grant);
    }

    internal void Disable(bool serverKick = false)
    {
        lock (gate)
        {
            error = serverKick && (request is not null || settings?.ElevatedGrant(letter + ":") is not null)
                ? "A server on this drive revoked the device's enrollment. Elevated access was turned off." : null;
            withdrawing = true;
            access?.SetElevatedAllowed(false);
            request?.Stop.Cancel();
            if (settings is not null) Forget(settings, letter + ":");
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task stopped;
        lock (gate)
        {
            disposed = true;
            access?.SetElevatedAllowed(false);
            request?.Stop.Cancel();
            stopped = request?.Worker ?? Task.CompletedTask;
        }
        // DriveWorker disposes the bound root handle only after this handshake ends.
        await stopped;
    }

    private static string Name(int workerPid, char drive, Guid nonce) =>
        $"BijouShare.Client.Drive.{workerPid}.{drive}.{nonce:N}";

    private async Task ServeAsync(Request attempt)
    {
        string? failure = null;
        var token = attempt.Stop.Token;
        Process? helper = null;
        bool pin = false;
        Task? helperExit = null;
        try
        {
            if (attempt.Restoring)
            {
                if (!ElevatedDriveConsent.IsApproved(UserDriveSecurity.Owner, letter, attempt.Grant))
                {
                    settings?.ClearElevatedGrant(letter + ":", attempt.Grant);
                    throw new IOException("Windows no longer has this drive approval. Select Allow elevated apps to approve it again.");
                }
                using var restored = await ElevatedDriveRestoreService.RestoreAsync(letter, attempt.Grant, mountedRoot, token);
                lock (gate)
                {
                    token.ThrowIfCancellationRequested();
                    if (settings?.ElevatedGrant(letter + ":") != attempt.Grant)
                        throw new IOException("The saved drive approval has changed.");
                    access?.SetElevatedAllowed(true);
                    attempt.Enabled = true;
                }
                _ = await restored.ReadAsync(new byte[1], token);
                throw new IOException("The drive service disconnected. BijouShare will retry.");
            }
            using var pipe = ClientActivation.CreatePipe(Name(Environment.ProcessId, letter, attempt.Grant));
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
            startup.CancelAfter(TimeSpan.FromMinutes(2));
            helper = await StartHelperAsync(attempt.Grant, startup.Token);
            helperExit = helper.WaitForExitAsync();
            if (helperExit.IsCompleted)
            {
                await helperExit;
                throw new IOException("The elevated helper exited before it could connect the drive.");
            }
            startup.CancelAfter(TimeSpan.FromSeconds(15));
            mountedRoot.DangerousAddRef(ref pin);
            await HandoffAsync(pipe, helper, mountedRoot, letter, startup.Token, () =>
            {
                lock (gate)
                {
                    token.ThrowIfCancellationRequested();
                    settings?.SetElevatedGrant(letter + ":", attempt.Grant);
                }
            });
            mountedRoot.DangerousRelease();
            pin = false;
            lock (gate)
            {
                token.ThrowIfCancellationRequested();
                access?.SetElevatedAllowed(true);
                attempt.Enabled = true;
            }

            // The helper closes its side at logoff, on failure, or when it stops.
            // Cancellation closes our side during disable, unmount and shutdown.
            _ = await pipe.ReadAsync(new byte[1], token);
            failure = "The elevated drive connection closed. BijouShare will reconnect.";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (OperationCanceledException) { failure = attempt.Restoring ? "The drive service timed out. BijouShare will retry." :
            "The drive request timed out. Try again and approve the Windows prompt with the same account."; }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { failure = "Windows elevation was canceled."; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or System.Security.SecurityException or TimeoutException)
        {
            failure = ex is EndOfStreamException ? (attempt.Restoring ? "The service could not restore this drive. BijouShare will retry." :
                "The elevated helper closed before the drive was connected.") : ex.Message;
        }
        finally
        {
            if (helper is not null)
            {
                // Its pipe is now closed, but the helper may already have received
                // the handle number and been suspended before DuplicateHandle. The
                // number must not be recycled into a different file or mount.
                _ = ReleaseOnExitAsync(helper, helperExit, pin ? mountedRoot : null);
            }
            lock (gate)
            {
                access?.SetElevatedAllowed(false);
                if (!token.IsCancellationRequested) error = failure;
                retryAt = Environment.TickCount64 + 5_000;
                request = null;
                attempt.Stop.Dispose();
            }
        }
    }

    private static async Task ReleaseOnExitAsync(Process helper, Task? exited, SafeFileHandle? pin)
    {
        try
        {
            if (exited is not null) await exited;
            pin?.DangerousRelease();
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            // If Windows cannot confirm exit, fail closed and keep the handle
            // number reserved until the worker exits rather than risk reuse.
        }
        finally { helper.Dispose(); }
    }

    internal static Task AuthorizeMountAsync(NamedPipeServerStream pipe, Process helper, SafeFileHandle mountedRoot,
        char letter, CancellationToken token) => HandoffAsync(pipe, helper, mountedRoot, letter, token, null);

    private static async Task HandoffAsync(NamedPipeServerStream pipe, Process helper, SafeFileHandle mountedRoot,
        char letter, CancellationToken token, Action? remember)
    {
        await pipe.WaitForConnectionAsync(token);
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid) || clientPid != helper.Id || helper.HasExited)
            throw new IOException("The drive request did not come from the approved helper.");

        var payload = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(payload, mountedRoot.DangerousGetHandle().ToInt64());
        await pipe.WriteAsync(payload, token);
        var reply = new byte[1];
        await pipe.ReadExactlyAsync(reply, token);
        var result = (MountAliasReply)reply[0];
        if (result != MountAliasReply.Ready)
            throw new IOException(result switch
            {
                MountAliasReply.DifferentLogon => "Use the same signed-in Windows administrator account for the UAC prompt.",
                MountAliasReply.LetterInUse => $"Drive {letter}: is already in use in the elevated session.",
                _ => "Windows could not verify or connect this drive in the elevated session."
            });
        token.ThrowIfCancellationRequested();
        remember?.Invoke();
        await pipe.WriteAsync(reply, token);
    }

    private async Task<Process> StartHelperAsync(Guid nonce, CancellationToken token)
    {
        // ShellExecute can wait for interactive UAC consent. A pending prompt must
        // never hold up unmount, logoff or shutdown. Late consent has no live pipe.
        var start = new ProcessStartInfo(InstalledClient)
        {
            UseShellExecute = true, Verb = "runas", WorkingDirectory = Path.GetDirectoryName(InstalledClient)!,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        start.ArgumentList.Add("--elevated-drive");
        start.ArgumentList.Add($"{letter}:");
        start.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        start.ArgumentList.Add(nonce.ToString("N"));
        await ElevationPrompt.WaitAsync(token);
        var launch = Task.Run(() =>
        {
            try
            {
                token.ThrowIfCancellationRequested();
                return Process.Start(start) ?? throw new IOException("Windows could not start the elevated drive helper.");
            }
            finally { ElevationPrompt.Release(); }
        });
        try { return await launch.WaitAsync(token); }
        catch (OperationCanceledException)
        {
            _ = launch.ContinueWith(t =>
            {
                if (t.IsCompletedSuccessfully) t.Result.Dispose();
                else _ = t.Exception;
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }

    internal sealed record Session(NamedPipeClientStream Pipe, long RootHandle, SafeProcessHandle Worker) : IDisposable
    {
        public void Dispose()
        {
            Pipe.Dispose();
            Worker.Dispose();
        }
    }

    internal static async Task<Session> ConnectAsync(char letter, int workerPid, Guid nonce, CancellationToken token)
    {
        if (!IsInstalledClient || letter is < 'A' or > 'Z' || workerPid <= 0 || nonce == Guid.Empty)
            throw new UnauthorizedAccessException("Invalid installed-client drive request.");
        // Identification lets the worker identify this connection without allowing
        // the lower-integrity pipe server to impersonate the elevated caller.
        var pipe = new NamedPipeClientStream(".", Name(workerPid, letter, nonce), PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        SafeProcessHandle? worker = null;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await pipe.ConnectAsync(timeout.Token);
            // Keeping the process object alive prevents PID recycling between image
            // verification and the helper's subsequent DuplicateHandle request.
            worker = ClientActivation.OpenVerifiedServerProcess(pipe, out var serverPid);
            if (serverPid != workerPid)
                throw new UnauthorizedAccessException("The drive request belongs to a different client process.");
            var payload = new byte[sizeof(long)];
            await pipe.ReadExactlyAsync(payload, timeout.Token);
            return new Session(pipe, BinaryPrimitives.ReadInt64LittleEndian(payload), worker);
        }
        catch { worker?.Dispose(); pipe.Dispose(); throw; }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out int processId);
}
