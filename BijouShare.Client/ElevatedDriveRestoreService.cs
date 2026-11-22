using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

// Session zero restores only an approved drive letter. It accepts no commands,
// paths, logon IDs or user identities from the request body.
internal sealed class ElevatedDriveRestoreService(ILogger<ElevatedDriveRestoreService> logger) : BackgroundService
{
    private const int MaxConnections = 128;
    private const int RequestSize = 1 + 16 + sizeof(long);
    private const PipeAccessRights ClientRights = PipeAccessRights.ReadData | PipeAccessRights.WriteData |
        PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize;
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SemaphoreSlim[] Handoffs = Enumerable.Range(0, 26).Select(_ => new SemaphoreSlim(1, 1)).ToArray();
    private static string PipeName(int servicePid) => $"BijouShare.Client.Restore.{servicePid}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var current = Process.GetCurrentProcess();
        if (!identity.IsSystem || current.SessionId != 0 || !MountAliasPipe.IsInstalledClient)
            return;
        var clients = new HashSet<Task>();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                clients.RemoveWhere(task => task.IsCompleted);
                if (clients.Count >= MaxConnections - 1)
                {
                    await Task.WhenAny(clients).WaitAsync(stoppingToken);
                    continue;
                }
                NamedPipeServerStream? listener = null;
                try
                {
                    listener = CreatePipe();
                    await listener.WaitForConnectionAsync(stoppingToken);
                    var connected = listener;
                    clients.Add(Task.Run(() => ServeAsync(connected, stoppingToken)));
                    listener = null;
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    logger.LogDebug(error, "The drive restore endpoint is unavailable.");
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                }
                finally { listener?.Dispose(); }
            }
        }
        finally { await Task.WhenAll(clients); }
    }

    private static NamedPipeServerStream CreatePipe()
    {
        var acl = new PipeSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(SystemSid);
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        acl.AddAccessRule(new PipeAccessRule(SystemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            ClientRights, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(PipeName(Environment.ProcessId), PipeDirection.InOut, MaxConnections,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 512, 512, acl, HandleInheritability.None);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        using (pipe)
        using (var startup = CancellationTokenSource.CreateLinkedTokenSource(stop))
        {
            try
            {
                startup.CancelAfter(TimeSpan.FromSeconds(8));
                var message = new byte[RequestSize];
                await pipe.ReadExactlyAsync(message, startup.Token);
                var letter = (char)message[0];
                var grant = new Guid(message.AsSpan(1, 16));
                if (letter is < 'A' or > 'Z' || grant == Guid.Empty ||
                    !GetNamedPipeClientProcessId(pipe.SafePipeHandle, out int pid) || pid <= 0)
                    return;
                var handle = BinaryPrimitives.ReadInt64LittleEndian(message.AsSpan(17));
                if (handle <= 0 || handle > uint.MaxValue || (handle & 3) != 0) return;
                using var process = Process.GetProcessById(pid);
                using var processPin = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
                var image = new StringBuilder(32768);
                int length = image.Capacity;
                if (processPin.IsInvalid || !QueryFullProcessImageNameW(processPin, 0, image, ref length) ||
                    !string.Equals(image.ToString(), MountAliasPipe.InstalledClient, StringComparison.OrdinalIgnoreCase))
                    return;

                SecurityIdentifier? owner = null;
                long logon = 0;
                // RunAsClient identifies the token on the kernel pipe's last message.
                // Revert before touching machine state or opening the peer's root.
                pipe.RunAsClient(() =>
                {
                    using var peer = WindowsIdentity.GetCurrent(ifImpersonating: true);
                    if (peer is null || peer.IsSystem || peer.ImpersonationLevel != TokenImpersonationLevel.Identification)
                        return;
                    owner = peer.User;
                    logon = ElevatedDriveAlias.AuthenticationId(peer.AccessToken);
                });
                if (owner is null || !ElevatedDriveConsent.IsApproved(owner, letter, grant)) return;
                using var alias = ElevatedDriveAlias.RestoreRegistered(letter, pid, handle, grant, owner, logon);
                if (!ElevatedDriveConsent.IsApproved(owner, letter, grant)) return;
                await pipe.WriteAsync(new byte[] { (byte)MountAliasReply.Ready }, startup.Token);
                using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop);
                try
                {
                    var closed = pipe.ReadAsync(new byte[1], lifetime.Token).AsTask();
                    var exited = process.WaitForExitAsync(lifetime.Token);
                    var ended = Task.WhenAny(closed, exited);
                    while (!ended.IsCompleted && ElevatedDriveConsent.IsApproved(owner, letter, grant))
                        await Task.WhenAny(ended, Task.Delay(TimeSpan.FromSeconds(3), lifetime.Token));
                    if (ended.IsCompleted) await await ended;
                }
                finally { await lifetime.CancelAsync(); }
            }
            catch (ElevatedDriveAlias.DriveLetterInUseException)
            {
                try { await pipe.WriteAsync(new byte[] { (byte)MountAliasReply.LetterInUse }, startup.Token); }
                catch (Exception error) when (error is IOException or OperationCanceledException) { }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException or
                Win32Exception or OperationCanceledException or InvalidOperationException or ArgumentException)
            {
                logger.LogDebug(error, "The drive restore connection ended.");
            }
        }
    }

    internal static async Task<NamedPipeClientStream> RestoreAsync(char letter, Guid grant, SafeFileHandle root, CancellationToken token)
    {
        if (letter is < 'A' or > 'Z' || grant == Guid.Empty || !MountAliasPipe.IsInstalledClient)
            throw new UnauthorizedAccessException("Only the installed client can restore an approved drive.");
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
        startup.CancelAfter(TimeSpan.FromSeconds(10));
        var gate = Handoffs[letter - 'A'];
        await gate.WaitAsync(startup.Token);
        NamedPipeClientStream? pipe = null;
        bool handedOff = false;
        try
        {
            var pid = ServiceProcessId();
            pipe = new NamedPipeClientStream(".", PipeName(pid), ClientRights, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification, HandleInheritability.None);
            await pipe.ConnectAsync(startup.Token);
            // The kernel reports both the pipe's server PID and SECURITY_DESCRIPTOR owner.
            // An ordinary local process cannot assign SYSTEM as an object's owner.
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var connectedPid) || connectedPid != pid ||
                pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
                owner != SystemSid || ServiceProcessId() != pid)
                throw new UnauthorizedAccessException("Windows could not verify the BijouShare Client service.");
            startup.Token.ThrowIfCancellationRequested();
            var transfer = SendRootAsync(pipe, letter, grant, root, gate);
            handedOff = true;
            try { return await transfer.WaitAsync(startup.Token); }
            catch (OperationCanceledException)
            {
                _ = CloseLateReplyAsync(transfer);
                throw;
            }
        }
        finally
        {
            if (!handedOff) { pipe?.Dispose(); gate.Release(); }
        }
    }

    // Only a live authenticated service ever receives this handle number. After sending
    // starts, pin it through the reply or service-side EOF even if the caller cancels.
    // There can be at most one unfinished handoff per drive letter.
    private static async Task<NamedPipeClientStream> SendRootAsync(NamedPipeClientStream pipe, char letter, Guid grant,
        SafeFileHandle root, SemaphoreSlim gate)
    {
        bool pinned = false;
        try
        {
            root.DangerousAddRef(ref pinned);
            var message = new byte[RequestSize];
            message[0] = (byte)letter;
            grant.TryWriteBytes(message.AsSpan(1, 16));
            BinaryPrimitives.WriteInt64LittleEndian(message.AsSpan(17), root.DangerousGetHandle().ToInt64());
            await pipe.WriteAsync(message);
            var reply = new byte[1];
            await pipe.ReadExactlyAsync(reply);
            if (reply[0] == (byte)MountAliasReply.LetterInUse)
                throw new ElevatedDriveAlias.DriveLetterInUseException(letter + ":");
            if (reply[0] != (byte)MountAliasReply.Ready)
                throw new IOException("Windows could not restore the approved drive.");
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
        finally { if (pinned) root.DangerousRelease(); gate.Release(); }
    }

    private static async Task CloseLateReplyAsync(Task<NamedPipeClientStream> transfer)
    {
        try { (await transfer).Dispose(); }
        catch (Exception error) when (error is IOException or ObjectDisposedException or UnauthorizedAccessException) { }
    }

    private static int ServiceProcessId()
    {
        using var manager = OpenSCManagerW(null, null, 1 /* SC_MANAGER_CONNECT */);
        if (manager.IsInvalid) throw ServiceError();
        using var service = OpenServiceW(manager, "BijouShare.Client", 4 /* SERVICE_QUERY_STATUS */);
        if (service.IsInvalid || !QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _))
            throw ServiceError();
        if (status.State != 4 /* SERVICE_RUNNING */ || status.ProcessId <= 0)
            throw new IOException("The BijouShare Client service is not running.");
        return status.ProcessId;
    }

    private static IOException ServiceError() => new("Windows could not find the running BijouShare Client service.",
        new Win32Exception(Marshal.GetLastPInvokeError()));
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus { public int Type, State, Controls, ExitCode, ServiceExitCode, CheckPoint, WaitHint, ProcessId, Flags; }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machine, string? database, int access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string name, int access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(nint handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, int flags, StringBuilder buffer, ref int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out int pid);
}
