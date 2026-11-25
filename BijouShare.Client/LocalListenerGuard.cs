using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class LocalListenerGuard
{
    internal static string PipeName(int servicePid) => $"BijouShare.Client.NetworkPorts.{servicePid}";
    internal const byte Ready = 1, PortInUse = 2, PortDenied = 3, Release = 4;

    internal static IDisposable Acquire(int port, NetworkServiceProtocol protocol)
    {
        if (port is < 1 or > 65535 || protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp or NetworkServiceProtocol.Both))
            throw new ArgumentException("Choose a valid port and protocol.");
        try
        {
            if (MountAliasPipe.IsInstalledClient) return AcquireFromServiceAsync(port, protocol).GetAwaiter().GetResult();
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.User == null || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new IOException("Install BijouShare Client and start its Windows service to protect this listener for your account.");
            using var reservation = Reserve(port, protocol);
            return NetworkPortFilters.Protect(port, protocol, identity.User, Environment.ProcessId);
        }
        catch (SocketException ex) { throw new IOException($"Local port {port} is already in use or reserved by Windows. Choose another port.", ex); }
        catch (Exception ex) when (ex is Win32Exception or OperationCanceledException or UnauthorizedAccessException or System.Security.SecurityException or EndOfStreamException)
        {
            throw new IOException("Windows could not protect this local port. Check that the BijouShare Client and Base Filtering Engine services are running.", ex);
        }
    }

    private static async Task<IDisposable> AcquireFromServiceAsync(int port, NetworkServiceProtocol protocol)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var pipe = await ElevatedDriveRestoreService.OpenVerifiedPipeAsync(PipeName, timeout.Token);
        try
        {
            var request = new byte[3];
            BinaryPrimitives.WriteUInt16LittleEndian(request, (ushort)port);
            request[2] = (byte)protocol;
            await pipe.WriteAsync(request, timeout.Token);
            var result = new byte[1];
            await pipe.ReadExactlyAsync(result, timeout.Token);
            if (result[0] == PortInUse) throw new IOException($"Local port {port} is already in use or reserved by Windows. Choose another port.");
            if (result[0] != Ready) throw new IOException("Windows could not protect this listener for your account. Check that the BijouShare Client and Base Filtering Engine services are running.");
            return new PipeLease(pipe, port, protocol);
        }
        catch { pipe.Dispose(); throw; }
    }

    private sealed class PipeLease(NamedPipeClientStream pipe, int port, NetworkServiceProtocol protocol) : IDisposable
    {
        public void Dispose()
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                pipe.WriteAsync(new byte[] { Release }, timeout.Token).AsTask().GetAwaiter().GetResult();
                ReadReleaseResultAsync(pipe, timeout.Token).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // The replacement broker can retire the old worker's persisted rules once
                // its last socket closes. A lease from a different process stays protected.
                try { ReleaseAfterRestartAsync(port, protocol).GetAwaiter().GetResult(); }
                catch (Exception retry) when (retry is IOException or OperationCanceledException or UnauthorizedAccessException or Win32Exception) { }
            }
            finally { pipe.Dispose(); }
        }
    }

    private static async Task ReleaseAfterRestartAsync(int port, NetworkServiceProtocol protocol)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var pipe = await ElevatedDriveRestoreService.OpenVerifiedPipeAsync(PipeName, timeout.Token);
        var request = new byte[3];
        BinaryPrimitives.WriteUInt16LittleEndian(request, (ushort)port);
        request[2] = (byte)(0x80 | (byte)protocol);
        await pipe.WriteAsync(request, timeout.Token);
        await ReadReleaseResultAsync(pipe, timeout.Token);
    }

    private static async Task ReadReleaseResultAsync(NamedPipeClientStream pipe, CancellationToken token)
    {
        var result = new byte[1];
        await pipe.ReadExactlyAsync(result, token);
        if (result[0] != Ready) throw new IOException("Windows could not release the network port rules.");
    }

    // Prove the protocol/port is free before a privileged component changes its filtering policy.
    internal static IDisposable Reserve(int port, NetworkServiceProtocol protocol)
    {
        var sockets = new List<Socket>(2);
        try
        {
            if (protocol.HasFlag(NetworkServiceProtocol.Tcp)) Bind(SocketType.Stream, ProtocolType.Tcp);
            if (protocol.HasFlag(NetworkServiceProtocol.Udp)) Bind(SocketType.Dgram, ProtocolType.Udp);
            return new Reservation(sockets);
        }
        catch { foreach (var socket in sockets) socket.Dispose(); throw; }
        void Bind(SocketType type, ProtocolType transport)
        {
            var socket = new Socket(AddressFamily.InterNetwork, type, transport);
            sockets.Add(socket);
            socket.ExclusiveAddressUse = true;
            socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
        }
    }

    private sealed class Reservation(List<Socket> sockets) : IDisposable
    {
        public void Dispose() { foreach (var socket in sockets) socket.Dispose(); }
    }
}

internal sealed class NetworkPortBroker(ILogger<NetworkPortBroker> logger) : BackgroundService
{
    private readonly object gate = new();
    private readonly Dictionary<(int Port, NetworkServiceProtocol Protocol), SecurityIdentifier> active = [];

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem || !MountAliasPipe.IsInstalledClient) return;
        var clients = new HashSet<Task>();
        var cleanup = SweepAsync(stop);
        try
        {
            while (!stop.IsCancellationRequested)
            {
                clients.RemoveWhere(task => task.IsCompleted);
                if (clients.Count >= 96) { await Task.WhenAny(clients).WaitAsync(stop); continue; }
                NamedPipeServerStream? listener = null;
                try
                {
                    listener = ElevatedDriveRestoreService.CreatePipe(LocalListenerGuard.PipeName(Environment.ProcessId));
                    await listener.WaitForConnectionAsync(stop);
                    var connected = listener;
                    clients.Add(Task.Run(() => ServeAsync(connected, stop)));
                    listener = null;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    logger.LogDebug(ex, "Network port broker is waiting for its pipe.");
                    await Task.Delay(TimeSpan.FromSeconds(1), stop);
                }
                finally { listener?.Dispose(); }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        finally { await Task.WhenAll(clients.Append(cleanup)); }
    }

    private async Task SweepAsync(CancellationToken stop)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(2));
        try
        {
            do
            {
                try
                {
                    lock (gate) NetworkPortFilters.Sweep((port, protocol) =>
                    {
                        if (IsActive(port, protocol)) return false;
                        try { using var reservation = LocalListenerGuard.Reserve(port, protocol); return true; }
                        catch (SocketException) { return false; }
                    });
                }
                catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException)
                { logger.LogWarning(ex, "Windows could not clean up unused network listener rules."); }
            } while (await timer.WaitForNextTickAsync(stop));
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }

    private bool IsActive(int port, NetworkServiceProtocol protocol) =>
        active.Keys.Any(key => key.Port == port && (key.Protocol & protocol) != 0);

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        using var connection = pipe;
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(stop);
        startup.CancelAfter(TimeSpan.FromSeconds(10));
        IDisposable? filters = null;
        int port = 0;
        NetworkServiceProtocol protocol = 0;
        bool released = false;
        try
        {
            var request = new byte[3];
            await pipe.ReadExactlyAsync(request, startup.Token);
            port = BinaryPrimitives.ReadUInt16LittleEndian(request);
            bool releaseAfterRestart = (request[2] & 0x80) != 0;
            protocol = (NetworkServiceProtocol)(request[2] & 0x7f);
            if (port == 0 || protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp or NetworkServiceProtocol.Both) ||
                !ElevatedDriveRestoreService.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out int pid) || pid <= 0) return;
            using var worker = Process.GetProcessById(pid);
            if (!ElevatedDriveRestoreService.IsInstalledWorker(worker.SafeHandle)) return;
            SecurityIdentifier? owner = null;
            pipe.RunAsClient(() =>
            {
                using var caller = WindowsIdentity.GetCurrent(ifImpersonating:true);
                if (caller is { IsSystem:false, ImpersonationLevel:TokenImpersonationLevel.Identification }) owner = caller.User;
            });
            if (owner == null) return;
            lock (gate)
            {
                if (IsActive(port, protocol)) throw new SocketException((int)SocketError.AddressAlreadyInUse);
                if (active.Values.Count(sid => sid == owner) >= ClientSettings.MaximumNetworkListeners) throw new IOException("Too many active port guards.");
                using var reservation = LocalListenerGuard.Reserve(port, protocol);
                if (releaseAfterRestart)
                    NetworkPortFilters.ReleaseOwned(port, protocol, worker, owner);
                else
                {
                    filters = NetworkPortFilters.Protect(port, protocol, owner, pid);
                    active.Add((port, protocol), owner);
                }
            }
            await pipe.WriteAsync(new byte[] { LocalListenerGuard.Ready }, startup.Token);
            if (releaseAfterRestart) return;
            var command = new byte[1];
            var count = await pipe.ReadAsync(command, stop);
            released = count == 1 && command[0] == LocalListenerGuard.Release;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or InvalidOperationException or OperationCanceledException)
        {
            logger.LogDebug(ex, "Network port guard request ended.");
            if (filters == null && !startup.IsCancellationRequested)
            {
                try { await pipe.WriteAsync(new[] { ex is SocketException ? LocalListenerGuard.PortInUse : LocalListenerGuard.PortDenied }, startup.Token); }
                catch (Exception write) when (write is IOException or OperationCanceledException) { }
            }
        }
        finally
        {
            if (filters != null)
            {
                byte releaseResult = LocalListenerGuard.Ready;
                lock (gate)
                {
                    active.Remove((port, protocol));
                    // A crashed broker/worker cannot expose a still-bound port. Sweep reclaims the
                    // persistent filters only after the worker has exited and the port is free.
                    if (released)
                    {
                        try { filters.Dispose(); }
                        catch (Exception ex) when (ex is Win32Exception or IOException)
                        {
                            releaseResult = LocalListenerGuard.PortDenied;
                            logger.LogWarning(ex, "Could not release network port guard.");
                        }
                    }
                }
                if (released)
                {
                    try { await pipe.WriteAsync(new byte[] { releaseResult }, stop); }
                    catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
                }
            }
        }
    }
}
