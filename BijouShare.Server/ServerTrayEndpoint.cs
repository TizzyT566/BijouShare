using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Server;

// Session zero supplies only Kestrel's current loopback address. The interactive helper
// never needs the service's private directory or access to an administrator session.
internal sealed class ServerTrayEndpoint(IServer server, IHostApplicationLifetime lifetime, ILogger<ServerTrayEndpoint> logger,
    WebPortListener? webPorts = null) : BackgroundService
{
    // Windows also checks FILE_READ_ATTRIBUTES when opening the local pipe for the desktop client.
    private const PipeAccessRights ClientRights = PipeAccessRights.ReadData | PipeAccessRights.WriteData |
        PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize;
    private static string PipeName(uint processId) => $"BijouShare.Server.Tray.{processId}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipe((uint)Environment.ProcessId);
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var request = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                request.CancelAfter(TimeSpan.FromSeconds(2));
                // Keep the pipe open until the client checks the peer PID supplied by Windows.
                var query = new byte[1];
                await pipe.ReadExactlyAsync(query, request.Token);
                if (query[0] != 1)
                    continue;
                var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
                var uri = lifetime.ApplicationStarted.IsCancellationRequested && !lifetime.ApplicationStopping.IsCancellationRequested &&
                    addresses is not null ? ServerTray.LocalAddress(addresses, webPorts?.CurrentPort) : null;
                await WriteAsync(pipe, uri, request.Token);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                logger.LogDebug(ex, "The server tray endpoint is temporarily unavailable.");
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
        }
    }

    internal static NamedPipeServerStream CreatePipe(uint processId)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(identity.User!);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            ClientRights, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(PipeName(processId), PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 512, 512, security);
    }

    internal static async Task WriteAsync(Stream pipe, Uri? url, CancellationToken token)
    {
        var text = url?.AbsoluteUri ?? "";
        var count = Encoding.ASCII.GetByteCount(text);
        var reply = new byte[count + 1];
        reply[0] = checked((byte)count);
        Encoding.ASCII.GetBytes(text, reply.AsSpan(1));
        await pipe.WriteAsync(reply, token);
    }

    internal static async Task<Uri?> ReadAsync(uint serviceProcessId, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        using var pipe = new NamedPipeClientStream(".", PipeName(serviceProcessId), ClientRights,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous, HandleInheritability.None);
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var actualId) || actualId != serviceProcessId)
            throw new UnauthorizedAccessException("The tray endpoint does not belong to the running Windows service.");
        await pipe.WriteAsync(new byte[] { 1 }, timeout.Token).ConfigureAwait(false);
        var size = new byte[1];
        await pipe.ReadExactlyAsync(size, timeout.Token).ConfigureAwait(false);
        if (size[0] == 0)
            return null;
        var reply = new byte[size[0]];
        await pipe.ReadExactlyAsync(reply, timeout.Token).ConfigureAwait(false);
        return ServerTray.LocalAddress([Encoding.ASCII.GetString(reply)]);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
}
