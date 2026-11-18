using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using BijouShare.Shared;

namespace BijouShare.Client;

// A protocol launch forwards one bounded request to the service, rather than opening another drive.
public sealed class ClientActivation(ClientSettings settings, ClientManagement management, ILogger<ClientActivation> logger) : BackgroundService
{
    private const int MaximumBytes = 4096;

    internal static string PipeName(string directory) => "BijouShare.Client." + Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant())))[..24];

    public static async Task<bool> TryForwardAsync(string directory, string uri, CancellationToken token = default)
    {
        _ = WadUri.Parse(uri);
        var bytes = Encoding.UTF8.GetBytes(uri);
        if (bytes.Length > MaximumBytes)
            throw new ArgumentException("The server link is too long.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var pipe = new NamedPipeClientStream(".", PipeName(directory), PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(timeout.Token);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException or IOException)
        {
            token.ThrowIfCancellationRequested();
            return false;
        }
        VerifyServerExecutable(pipe);
        await pipe.WriteAsync(BitConverter.GetBytes(bytes.Length), timeout.Token);
        await pipe.WriteAsync(bytes, timeout.Token);
        await pipe.FlushAsync(timeout.Token);
        var reply = new byte[1];
        await pipe.ReadExactlyAsync(reply, timeout.Token);
        if (reply[0] != 1)
            throw new IOException("The running client could not add this server. Open its management page to check the configuration.");
        return true;
    }

    public static async Task<string?> TryGetManagementUrlAsync(string directory, CancellationToken token = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        using var pipe = new NamedPipeClientStream(".", PipeName(directory), PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(timeout.Token);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException or IOException)
        {
            token.ThrowIfCancellationRequested();
            return null;
        }
        VerifyServerExecutable(pipe);
        await pipe.WriteAsync(new byte[4], timeout.Token);
        var header = new byte[4];
        await pipe.ReadExactlyAsync(header, timeout.Token);
        var count = BitConverter.ToInt32(header);
        if (count is < 1 or > 128)
            throw new IOException("The running client returned an invalid management address.");
        var bytes = new byte[count];
        await pipe.ReadExactlyAsync(bytes, timeout.Token);
        var result = Encoding.UTF8.GetString(bytes);
        if (!System.Uri.TryCreate(result, UriKind.Absolute, out var url) || url.Scheme != "http" ||
            url.Host != "127.0.0.1" || url.AbsolutePath != "/" || url.Query.Length != 0 || url.Fragment.Length != 0)
            throw new IOException("The running client returned an invalid management address.");
        return result;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var directory = Path.GetDirectoryName(settings.SettingsPath ?? throw new InvalidOperationException("Client settings path is missing."))!;
        while (!stoppingToken.IsCancellationRequested)
        {
            using var pipe = CreatePipe(PipeName(directory));
            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                var header = new byte[4];
                await pipe.ReadExactlyAsync(header, timeout.Token);
                var count = BitConverter.ToInt32(header);
                if (count == 0)
                {
                    var address = Encoding.UTF8.GetBytes($"http://127.0.0.1:{settings.ManagementPort}/");
                    await pipe.WriteAsync(BitConverter.GetBytes(address.Length), timeout.Token);
                    await pipe.WriteAsync(address, timeout.Token);
                    continue;
                }
                if (count is < 1 or > MaximumBytes)
                    throw new InvalidDataException("Invalid protocol launch length.");
                var bytes = new byte[count];
                await pipe.ReadExactlyAsync(bytes, timeout.Token);
                try
                {
                    var uri = WadUri.Parse(new UTF8Encoding(false, true).GetString(bytes));
                    await management.AddServerAsync(uri, timeout.Token);
                    await pipe.WriteAsync(new byte[] { 1 }, timeout.Token);
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) when (exception is IOException or ArgumentException or UnauthorizedAccessException or CryptographicException or OperationCanceledException)
            {
                // Never log the URI: its path can contain an enrollment secret.
                logger.LogWarning("A protocol launch could not be applied ({Reason}).", exception.GetType().Name);
                if (pipe.IsConnected)
                {
                    try
                    {
                        await pipe.WriteAsync(new byte[] { 0 }, stoppingToken);
                    }
                    catch (Exception responseError) when (responseError is IOException or OperationCanceledException) { }
                }
            }
        }
    }

    private static void VerifyServerExecutable(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var processId))
            throw new IOException("Cannot verify the running client process.");
        using var process = OpenProcess(0x1000, false, processId);
        var path = new StringBuilder(32768);
        var length = (uint)path.Capacity;
        if (process.IsInvalid || !QueryFullProcessImageName(process, 0, path, ref length) ||
            !string.Equals(Path.GetFullPath(path.ToString()), Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The client activation channel belongs to another executable. Open the installed client to manage connections.");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder name, ref uint size);

    private static NamedPipeServerStream CreatePipe(string name)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        // Block network logons before granting local machine users the AddServer-only channel.
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        using var identity = WindowsIdentity.GetCurrent();
        foreach (var sid in new[] { identity.User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }.Distinct())
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, MaximumBytes, MaximumBytes, security, HandleInheritability.None);
    }
}
