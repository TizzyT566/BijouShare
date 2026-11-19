using System.Diagnostics;
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
public sealed class ClientActivation(ClientSettings settings, ClientManagement management, ClientManagementAccess access, ILogger<ClientActivation> logger) : BackgroundService
{
    private const int MaximumBytes = 4096;

    internal static string PipeName(string directory) => "BijouShare.Client." + Convert.ToHexString(SHA3_256.HashData(
        Encoding.UTF8.GetBytes(Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant())))[..24];

    internal static async Task DeliverProtocolLinkAsync(string directory, WadUri link, Action<ProcessStartInfo>? startClient = null, CancellationToken token = default)
    {
        var uri = link.ToStringWithInvite();
        if (await TryForwardAsync(directory, uri, token, connectTimeoutMs: 350))
            return;

        var options = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "BijouShare.Client.exe"))
        {
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (startClient is null)
        {
            try
            {
                using var process = Process.Start(options) ?? throw new IOException("Could not start the installed BijouShare client.");
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                throw new IOException("Could not start the installed BijouShare client.", ex);
            }
        }
        else
            startClient(options);

        // A concurrent launcher or service may win the profile lease and become the pipe
        // owner. Deliver to whichever authenticated instance acknowledges the saved link.
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
        startup.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            while (!await TryForwardAsync(directory, uri, startup.Token, connectTimeoutMs: 500))
                await Task.Delay(100, startup.Token);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            throw new IOException("The client did not acknowledge the connection link. Open BijouShare.Client.exe to check startup.");
        }
    }

    public static async Task<bool> TryForwardAsync(string directory, string uri, CancellationToken token = default, int connectTimeoutMs = 3000)
    {
        _ = WadUri.Parse(uri);
        if (Encoding.UTF8.GetByteCount(uri) > MaximumBytes)
            throw new ArgumentException("The server link is too long.");
        using var pipe = new NamedPipeClientStream(".", PipeName(directory), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            await pipe.ConnectAsync(connectTimeoutMs, token);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException or IOException)
        {
            token.ThrowIfCancellationRequested();
            return false;
        }
        VerifyServerExecutable(pipe);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var bytes = Encoding.UTF8.GetBytes(uri);
        try
        {
            await pipe.WriteAsync(BitConverter.GetBytes(bytes.Length), timeout.Token);
            await pipe.WriteAsync(bytes, timeout.Token);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        await pipe.FlushAsync(timeout.Token);
        var reply = new byte[1];
        await pipe.ReadExactlyAsync(reply, timeout.Token);
        if (reply[0] != 1)
            throw new IOException("The running client could not add this server. Open its management page to check the configuration.");
        return true;
    }

    internal sealed class RunningClient(string managementUrl, int processId)
    {
        public string ManagementUrl { get; } = managementUrl;
        public int ProcessId { get; } = processId;
    }

    public static async Task<string?> TryGetManagementUrlAsync(string directory, CancellationToken token = default) =>
        (await TryGetRunningClientAsync(directory, token))?.ManagementUrl;

    internal static async Task<RunningClient> WaitForRunningClientAsync(string directory, CancellationToken token = default)
    {
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
        startup.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            while (true)
            {
                if (await TryGetRunningClientAsync(directory, startup.Token) is { } running)
                    return running;
                await Task.Delay(250, startup.Token);
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            throw new IOException("The client console did not become ready. Check that the BijouShare.Client service is running, then click its tray icon.");
        }
    }

    internal static async Task<RunningClient?> TryGetRunningClientAsync(string directory, CancellationToken token = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        using var pipe = new NamedPipeClientStream(".", PipeName(directory), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            await pipe.ConnectAsync(timeout.Token);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException or IOException)
        {
            token.ThrowIfCancellationRequested();
            return null;
        }
        var processId = VerifyServerExecutable(pipe);
        string result;
        try
        {
            await pipe.WriteAsync(new byte[4], timeout.Token);
            var header = new byte[4];
            await pipe.ReadExactlyAsync(header, timeout.Token);
            var count = BitConverter.ToInt32(header);
            if (count is < 1 or > 128)
                throw new IOException("The running client returned an invalid management address.");
            var bytes = new byte[count];
            await pipe.ReadExactlyAsync(bytes, timeout.Token);
            result = Encoding.UTF8.GetString(bytes);
        }
        // During startup the pipe can exist before Kestrel publishes its port.
        // During an upgrade the previous owner can close the pipe mid-reply.
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { return null; }
        catch (IOException ex) when (ex is EndOfStreamException || (ex.HResult & 0xffff) is 109 or 232 or 233) { return null; }
        if (!System.Uri.TryCreate(result, UriKind.Absolute, out var url) || url.Scheme != "http" ||
            url.Host != "127.0.0.1" || url.UserInfo.Length != 0 || url.AbsolutePath != "/" || url.Query.Length != 0 || url.Fragment.Length != 72 || !url.Fragment.StartsWith("#access=", StringComparison.Ordinal) || !url.Fragment[8..].All(Uri.IsHexDigit))
            throw new IOException("The running client returned an invalid management address.");
        return new(result, processId);
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
                    var address = Encoding.UTF8.GetBytes(await access.LaunchUrl(timeout.Token));
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
            catch (Exception exception) when (exception is IOException or InvalidDataException or ArgumentException or UnauthorizedAccessException or CryptographicException or OperationCanceledException)
            {
                // The URI fragment may contain a bearer credential.
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

    private static int VerifyServerExecutable(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var processId))
            throw new IOException("Cannot verify the running client process.");
        using var process = OpenProcess(0x1000, false, processId);
        var path = new StringBuilder(32768);
        var length = (uint)path.Capacity;
        if (process.IsInvalid || !QueryFullProcessImageName(process, 0, path, ref length) ||
            !string.Equals(Path.GetFullPath(path.ToString()), Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The client activation channel belongs to another executable. Open the installed client to manage connections.");
        return checked((int)processId);
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
        using var identity = WindowsIdentity.GetCurrent();
        security.SetOwner(identity.User!);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, MaximumBytes, MaximumBytes, security, HandleInheritability.None);
    }
}
