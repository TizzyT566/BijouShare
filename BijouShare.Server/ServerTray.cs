using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using BijouShare.Shared;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Server;

internal static class ServerTray
{
    private const string ServiceName = "BijouShare.Server";
    private const string Title = "BijouShare Server";
    private const string NoLocalAddress = "The server has not published a local web address. Check that startup completed and a loopback HTTP or HTTPS management endpoint is configured.";
    private const string ChannelUnavailable = "The server management channel did not respond. Check BijouShare.Server in Event Viewer under Windows Logs > Application, then try again.";
    private sealed class ServiceUnavailableException(string message) : IOException(message);

    internal static bool IsInstalledExecutable()
    {
        var executable = Environment.ProcessPath;
        var command = Registry.GetValue($@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{ServiceName}",
            "ImagePath", null) as string;
        if (executable is null || string.IsNullOrWhiteSpace(command))
            return false;
        var registered = command.TrimStart();
        var prefix = registered.StartsWith('"') ? $"\"{executable}\"" : executable;
        return registered.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            (registered.Length == prefix.Length || char.IsWhiteSpace(registered[prefix.Length]));
    }

    internal static WindowsTrayIcon StartForHost(WebApplication app)
    {
        var tray = WindowsTrayIcon.Start(Title,
            () => OpenBrowser(LocalAddress(app.Urls)),
            error => app.Logger.LogWarning(error, "Could not open server management from the notification area."),
            app.Lifetime.StopApplication);
        WindowsTrayIcon.DetachPrivateConsole();
        return tray;
    }

    internal static Mutex ClaimStandaloneIcon(string directory, out bool first)
    {
        var path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)).ToUpperInvariant();
        var key = Convert.ToHexString(SHA3_256.HashData(Encoding.UTF8.GetBytes(path)));
        return new Mutex(false, @"Local\BijouShare.Server.Tray." + key, out first);
    }

    internal static async Task OpenInstalledManagementAsync()
    {
        WindowsTrayIcon.DetachPrivateConsole();
        await OpenInstalledWhenReadyAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
    }

    private static async Task OpenInstalledWhenReadyAsync(TimeSpan timeout, CancellationToken token)
    {
        try
        {
            await OpenWhenReadyAsync(async probe =>
            {
                var pid = RunningServiceProcessId();
                var url = await ServerTrayEndpoint.ReadAsync(pid, probe);
                if (pid != RunningServiceProcessId()) throw new ServiceUnavailableException("BijouShare Server restarted. Wait for the service to finish starting and click the icon again.");
                return url;
            }, OpenBrowser, timeout, token);
        }
        catch (UnauthorizedAccessException)
        {
            throw new TrayOpenException("Windows denied access to the server management channel or its owner could not be verified. Restart BijouShare Server from Services and try again.");
        }
    }

    internal static async Task OpenWhenReadyAsync(Func<CancellationToken, Task<Uri?>> findAddress, Action<Uri> open,
        TimeSpan timeout, CancellationToken cancellation = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(timeout);
        var failure = ChannelUnavailable;
        try
        {
            while (true)
            {
                Uri? url = null;
                try
                {
                    url = await findAddress(deadline.Token);
                    if (url is null) failure = NoLocalAddress;
                }
                catch (ServiceUnavailableException error) { failure = error.Message; }
                catch (Exception error) when (error is not TrayOpenException && (error is IOException or InvalidOperationException or TimeoutException ||
                    error is OperationCanceledException && !deadline.IsCancellationRequested))
                {
                    failure = ChannelUnavailable;
                }
                deadline.Token.ThrowIfCancellationRequested();
                if (url is not null)
                {
                    open(url);
                    return;
                }
                await Task.Delay(300, deadline.Token);
            }
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellation.IsCancellationRequested)
        {
            throw new TrayOpenException(failure);
        }
    }

    internal static int RunCompanion()
    {
        // Local names are scoped to this interactive Windows session, including remote desktops.
        using var instance = new Mutex(false, @"Local\BijouShare.Server.Tray", out var first);
        if (!first)
            return 0;
        using var stop = new CancellationTokenSource();
        using var tray = WindowsTrayIcon.Start(Title,
            token => OpenInstalledWhenReadyAsync(TimeSpan.FromSeconds(6), token),
            error => Console.Error.WriteLine($"BijouShare.Server: {error.Message}"), stop.Cancel);
        WindowsTrayIcon.DetachPrivateConsole();
        bool hasConsole = GetConsoleWindow() != IntPtr.Zero;
        void Cancel(object? sender, ConsoleCancelEventArgs e) { e.Cancel = true; stop.Cancel(); }
        if (hasConsole) Console.CancelKeyPress += Cancel;
        try
        {
            WaitForCompanionExitAsync(tray.Completion, () => ServiceRegistrationRemoved(ServiceName),
                TimeSpan.FromSeconds(5), stop.Token).GetAwaiter().GetResult();
        }
        finally { if (hasConsole) Console.CancelKeyPress -= Cancel; }
        return 0;
    }

    internal static async Task WaitForCompanionExitAsync(Task trayClosed, Func<bool> registrationRemoved,
        TimeSpan interval, CancellationToken stop)
    {
        while (!stop.IsCancellationRequested && !trayClosed.IsCompleted && !registrationRemoved())
            await Task.WhenAny(trayClosed, Task.Delay(interval, stop)).ConfigureAwait(false);
    }

    private static bool ServiceRegistrationRemoved(string serviceName)
    {
        // Do not hold a service handle between checks: that would delay deletion during uninstall.
        using var manager = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (manager.IsInvalid) return false;
        using var service = OpenService(manager, serviceName, 0x0004); // SERVICE_QUERY_STATUS
        return service.IsInvalid && Marshal.GetLastPInvokeError() is 1060 or 1072; // Missing or marked for deletion.
    }

    internal static Uri? LocalAddress(IEnumerable<string> addresses)
    {
        foreach (var address in addresses)
        {
            // Kestrel accepts + and * as wildcard hosts, which Uri does not parse.
            var value = address.Replace("://*:", "://0.0.0.0:", StringComparison.Ordinal)
                .Replace("://+:", "://0.0.0.0:", StringComparison.Ordinal);
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                uri.Scheme is not ("http" or "https") || uri.Port < 1 || uri.UserInfo.Length != 0 ||
                uri.AbsolutePath != "/" || uri.Query.Length != 0 || uri.Fragment.Length != 0)
                continue;
            if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                return uri;
            if (!IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip))
                continue;
            if (IPAddress.IsLoopback(ip))
                return uri;
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            {
                var host = uri.Scheme == "https" ? "localhost" :
                    ip.Equals(IPAddress.Any) ? IPAddress.Loopback.ToString() : IPAddress.IPv6Loopback.ToString();
                return new UriBuilder(uri) { Host = host }.Uri;
            }
        }
        return null;
    }

    private static void OpenBrowser(Uri? url)
    {
        if (url is null)
            throw new TrayOpenException(NoLocalAddress);
        try { using var browser = Process.Start(new ProcessStartInfo(url.AbsoluteUri) { UseShellExecute = true }); }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            throw new TrayOpenException("Windows could not open the default browser. Choose a browser for HTTP and HTTPS in Settings > Apps > Default apps, then try again.");
        }
    }

    private static uint RunningServiceProcessId()
    {
        using var manager = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (manager.IsInvalid)
            throw ServiceQueryError(Marshal.GetLastPInvokeError());
        using var service = OpenService(manager, ServiceName, 0x0004); // SERVICE_QUERY_STATUS
        if (service.IsInvalid)
            throw ServiceQueryError(Marshal.GetLastPInvokeError());
        if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatusProcess>(), out _))
            throw ServiceQueryError(Marshal.GetLastPInvokeError());
        if (status.State == 1) // SERVICE_STOPPED
            throw new ServiceUnavailableException("BijouShare Server is stopped. Open Services, start BijouShare Server, then click the tray icon again.");
        if (status.State == 7) // SERVICE_PAUSED
            throw new ServiceUnavailableException("BijouShare Server is paused. Resume it in Services, then click the tray icon again.");
        if (status.State != 4 || status.ProcessId == 0) // SERVICE_RUNNING
            throw new ServiceUnavailableException("BijouShare Server is changing state. Wait until it shows Running in Services, then click the tray icon again.");
        return status.ProcessId;
    }

    private static TrayOpenException ServiceQueryError(int code) => new(code switch
    {
        1060 => "The BijouShare Server service is not installed. Run BijouShare Server Setup on this computer, then open its tray icon.",
        5 => "Windows denied access to the BijouShare Server service status. Ask an administrator to check the service permissions.",
        _ => "Windows could not read the BijouShare Server service status. Open Services and check that BijouShare Server is running."
    });

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint Type, State, Controls, ExitCode, ServiceExitCode, CheckPoint, WaitHint, ProcessId, Flags;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatusProcess status, int size, out uint needed);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();
}
