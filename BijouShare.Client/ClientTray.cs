using System.Diagnostics;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class ClientTray
{
    // The profile lease is per user, but every signed-in desktop needs its own icon.
    internal static EventWaitHandle? ClaimSession(string directory, int ownerProcessId)
    {
        var presence = new EventWaitHandle(false, EventResetMode.ManualReset,
            $@"Local\{ClientActivation.PipeName(directory)}.Tray.{ownerProcessId}", out var created);
        if (created)
            return presence;
        presence.Dispose();
        return null;
    }

    internal static WindowsTrayIcon Start(Func<string> managementUrl, Action? exit = null)
    {
        var icon = WindowsTrayIcon.Start("BijouShare Client", () => OpenBrowser(managementUrl()),
            _ => Console.Error.WriteLine("Could not open the client console. Click the BijouShare Client tray icon to retry."), exit);
        WindowsTrayIcon.DetachPrivateConsole();
        return icon;
    }

    internal static void OpenBrowser(string url)
    {
        try { using var browser = Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            // Shell errors can include the complete URL, including the owner's access credential.
            throw new IOException("Windows could not open the client console. Check your default browser and click the BijouShare Client tray icon to retry.");
        }
    }

    internal static async Task AttachAsync(string directory, ClientActivation.RunningClient running, ClientCommandLine options)
    {
        Console.WriteLine($"Client management: {new Uri(running.ManagementUrl).GetLeftPart(UriPartial.Authority)}");
        using var presence = options.NoBrowser ? null : ClaimSession(directory, running.ProcessId);
        if (presence is null && !options.SessionWorker)
            return;

        Process owner;
        try { owner = Process.GetProcessById(running.ProcessId); }
        catch (ArgumentException) { return; } // The host stopped during attachment.
        using (owner)
        {
            // The service can start after a manually launched host, and the same user can
            // sign in to two desktops. Attach to that host without creating another mount.
            using var tray = presence is null ? null : Start(() =>
            {
                var current = ClientActivation.TryGetRunningClientAsync(directory).GetAwaiter().GetResult();
                if (current is null || current.ProcessId != running.ProcessId)
                    throw new IOException("The client console is unavailable.");
                return current.ManagementUrl;
            });
            await owner.WaitForExitAsync();
        }
    }
}
