using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
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

    internal static WindowsTrayIcon? StartForSession(string directory, int ownerProcessId,
        Func<CancellationToken, Task<string>> managementUrl, Action? exit = null)
    {
        EventWaitHandle? presence = null;
        try
        {
            presence = ClaimSession(directory, ownerProcessId);
            if (presence is null)
                return null;
            var icon = WindowsTrayIcon.Start("BijouShare Client", async token => OpenBrowser(await managementUrl(token).ConfigureAwait(false)),
                _ => Console.Error.WriteLine("Could not use the client tray. Open BijouShare Client from Start to reach the console."), exit);
            _ = ReleaseWhenClosedAsync(icon, presence);
            return icon;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or WaitHandleCannotBeOpenedException or Win32Exception)
        {
            presence?.Dispose();
            Console.Error.WriteLine($"Could not start the client tray ({ex.GetType().Name}). Open BijouShare Client from Start to reach the console.");
            return null;
        }
    }

    private static async Task ReleaseWhenClosedAsync(WindowsTrayIcon icon, EventWaitHandle presence)
    {
        using (presence)
            await icon.Completion.ConfigureAwait(false);
    }

    internal static void OpenFromShortcut(string url)
    {
        try { OpenBrowser(url); }
        catch (IOException ex) { ShowStartupError(ex.Message); }
    }

    internal static void ShowStartupError(string message) =>
        MessageBoxW(0, message, "BijouShare Client", 0x10 /* MB_ICONERROR */);

    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(nint owner, string message, string caption, uint flags);

    internal static void OpenBrowser(string url)
    {
        try { using var browser = Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            // Shell errors can include the complete URL, including the owner's access credential.
            throw new IOException("Windows could not open the client console. Check your default browser and click the BijouShare Client tray icon to retry.");
        }
    }

    internal static string InviteRequiredNotice(string drive, string address) =>
        $"This server is invite only. Ask its administrator for a valid invite link.\n{drive} · {address}";

    internal static async Task AttachAsync(string directory, ClientActivation.RunningClient running, ClientCommandLine options,
        Action<string>? openConsole = null)
    {
        Console.WriteLine($"Client management: {new Uri(running.ManagementUrl).GetLeftPart(UriPartial.Authority)}");
        Process owner;
        try { owner = Process.GetProcessById(running.ProcessId); }
        catch (ArgumentException) { return; } // The host stopped during attachment.
        using (owner)
        {
            // The service can start after a manually launched host, and the same user can
            // sign in to two desktops. Attach to that host without creating another mount.
            using var tray = options.NoBrowser ? null : StartForSession(directory, running.ProcessId, async token =>
            {
                var current = await ClientActivation.TryGetRunningClientAsync(directory, token).ConfigureAwait(false);
                if (current is null || current.ProcessId != running.ProcessId)
                    throw new IOException("The client console is unavailable.");
                return current.ManagementUrl;
            });
            if (options.Command == ClientCommand.OpenManagement)
                (openConsole ?? OpenFromShortcut)(running.ManagementUrl);
            if (tray is null && !options.SessionWorker)
                return;
            if (tray is not null)
                WindowsTrayIcon.DetachPrivateConsole();
            await owner.WaitForExitAsync();
        }
    }
}
