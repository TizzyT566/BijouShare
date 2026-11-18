using Microsoft.Win32;

namespace BijouShare.Client;

internal static class WadProtocol
{
    // Handle protocol launches before general CLI parsing so URI quoting cannot introduce setup options.
    public static WadUri? ParseActivation(string[] args)
    {
        if (!args.Contains("--open-uri", StringComparer.Ordinal))
            return null;
        if (args.Length == 2 && args[0] == "--open-uri")
            return WadUri.Parse(args[1]);
        throw new ArgumentException("Invalid wad protocol activation.");
    }

    public static void RegisterForCurrentUser()
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "BijouShare.Client.exe");
        if (!File.Exists(executable) || executable.Contains('"'))
            throw new InvalidOperationException("Cannot register the client executable for wad links.");
        using var protocol = Registry.CurrentUser.CreateSubKey(@"Software\Classes\wad");
        protocol.SetValue("", "URL:BijouShare connection");
        protocol.SetValue("URL Protocol", "");
        using var icon = protocol.CreateSubKey("DefaultIcon");
        icon.SetValue("", $"\"{executable}\",0");
        using var command = protocol.CreateSubKey(@"shell\open\command");
        command.SetValue("", $"\"{executable}\" --open-uri \"%1\"");
    }

    internal static void RegisterOnLaunch(ClientCommandLine options)
    {
        // Service installations already register their machine-wide handler.
        if (options.NoBrowser || options.SessionWorker)
            return;
        try
        {
            // The installer owns the machine handler. Avoid shadowing it with a
            // per-user registration that would outlive an MSI uninstall.
            var executable = Path.Combine(AppContext.BaseDirectory, "BijouShare.Client.exe");
            using var command = Registry.ClassesRoot.OpenSubKey(@"wad\shell\open\command");
            if (!string.Equals(command?.GetValue(null) as string, $"\"{executable}\" --open-uri \"%1\"",
                    StringComparison.OrdinalIgnoreCase))
                RegisterForCurrentUser();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException or InvalidOperationException)
        {
            Console.Error.WriteLine("Could not register wad links for this Windows user. Run --register-protocol to retry.");
        }
    }
}
