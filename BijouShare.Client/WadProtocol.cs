using Microsoft.Win32;

namespace BijouShare.Client;

internal static class WadProtocol
{
    // Handle protocol launches before general CLI parsing so URI quoting cannot introduce setup options.
    public static string[] NormalizeActivationArguments(string[] args)
    {
        if (!args.Contains("--open-uri", StringComparer.Ordinal))
            return args;
        if (args.Length != 4 || args[0] != "--data-dir" || args[2] != "--open-uri" || !Path.IsPathFullyQualified(args[1]))
            throw new ArgumentException("Invalid wad protocol activation.");
        WadUri.Parse(args[3]);
        return ["--data-dir", args[1], args[3]];
    }

    public static void RegisterForCurrentUser(string directory)
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "BijouShare.Client.exe");
        directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if (!File.Exists(executable) || executable.Contains('"') || directory.Contains('"'))
            throw new InvalidOperationException("Cannot register the client executable for wad links.");
        using var protocol = Registry.CurrentUser.CreateSubKey(@"Software\Classes\wad");
        protocol.SetValue("", "URL:BijouShare connection");
        protocol.SetValue("URL Protocol", "");
        using var icon = protocol.CreateSubKey("DefaultIcon");
        icon.SetValue("", $"\"{executable}\",0");
        using var command = protocol.CreateSubKey(@"shell\open\command");
        command.SetValue("", $"\"{executable}\" --data-dir \"{directory}\" --open-uri \"%1\"");
    }
}
