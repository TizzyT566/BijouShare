using System.Text;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class ClientSetupSelfTests
{
    public static void Run(Action<bool, string> check)
    {
        void Invalid(string value)
        {
            try
            {
                WadUri.Parse(value);
            }
            catch (ArgumentException) { check(true, "Connection links reject unsafe or malformed input"); return; }
            throw new InvalidOperationException("Invalid connection link accepted.");
        }
        var code = new string('a', 32);
        var link = WadUri.Parse("wad://fileserver:7443/" + code);
        check(link.Host == "fileserver" && link.Port == 7443 && link.InviteCode == code && !link.ToString().Contains(code),
            "Connection links parse invite enrollment without exposing the credential in diagnostic strings");
        check(WadUri.Parse("wad://[::1]:7443").Host == "::1" && WadUri.Parse("WAD://192.168.1.10:7443/").InviteCode is null,
            "Connection links support IPv4, bracketed IPv6, and links without an invite");
        foreach (var invalid in new[] { "https://host:7443/code", "wad://host", "wad://host:0", "wad://host:65536", "wad://user@host:7443", "wad://host:7443/a/b", "wad://host:7443/../abc", "wad://host:7443/%61", "wad://host:7443/a?b", "wad://host:7443/a#b", "wad://host:7443/a\" --name hacked", "wad://host:7443/\n" })
            Invalid(invalid);
        Invalid("wad://host:7443/short-code");
        var cli = ClientCommandLine.Parse(["--data-dir", Path.GetFullPath("artifacts"), "--probe", "wad://host:7443/" + code]);
        check(cli.Link?.InviteCode == code && cli.Command == ClientCommand.Probe, "Automation can probe a positional wad connection link");
        try
        {
            WadProtocol.NormalizeActivationArguments(["--data-dir", Path.GetFullPath("artifacts"), "--open-uri", "wad://host:7443", "--name", "injected"]);
            throw new InvalidOperationException("Protocol activation accepted injected setup arguments.");
        }
        catch (ArgumentException) { check(true, "Windows protocol activation cannot append arbitrary setup options"); }
        var root = Path.GetFullPath(Path.Combine("artifacts", "client-setup-tests", Guid.NewGuid().ToString("N")));
        var path = Path.Combine(root, "client.json");
        PrivateStorage.SecureDirectory(root);
        var settings = ClientSettings.Create("Before setup");
        settings.SetupComplete = false;
        settings.AttachPath(path);
        var id = settings.DeviceId;
        var publicKey = settings.PublicKey;
        settings.AddServer("127.0.0.1", 7443, code);
        check(!File.Exists(path), "Opening a connection link before web setup keeps the initial identity in memory");
        settings.UpdateDevice("My chosen laptop", "N:\\");
        var saved = ClientSettings.Load(path);
        check(saved.SetupComplete && saved.DeviceName == "My chosen laptop" && saved.DeviceId == id && saved.PublicKey == publicKey,
            "Web setup saves the chosen name and shared drive without changing the device identity");
        check(!File.ReadAllText(path, Encoding.UTF8).Contains(code) && saved.ForServer(saved.ServerSnapshot()[0]).GetInviteCode() == code,
            "Pending invitation credentials persist only as machine-protected ciphertext");
        saved.AddServer("127.0.0.1", 7443, null);
        check(saved.ForServer(saved.ServerSnapshot()[0]).GetInviteCode() is null,
            "Opening a plain connection link clears a previous invitation so manual approval remains available");
        saved.RemoveServer("127.0.0.1", 7443);
        saved = ClientSettings.Load(path);
        check(saved.SetupComplete && saved.ServerSnapshot().Length == 0 && saved.Host.Length == 0 && saved.DeviceId == id,
            "Removing the last server persists an empty configured drive without resurrecting a legacy endpoint");
    }
}
