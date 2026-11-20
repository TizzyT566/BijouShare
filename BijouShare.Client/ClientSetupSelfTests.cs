using System.Text;
using BijouShare.Shared;
using Microsoft.Extensions.Logging.Abstractions;

namespace BijouShare.Client;

internal static class ClientSetupSelfTests
{
    internal static async Task ActivationHandoff(Action<bool, string> check)
    {
        var directory = Path.Combine(Path.GetTempPath(), "BijouShare-protocol-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "client.json");
        var settings = ClientSettings.Create("Before setup");
        settings.SetupComplete = false;
        settings.AttachPath(path);
        using var connections = new DriveConnections(settings, NullLoggerFactory.Instance);
        var management = new ClientManagement(settings, connections, new ClientDriveState());
        var access = new ClientManagementAccess();
        access.Listen("http://127.0.0.1:12345");
        using var pump = new ClientActivation(settings, management, access, NullLogger<ClientActivation>.Instance);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var link = new WadUri("first-host", 7443, new string('1', 64), new string('s', 32));
        Task listener = Task.CompletedTask;
        try
        {
            var osActivation = WadProtocol.ParseActivation(["--open-uri", link.ToStringWithInvite()]);
            check(osActivation == link && WadProtocol.ParseActivation([link.ToStringWithInvite()]) is null,
                "Only a Windows protocol activation enters the short-lived launcher");
            var firstLaunch = ClientActivation.WaitForRunningClientAsync(directory, deadline.Token);
            await ClientActivation.DeliverProtocolLinkAsync(directory, link, start =>
            {
                check(start.FileName == Path.Combine(AppContext.BaseDirectory, "BijouShare.Client.exe") &&
                    start.ArgumentList.Count == 0 && start.Arguments.Length == 0 && !start.UseShellExecute && start.CreateNoWindow,
                    "A cold URI activation starts the installed client with no URI or invite in its command line");
                listener = Task.Run(async () =>
                {
                    await Task.Delay(700, deadline.Token);
                    await pump.StartAsync(deadline.Token);
                });
            }, deadline.Token);
            await listener;
            check((await firstLaunch).ManagementUrl == await access.LaunchUrl(deadline.Token),
                "A concurrent desktop launch waits for the profile owner's authenticated console");
            var running = await ClientActivation.TryGetRunningClientAsync(directory, deadline.Token);
            check(running is not null && running.ProcessId == Environment.ProcessId && running.ManagementUrl == await access.LaunchUrl(deadline.Token),
                "A desktop tray attaches to the verified profile owner and obtains its private console URL");
            using (var iconClaim = ClientTray.ClaimSession(directory, Environment.ProcessId))
            using (var duplicate = ClientTray.ClaimSession(directory, Environment.ProcessId))
            {
                check(iconClaim is not null && duplicate is null, "A second client launch shares the existing tray icon in this Windows session");
                var opened = new List<string>();
                await ClientTray.AttachAsync(directory, running!, ClientCommandLine.Parse(["--open-management"]), opened.Add).WaitAsync(deadline.Token);
                await ClientTray.AttachAsync(directory, running!, ClientCommandLine.Parse([]), opened.Add).WaitAsync(deadline.Token);
                check(opened.Count == 1 && opened[0] == running!.ManagementUrl,
                    "The Start menu opens the owner's console even with an existing tray, while ordinary launches leave the browser alone");
            }
            using (var reclaimed = ClientTray.ClaimSession(directory, Environment.ProcessId))
                check(reclaimed is not null, "A replacement client can claim the tray after its previous owner exits");
            var warm = new WadUri("second-host", 7443, new string('2', 64), new string('t', 32));
            await ClientActivation.DeliverProtocolLinkAsync(directory, warm,
                _ => throw new InvalidOperationException("A warm URI activation started another client."), deadline.Token);
            var saved = ClientSettings.Load(path);
            check(!saved.SetupComplete && saved.DriveSnapshot().Length == 0 && connections.Snapshot().Length == 0 &&
                saved.Servers.Count == 2 && saved.ForServer(saved.Servers[0]).GetInviteCode() == link.InviteCode &&
                saved.ForServer(saved.Servers[1]).GetInviteCode() == warm.InviteCode &&
                !File.ReadAllText(path).Contains(link.InviteCode!, StringComparison.Ordinal),
                "Cold and warm activations wait for a private-pipe acknowledgment after saving the protected invite with no mounted drive");
        }
        finally
        {
            await pump.StopAsync(CancellationToken.None);
            if (File.Exists(path))
                File.Delete(path);
            Directory.Delete(directory);
        }
    }

    public static void Run(Action<bool, string> check)
    {
        check(ClientCommandLine.Parse(["--open-management"]).Command == ClientCommand.OpenManagement &&
            ClientCommandLine.Parse([]).Command == ClientCommand.Run,
            "Opening the client console after installation is independent of ordinary tray startup");
        try
        {
            ClientCommandLine.Parse(["--open-management", "--mount", @"N:\"]);
            throw new InvalidOperationException("Console activation accepted options that could modify the profile.");
        }
        catch (ArgumentException) { check(true, "One-shot console activation rejects setup and drive options"); }
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
        var fingerprint = new string('d', 64);
        var link = WadUri.Parse($"wad://fileserver:7443/{fingerprint}#{code}");
        check(link.Host == "fileserver" && link.Port == 7443 && link.InviteCode == code && !link.ToString().Contains(code),
            "Connection links parse invite enrollment without exposing the credential in diagnostic strings");
        check(WadUri.Parse("wad://[::1]:7443/" + fingerprint).Host == "::1" && WadUri.Parse("WAD://192.168.1.10:7443/" + fingerprint).InviteCode is null,
            "Connection links support IPv4, bracketed IPv6, and links without an invite");
        foreach (var invalid in new[] { "https://host:7443/code", "wad://host", "wad://host:0", "wad://host:65536", "wad://user@host:7443", "wad://host:7443/a/b", "wad://host:7443/../abc", "wad://host:7443/%61", "wad://host:7443/a?b", "wad://host:7443/a#b", "wad://host:7443/a\" --name hacked", "wad://host:7443/\n" })
            Invalid(invalid);
        Invalid("wad://host:7443/short-code");
        Invalid($"wad://host:7443/{code}#{fingerprint}");
        Invalid($"wad://host:7443/{fingerprint}#short");
        var pinnedLink = $"wad://host:7443/{fingerprint}#{code}";
        var cli = ClientCommandLine.Parse(["--data-dir", Path.GetFullPath("artifacts"), "--probe", pinnedLink]);
        check(cli.Link?.InviteCode == code && cli.Link.TrustedServerId == fingerprint && cli.Link.ToStringWithInvite() == pinnedLink &&
            cli.Command == ClientCommand.Probe, "Probe and local activation retain the full server trust anchor carried by an invite");
        Invalid("wad://host:7443/" + fingerprint[..16]);
        Invalid("wad://host:7443/" + fingerprint.ToUpperInvariant());
        try
        {
            WadProtocol.ParseActivation(["--data-dir", Path.GetFullPath("artifacts"), "--open-uri", "wad://host:7443", "--name", "injected"]);
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
        try
        {
            settings.AddServer("127.0.0.1", 7443, code);
            throw new InvalidOperationException("Saved an invitation without a recipient fingerprint.");
        }
        catch (ArgumentException) { check(settings.Servers.Count == 0, "New server enrollment requires a full fingerprint before saving an invite"); }
        settings.AddServer("127.0.0.1", 7443, code, trustedServerId: fingerprint);
        settings = ClientSettings.Load(path);
        check(!settings.SetupComplete && settings.DriveSnapshot().Length == 0 && settings.DeviceId == id && settings.PublicKey == publicKey &&
            settings.ForServer(settings.ServerSnapshot().Single()).GetInviteCode() == code && !File.ReadAllText(path).Contains(code, StringComparison.Ordinal),
            "A pre-setup connection link retains its pinned server and protected invite while no drives are configured");
        settings.UpdateDevice("My chosen laptop");
        var saved = ClientSettings.Load(path);
        check(saved.SetupComplete && saved.DriveSnapshot().Length == 0 && saved.DeviceName == "My chosen laptop" &&
            saved.DeviceId == id && saved.PublicKey == publicKey,
            "Name-only setup persists zero drives and retains the device identity");
        check(!File.ReadAllText(path, Encoding.UTF8).Contains(code) && saved.ForServer(saved.ServerSnapshot()[0]).GetInviteCode() == code,
            "Pending invitation credentials persist only as current-user protected ciphertext");
        saved.AddServer("127.0.0.1", 7443, null, trustedServerId: fingerprint);
        check(saved.ForServer(saved.ServerSnapshot()[0]).GetInviteCode() is null &&
            saved.ServerSnapshot()[0].TrustedServerId == fingerprint,
            "A link without an invite clears the earlier invitation and retains the expected fingerprint");
        saved.AddServer("127.0.0.1", 7443, code, trustedServerId: fingerprint);
        try
        {
            saved.AddServer("127.0.0.1", 7443, null, trustedServerId: new string('e', 64));
            throw new InvalidOperationException("Replaced a queued server fingerprint.");
        }
        catch (ArgumentException)
        {
            saved = ClientSettings.Load(path);
            var queued = saved.ServerSnapshot().Single();
            check(queued.TrustedServerId == fingerprint && saved.ForServer(queued).GetInviteCode() == code,
                "Conflicting connection links preserve the queued fingerprint and invite");
        }
        saved.AddServer("127.0.0.1", 7443, null);
        check(saved.ForServer(saved.ServerSnapshot()[0]).GetInviteCode() is null && saved.ServerSnapshot()[0].TrustedServerId == fingerprint,
            "A plain connection link clears the earlier invite and retains verified trust");
        saved.AddDrive("N:", "Primary");
        check(saved.ServerSnapshot(@"N:\").Length == 1, "The first explicit drive receives the staged server");
        saved.RemoveServer("127.0.0.1", 7443);
        saved = ClientSettings.Load(path);
        check(saved.SetupComplete && saved.ServerSnapshot().Length == 0 && saved.DeviceId == id,
            "Removing the last server persists an empty configured drive");
        saved.AddDrive("P:", "Archive");
        saved.AddServer("nas", 7443, null, trustedServerId: fingerprint);
        try
        {
            saved.AddServer("NAS", 7443, code, "P:", new string('e', 64));
            throw new InvalidOperationException("Saved a conflicting server identity on a second drive.");
        }
        catch (ArgumentException)
        {
            check(saved.ServerSnapshot("P:\\").Length == 0 && saved.ServerSnapshot("N:\\").Single().TrustedServerId == fingerprint,
                "A link on another drive cannot replace or bypass an existing endpoint fingerprint");
        }
        saved.AddServer("archive", 7443, null, "P:", new string('a', 64));
        saved = ClientSettings.Load(path);
        check(saved.ServerSnapshot("N:\\").Single().Host == "nas" && saved.ServerSnapshot("P:\\").Single().Host == "archive",
            "Restart preserves the server namespace assigned to each drive");
        saved.RemoveServer("nas", 7443);
        saved.RemoveDrive("N:");
        saved = ClientSettings.Load(path);
        check(saved.DriveSnapshot().SequenceEqual(["P:\\"]) && saved.GetDriveName("P:") == "Archive" &&
            saved.DriveNames.Count == 1 && saved.ServerSnapshot("P:\\").Single().Host == "archive",
            "Removing the empty primary drive preserves the promoted drive's name and servers");
        var legacy = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        legacy.Remove("driveNames");
        File.WriteAllText(path, legacy.ToJsonString());
        saved = ClientSettings.Load(path);
        check(saved.GetDriveName("P:") == ClientSettings.DefaultDriveName,
            "Existing profiles without labels retain the original BijouShare volume name");
    }
}
