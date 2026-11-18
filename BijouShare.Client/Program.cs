using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting.WindowsServices;
using BijouShare.Client;
using BijouShare.Shared;

try
{
    args = WadProtocol.NormalizeActivationArguments(args);
    var commandLine = ClientCommandLine.Parse(args);
    if (commandLine.Command == ClientCommand.Help)
    {
        Console.WriteLine(ClientCommandLine.Help);
        return 0;
    }

    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("BijouShare requires Windows.");
    if (commandLine.Command == ClientCommand.SelfTest)
        return await ClientSelfTests.RunAsync();

    var directory = commandLine["--data-dir"] ?? PrivateStorage.DefaultDirectory("Client");
    if (!Path.IsPathFullyQualified(directory))
        throw new ArgumentException("--data-dir must be an absolute directory path.");
    directory = Path.GetFullPath(directory);
    if (commandLine.RegisterProtocol)
    {
        WadProtocol.RegisterForCurrentUser(directory);
        Console.WriteLine("Registered wad links for this Windows user.");
        return 0;
    }
    if (commandLine.Link is { } activation && commandLine.Command == ClientCommand.Run &&
        await ClientActivation.TryForwardAsync(directory, activation.ToStringWithInvite()))
    {
        Console.WriteLine("Connection link delivered to the running client.");
        return 0;
    }
    if (commandLine.Command == ClientCommand.Run && commandLine.Link is null && commandLine["--server"] is null &&
        commandLine["--name"] is null && commandLine["--mount"] is null && commandLine["--management-port"] is null && !commandLine.ResetServerTrust)
    {
        var runningUrl = await ClientActivation.TryGetManagementUrlAsync(directory);
        if (runningUrl is not null)
        {
            if (!commandLine.NoBrowser)
            {
                WadProtocol.RegisterForCurrentUser(directory);
                OpenManagementBrowser(runningUrl);
            }
            Console.WriteLine($"Client management: {runningUrl}");
            return 0;
        }
    }
    using var lease = StorageLease.Acquire(directory);
    var path = Path.Combine(directory, "client.json");

    if (commandLine.Command == ClientCommand.CreateDevice)
    {
        var output = Path.GetFullPath(commandLine["--out"] ?? "device-request.json");
        if (output.Equals(path, StringComparison.OrdinalIgnoreCase) ||
            output.Equals(Path.Combine(directory, ".instance.lock"), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The public request output cannot overwrite client settings or the instance lock.");

        var identity = File.Exists(path) ? ClientSettings.Load(path) : ClientSettings.Create(commandLine["--name"] ?? Environment.MachineName);
        if (commandLine["--name"] is { } exportName)
            identity.DeviceName = exportName;
        identity.Save(path);
        PrivateStorage.AtomicWrite(output, Wire.Encode(new EnrollmentRequest(identity.DeviceId, identity.DeviceName, identity.PublicKey)));
        Console.WriteLine($"Public device request: {output}");
        Console.WriteLine($"Device SHA-256 fingerprint: {KeyAgreement.Fingerprint(identity.PublicKey)}");
        return 0;
    }

    var existing = File.Exists(path);
    if (!existing && commandLine.Command == ClientCommand.ImportEnrollment)
        throw new InvalidOperationException("Configure this device before importing legacy enrollment.");
    var settings = existing ? ClientSettings.Load(path) : ClientSettings.Create(commandLine["--name"] ?? Environment.MachineName);
    settings.AttachPath(path);
    if (!existing && commandLine.Command == ClientCommand.Run && commandLine["--server"] is null)
        settings.SetupComplete = false;
    var changed = !existing;
    ServerEndpoint? selectedServer = null;
    if (commandLine["--management-port"] is { } managementPort)
    {
        if (!int.TryParse(managementPort, out var parsed) || parsed is < 1024 or > 65535)
            throw new ArgumentException("--management-port must be between 1024 and 65535.");
        settings.ManagementPort = parsed;
        changed = true;
    }
    if (commandLine["--name"] is { } deviceName && settings.DeviceName != deviceName)
    {
        settings.DeviceName = deviceName;
        changed = true;
    }
    if (commandLine.Link is { } link)
    {
        selectedServer = settings.AddServer(link.Host, link.Port, link.InviteCode);
        changed = true;
    }
    if (commandLine["--server"] is { } server)
    {
        var serverPort = 7443;
        if (commandLine["--port"] is { } port)
        {
            if (!int.TryParse(port, out var parsed) || parsed is < 1 or > 65535)
                throw new ArgumentException("--port must be between 1 and 65535.");
            serverPort = parsed;
        }
        selectedServer = settings.UpsertServer(server, serverPort);
        changed = true;
    }
    if (commandLine["--mount"] is { } mount)
    {
        settings.MountPoint = ClientSettings.NormalizeMountPoint(mount);
        changed = true;
    }
    if (commandLine.ResetServerTrust)
    {
        selectedServer ??= settings.Servers.Count == 1 ? settings.Servers[0] : null;
        if (selectedServer is null)
            throw new ArgumentException("Select the server to reset with --server and --port.");
        settings.ResetServerTrust(selectedServer);
        changed = true;
    }

    if (commandLine.Command == ClientCommand.ImportEnrollment)
    {
        var bundlePath = commandLine["--import-enrollment"]!;
        if (new FileInfo(bundlePath).Length > 8192)
            throw new InvalidDataException("The enrollment bundle exceeds 8 KB.");
        var bundle = Wire.Decode<EnrollmentBundle>(File.ReadAllBytes(bundlePath));
        settings.Enroll(bundle);
        settings.Save(path);
        Console.WriteLine($"Imported existing identity trust for {settings.Host}:{settings.Port}; drive {settings.MountPoint}");
        Console.WriteLine($"Server SHA-256 fingerprint: {KeyAgreement.Fingerprint(settings.ServerPublicKey)}");
        return 0;
    }

    settings.Validate(requireEnrollment: commandLine.Command == ClientCommand.Probe);
    if (changed && settings.SetupComplete)
        settings.Save(path);
    if (commandLine.Command == ClientCommand.Probe)
    {
        using var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var results = await Task.WhenAll(settings.ServerSnapshot().Select(async endpoint =>
        {
            using var connection = new RemoteConnection(settings.ForServer(endpoint), loggerFactory.CreateLogger<RemoteConnection>());
            long offset = 0;
            var count = 0;
            try
            {
                while (true)
                {
                    var response = (await connection.CallAsync(new()
                    {
                        Operation = "List",
                        Offset = offset
                    })).Response;
                    if (offset == 0)
                        Console.WriteLine($"{endpoint.FolderName ?? endpoint.Host}: authenticated device {connection.DeviceName}. Visible shares:");
                    foreach (var entry in response.Entries ?? throw new InvalidDataException("Server returned an invalid share listing."))
                    {
                        Console.WriteLine($"  {endpoint.FolderName ?? endpoint.Host}\\{entry.Name} ({entry.Permissions})");
                        count++;
                    }
                    if (!response.More)
                        break;
                    if (response.Length <= offset)
                        throw new InvalidDataException("The server directory listing did not advance.");
                    offset = response.Length;
                }
                Console.WriteLine($"{endpoint.FolderName ?? endpoint.Host}: {count} visible share(s).");
                return (Status: 0, Count: count);
            }
            catch (RemoteException ex) when (ex.Code is "PendingApproval" or "DeviceRejected" or "DeviceBlocked")
            {
                Console.WriteLine(ex.Code == "PendingApproval"
                    ? $"{endpoint.Name}: This device is awaiting administrator approval on the server."
                    : $"{endpoint.Name}: This device was rejected or blocked. An administrator must explicitly approve or enable it.");
                return (Status: ex.Code == "PendingApproval" ? 2 : 3, Count: 0);
            }
            catch (Exception ex) when (ex is IOException or CryptographicException or InvalidOperationException)
            {
                Console.Error.WriteLine($"{endpoint.Name}: {ex.Message}");
                return (Status: 1, Count: 0);
            }
        }));
        if (results.Any(result => result.Status == 0))
        {
            Console.WriteLine($"{results.Sum(result => result.Count)} visible share(s) across configured servers.");
            return 0;
        }
        return results.Any(result => result.Status == 2) ? 2 : results.Any(result => result.Status == 3) ? 3 : 1;
    }

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory });
    builder.WebHost.UseUrls($"http://127.0.0.1:{settings.ManagementPort}");
    builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 8192);
    builder.Services.AddWindowsService(o => o.ServiceName = "BijouShare.Client");
    builder.Services.AddSingleton(settings);
    builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(directory, "web-keys")))
        .ProtectKeysWithDpapi(true).SetApplicationName("BijouShare.Client");
    builder.Services.AddSingleton<MultiServerConnection>();
    builder.Services.AddSingleton<IRemoteConnection>(services => services.GetRequiredService<MultiServerConnection>());
    builder.Services.AddSingleton<DriveOperations>();
    builder.Services.AddHostedService<DriveWorker>();
    ClientManagementWeb.AddServices(builder.Services);
    using var host = builder.Build();
    ClientManagementWeb.Map(host);
    var managementUrl = $"http://127.0.0.1:{settings.ManagementPort}";
    Console.WriteLine($"Client management: {managementUrl}");
    var interactive = !WindowsServiceHelpers.IsWindowsService();
    if (interactive && !commandLine.NoBrowser && (args.Length == 0 || !settings.SetupComplete || commandLine.Link is not null))
    {
        WadProtocol.RegisterForCurrentUser(directory);
        host.Lifetime.ApplicationStarted.Register(() => OpenManagementBrowser(managementUrl));
    }
    await host.RunAsync();
    return Environment.ExitCode;
}

catch (RemoteException ex) when (ex.Code is "PendingApproval" or "DeviceRejected" or "DeviceBlocked")
{
    Console.WriteLine(ex.Code == "PendingApproval"
        ? "This device is awaiting administrator approval on the server. Approve it, assign groups, then connect again."
        : "This device was rejected or blocked by the server administrator. It stays blocked until explicitly approved or enabled.");
    return ex.Code == "PendingApproval" ? 2 : 3;
}
catch (Exception ex) when (!args.Contains("--self-test") && ex is IOException or UnauthorizedAccessException or
    ArgumentException or InvalidOperationException or CryptographicException or System.Text.Json.JsonException or PlatformNotSupportedException)
{
    Console.Error.WriteLine($"BijouShare client: {ex.Message}");
    return 1;
}

static void OpenManagementBrowser(string url)
{
    try
    {
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }
    catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
    {
        Console.WriteLine($"Open the client management UI in your browser: {url}");
    }
}
