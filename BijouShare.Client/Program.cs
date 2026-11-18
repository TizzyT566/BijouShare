using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting.WindowsServices;
using BijouShare.Client;
using BijouShare.Shared;

try
{
    var protocolLink = WadProtocol.ParseActivation(args);
    var commandLine = ClientCommandLine.Parse(protocolLink is null ? args : []);
    if (commandLine.Command == ClientCommand.Help)
    {
        Console.WriteLine(ClientCommandLine.Help);
        return 0;
    }

    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("BijouShare requires Windows.");
    if (commandLine.Command == ClientCommand.SelfTest)
        return await ClientSelfTests.RunAsync();
    if (commandLine.Command == ClientCommand.OpenManagement)
    {
        await ClientActivation.OpenManagementAsync(UserProfileStorage.Resolve(null), ClientTray.OpenBrowser);
        return 0;
    }

    if (WindowsServiceHelpers.IsWindowsService())
    {
        var service = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory
        });
        service.Services.AddWindowsService(o => o.ServiceName = "BijouShare.Client");
        service.Services.AddHostedService(provider => new UserSessionLauncher(
            provider.GetRequiredService<ILogger<UserSessionLauncher>>(), commandLine.NoBrowser));
        using var broker = service.Build();
        await broker.RunAsync();
        return 0;
    }

    var directory = UserProfileStorage.Resolve(commandLine["--data-dir"]);
    if (protocolLink is not null)
    {
        await ClientActivation.DeliverProtocolLinkAsync(directory, protocolLink);
        return 0;
    }
    if (commandLine.RegisterProtocol)
    {
        WadProtocol.RegisterForCurrentUser();
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
        commandLine["--name"] is null && commandLine["--mount"] is null && commandLine["--management-port"] is null)
    {
        var running = await ClientActivation.TryGetRunningClientAsync(directory);
        if (running is not null)
        {
            WadProtocol.RegisterOnLaunch(commandLine);
            await ClientTray.AttachAsync(directory, running, commandLine);
            return 0;
        }
    }
    using var lease = UserProfileStorage.Acquire(directory);
    var path = Path.Combine(directory, "client.json");

    var existing = File.Exists(path);
    var settings = existing ? ClientSettings.Load(path) : ClientSettings.Create(commandLine["--name"] ?? Environment.UserName);
    settings.AttachPath(path);
    if (!existing && commandLine.Command == ClientCommand.Run && commandLine["--server"] is null)
        settings.SetupComplete = false;
    var changed = !existing;
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
    string? targetDrive = null;
    if (commandLine["--mount"] is { } mount)
    {
        targetDrive = ClientSettings.NormalizeMountPoint(mount);
        if (!settings.DriveSnapshot().Contains(targetDrive))
        {
            if (!settings.SetupComplete)
                throw new ArgumentException("Complete device setup before adding a drive.");
            if (!ClientManagement.AvailableDriveLetters().Contains(targetDrive))
                throw new ArgumentException("That drive letter is already in use.");
            settings.AddDrive(targetDrive);
            changed = true;
        }
    }
    if (commandLine.Link is { } link)
    {
        settings.AddServer(link.Host, link.Port, link.InviteCode, targetDrive, link.TrustedServerId);
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
        settings.AddServer(server, serverPort, null, targetDrive, commandLine["--server-id"], preserveInvite: true);
        changed = true;
    }

    settings.Validate(requireEnrollment: commandLine.Command == ClientCommand.Probe);
    if (changed)
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
                    {
                        Console.WriteLine($"{endpoint.FolderName ?? endpoint.Host}: authenticated device {connection.DeviceName}. Visible shares:");
                    }
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
    var managementAccess = new ClientManagementAccess();
    builder.Services.AddSingleton(managementAccess);
    builder.Services.AddSingleton(settings);
    builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(directory, "web-keys")))
        .ProtectKeysWithDpapi(false).SetApplicationName("BijouShare.Client");
    builder.Services.AddSingleton<DriveConnections>();
    builder.Services.AddHostedService<DriveWorker>();
    ClientManagementWeb.AddServices(builder.Services);
    using var host = builder.Build();
    managementAccess.RequireOwner(host);
    ClientManagementWeb.Map(host);
    using var trayPresence = commandLine.NoBrowser ? null : ClientTray.ClaimSession(directory, Environment.ProcessId);
    await host.StartAsync();
    var address = host.Urls.Single();
    managementAccess.Listen(address);
    Console.WriteLine($"Client management: {address}");
    WadProtocol.RegisterOnLaunch(commandLine);
    using var tray = trayPresence is null ? null : ClientTray.Start(
        () => managementAccess.LaunchUrl(host.Lifetime.ApplicationStopping).GetAwaiter().GetResult(),
        commandLine.SessionWorker ? null : host.Lifetime.StopApplication);
    await host.WaitForShutdownAsync();
    return Environment.ExitCode;
}

catch (RemoteException ex) when (ex.Code is "PendingApproval" or "DeviceRejected" or "DeviceBlocked")
{
    Console.WriteLine(ex.Code == "PendingApproval"
        ? "This device is awaiting administrator approval on the server. Approve it, assign groups, then connect again."
        : "This device was rejected or blocked by the server administrator. It stays blocked until explicitly approved or enabled.");
    return ex.Code == "PendingApproval" ? 2 : 3;
}
catch (Exception ex) when (!args.Contains("--self-test") && ex is IOException or InvalidDataException or OperationCanceledException or UnauthorizedAccessException or
    ArgumentException or InvalidOperationException or CryptographicException or System.Text.Json.JsonException or PlatformNotSupportedException)
{
    Console.Error.WriteLine($"BijouShare client: {ex.Message}");
    return 1;
}
