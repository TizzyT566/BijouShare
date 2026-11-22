using System.Security.Cryptography;
using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Extensions.Hosting.WindowsServices;
using BijouShare.Client;
using BijouShare.Shared;

var startupStage = "opening the Windows user session";
try
{
    if (args.Length > 0 && args[0] == "--elevated-drive")
        return await ElevatedDriveHelper.RunAsync(args);

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
    if (WindowsServiceHelpers.IsWindowsService())
    {
        var service = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory
        });
        service.Services.AddWindowsService(o => o.ServiceName = "BijouShare.Client");
        service.Services.AddHostedService<ElevatedDriveRestoreService>();
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
    var desktopLaunch = commandLine.Command is ClientCommand.Run or ClientCommand.OpenManagement &&
        commandLine.Link is null && commandLine["--server"] is null && commandLine["--name"] is null &&
        commandLine["--mount"] is null && commandLine["--management-port"] is null;
    if (desktopLaunch)
    {
        var running = await ClientActivation.TryGetRunningClientAsync(directory);
        if (running is not null)
        {
            WadProtocol.RegisterOnLaunch(commandLine);
            await ClientTray.AttachAsync(directory, running, commandLine);
            return 0;
        }
    }
    startupStage = "opening the private client profile";
    StorageLease lease;
    try { lease = UserProfileStorage.Acquire(directory); }
    catch (StorageInUseException) when (desktopLaunch)
    {
        // The service and the shortcut can start together, before the winner publishes its pipe.
        var running = await ClientActivation.WaitForRunningClientAsync(directory);
        await ClientTray.AttachAsync(directory, running, commandLine);
        return 0;
    }
    using var profileLifetime = lease;
    var path = Path.Combine(directory, "client.json");

    startupStage = "loading the device identity and settings";
    var existing = File.Exists(path);
    var settings = existing ? ClientSettings.Load(path) : ClientSettings.Create(commandLine["--name"] ?? Environment.UserName);
    settings.AttachPath(path);
    if (!existing && commandLine.Command is ClientCommand.Run or ClientCommand.OpenManagement && commandLine["--server"] is null)
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
            catch (RemoteException ex) when (EnrollmentMessage(ex.Code) is { } message)
            {
                Console.WriteLine($"{endpoint.Name}: {message}");
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

    startupStage = "starting the local web console and drive worker";
    return await ClientWorkerHost.RunAsync(settings, directory, commandLine);
}

catch (RemoteException ex) when (EnrollmentMessage(ex.Code) is { } message)
{
    Console.WriteLine(message);
    return ex.Code == "PendingApproval" ? 2 : 3;
}
catch (Exception ex) when (!args.Contains("--self-test") && ex is IOException or InvalidDataException or OperationCanceledException or UnauthorizedAccessException or
    ArgumentException or InvalidOperationException or CryptographicException or System.Text.Json.JsonException or PlatformNotSupportedException or Win32Exception or System.Security.SecurityException)
{
    Console.Error.WriteLine($"BijouShare client: {ex.Message}");
    if (args is ["--open-management"])
        ClientTray.ShowStartupError(ex.Message);
    if (args.Contains("--session-worker", StringComparer.Ordinal))
    {
        var cause = ex.GetBaseException();
        var code = cause is Win32Exception native ? native.NativeErrorCode : cause.HResult;
        // Application events are readable by other accounts. Leave profile paths, keys and links out.
        try
        {
            EventLog.WriteEntry("BijouShare.Client",
                $"The signed-in client failed while {startupStage} ({cause.GetType().Name}, code 0x{code:X8}). Open BijouShare Client from Start for the error details.",
                EventLogEntryType.Error, 4301);
        }
        catch (Exception loggingError) when (loggingError is Win32Exception or InvalidOperationException or
            IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
    }
    return 1;
}

static string? EnrollmentMessage(string code) => code switch
{
    "InviteRequired" => "This server is invite only. Ask its administrator for a valid invite link.",
    "PendingApproval" => "This device is awaiting administrator approval on the server.",
    "DeviceRejected" or "DeviceBlocked" => "This device was rejected or blocked. An administrator must explicitly approve or enable it.",
    _ => null
};
