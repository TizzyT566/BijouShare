using BijouShare.Shared;
using Microsoft.AspNetCore.DataProtection;

namespace BijouShare.Client;

internal static class ClientWorkerHost
{
    internal static async Task<int> RunAsync(ClientSettings settings, string directory, ClientCommandLine commandLine,
        CancellationToken cancellationToken = default)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory });
        builder.WebHost.UseUrls($"http://127.0.0.1:{settings.ManagementPort}");
        builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 8192);
        var access = new ClientManagementAccess();
        builder.Services.AddSingleton(access);
        builder.Services.AddSingleton(settings);
        builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(directory, "web-keys")))
            .ProtectKeysWithDpapi(false).SetApplicationName("BijouShare.Client");
        builder.Services.AddSingleton<DriveConnections>();
        builder.Services.AddHostedService<DriveWorker>();
        ClientManagementWeb.AddServices(builder.Services);
        await using var host = builder.Build();
        access.RequireOwner(host);
        ClientManagementWeb.Map(host);
        using var tray = commandLine.NoBrowser ? null : ClientTray.StartForSession(directory, Environment.ProcessId,
            access.LaunchUrl, commandLine.SessionWorker ? null : host.Lifetime.StopApplication);
        if (tray is not null)
            host.Services.GetRequiredService<DriveConnections>().InviteRequired += (drive, address) =>
                tray.ShowWarning(ClientTray.InviteRequiredNotice(drive, address));

        await host.StartAsync(cancellationToken);
        var address = host.Urls.Single();
        access.Listen(address);
        Console.WriteLine($"Client management: {address}");
        WadProtocol.RegisterOnLaunch(commandLine);
        if (tray is not null)
            WindowsTrayIcon.DetachPrivateConsole();
        if (commandLine.Command == ClientCommand.OpenManagement)
            ClientTray.OpenFromShortcut(await access.LaunchUrl(cancellationToken));
        await host.WaitForShutdownAsync(cancellationToken);
        return Environment.ExitCode;
    }
}
