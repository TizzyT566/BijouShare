using System.Net.Sockets;

namespace BijouShare.Server;

internal sealed record ServerPorts(int FilePort, int? WebPort);
internal sealed record PortUpdate(int FilePort, int? WebPort, int ExpectedFilePort, int? ExpectedWebPort);

internal sealed class ServerPortSettings(ServerOptions options, FileServer files, WebPortListener web,
    StateStore store, AuditLog audit)
{
    private readonly SemaphoreSlim changes = new(1, 1);
    public ServerPorts Current => new(options.Port, web.CurrentPort);

    internal static bool IsDirectWebEndpoint(HttpContext context, int? currentPort)
    {
        if (currentPort is null || context.Connection.LocalPort != currentPort)
            return false;
        var request = context.Request;
        var hostPort = request.Host.Port ?? (request.IsHttps ? 443 : 80);
        var origin = request.Headers.Origin.ToString();
        return hostPort == currentPort && (origin.Length == 0 ||
            Uri.TryCreate(origin, UriKind.Absolute, out var source) &&
            source.Port == currentPort && source.Scheme.Equals(request.Scheme, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<IResult> SaveAsync(PortUpdate update, HttpContext context)
    {
        await changes.WaitAsync(context.RequestAborted);
        try
        {
            var current = Current;
            if (current != new ServerPorts(update.ExpectedFilePort, update.ExpectedWebPort))
                return Results.Conflict(new { error = "The port settings have changed. Reload Settings and try again." });
            if (update.FilePort is < 1 or > 65535 || update.WebPort is < 1 or > 65535)
                return Results.BadRequest(new { error = "Enter a port between 1 and 65535 for each listener." });
            if (update.FilePort == update.WebPort)
                return Results.BadRequest(new { error = "Choose different ports for file sharing and the web UI." });

            var fileChanged = current.FilePort != update.FilePort;
            var webChanged = current.WebPort != update.WebPort;
            if (!fileChanged && !webChanged)
                return Results.Ok(current);
            if (webChanged && (!web.CanChangePort || update.WebPort is null))
                return Results.BadRequest(new { error = "This web listener is managed by the server's hosting configuration." });
            if (webChanged && !IsDirectWebEndpoint(context, current.WebPort))
                return Results.BadRequest(new { error = "Open the web UI directly from the server tray icon to change its port." });
            if (webChanged && IsBlockedBrowserPort(update.WebPort!.Value))
                return Results.BadRequest(new { error = "Browsers block this web UI port. Choose another port." });

            // Keep the old listeners available until both replacements have bound and the settings are on disk.
            using var fileChange = fileChanged ? files.PreparePort(update.FilePort) : null;
            await using var webChange = webChanged
                ? await web.PrepareAsync(update.WebPort!.Value, context.RequestAborted) : null;
            var previous = store.Read(s => (s.FilePort, s.WebPort));
            try
            {
                store.SavePorts(fileChanged ? update.FilePort : previous.FilePort,
                    webChanged ? update.WebPort : previous.WebPort);
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return Results.Json(new { error = "Could not save the port settings. Check the server data directory." },
                    statusCode: StatusCodes.Status500InternalServerError);
            }
            fileChange?.Commit();
            webChange?.Commit(context.Response);
            audit.Write(context.User.Identity!.Name!, "ChangePorts",
                $"File {current.FilePort} → {update.FilePort}, web {current.WebPort} → {update.WebPort}");
            return Results.Ok(Current);
        }
        catch (SocketException)
        {
            return Results.Conflict(new { error = $"Cannot listen on file port {update.FilePort}. Choose an available port." });
        }
        catch (IOException)
        {
            return Results.Conflict(new { error = $"Cannot start the web UI on port {update.WebPort}. Choose an available port." });
        }
        finally { changes.Release(); }
    }

    // HTTP(S) requests to these ports are blocked by the Fetch standard, including top-level navigation.
    // https://fetch.spec.whatwg.org/#port-blocking
    private static bool IsBlockedBrowserPort(int port) => port is
        1 or 7 or 9 or 11 or 13 or 15 or 17 or 19 or 20 or 21 or 22 or 23 or 25 or 37 or 42 or 43 or 53 or
        69 or 77 or 79 or 87 or 95 or 101 or 102 or 103 or 104 or 109 or 110 or 111 or 113 or 115 or 117 or
        119 or 123 or 135 or 137 or 139 or 143 or 161 or 179 or 389 or 427 or 465 or 512 or 513 or 514 or
        515 or 526 or 530 or 531 or 532 or 540 or 548 or 554 or 556 or 563 or 587 or 601 or 636 or 989 or
        990 or 993 or 995 or 1719 or 1720 or 1723 or 2049 or 3659 or 4045 or 4190 or 5060 or 5061 or 6000 or
        6566 or (>= 6665 and <= 6669) or 6679 or 6697 or 10080;
}
