using System.Net;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace BijouShare.Client;

public static class ClientManagementWeb
{
    public sealed record DeviceUpdate(string DeviceName, string MountPoint);
    public sealed record ServerRequest(string? Uri = null, string? Host = null, int Port = 7443, string? InviteCode = null);
    public sealed record ServerRemoval(string Host, int Port);

    public static void AddServices(IServiceCollection services)
    {
        services.AddSingleton<ClientDriveState>();
        services.AddSingleton<ClientManagement>();
        services.AddHostedService<ClientActivation>();
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.Cookie.Name = "BijouShare.Client.Csrf";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });
    }

    public static void Map(WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'";
            var remote = context.Connection.RemoteIpAddress;
            var host = context.Request.Host.Host;
            var localHost = host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                IPAddress.TryParse(host.Trim('[', ']'), out var hostIp) && IPAddress.IsLoopback(hostIp);
            var expectedOrigin = context.Request.Scheme + "://" + context.Request.Host;
            var origin = context.Request.Headers.Origin.ToString();
            if (remote is null || !IPAddress.IsLoopback(remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote) || !localHost ||
                origin.Length > 0 && !origin.Equals(expectedOrigin, StringComparison.OrdinalIgnoreCase) ||
                context.Request.Headers["Sec-Fetch-Site"] == "cross-site")
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Client management is available from this computer only."
                });
                return;
            }
            if (context.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(context.Request.Method))
            {
                try
                {
                    await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);
                }
                catch (AntiforgeryValidationException)
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Refresh the page before making changes."
                    });
                    return;
                }
            }
            await next();
        });
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.MapGet("/api/session", (HttpContext context, IAntiforgery antiforgery) => Results.Ok(new
        {
            csrfToken = antiforgery.GetAndStoreTokens(context).RequestToken
        }));
        app.MapGet("/api/state", (ClientManagement management) => Results.Ok(management.Snapshot()));
        app.MapPut("/api/device", (DeviceUpdate update, ClientManagement management, CancellationToken token) =>
            Change(async () => await management.UpdateDeviceAsync(update.DeviceName, update.MountPoint, token), management));
        app.MapPost("/api/servers", (ServerRequest request, ClientManagement management, CancellationToken token) =>
            Change(async () =>
            {
                var link = request.Uri is { Length: > 0 } uri ? WadUri.Parse(uri)
                    : new WadUri(request.Host ?? throw new ArgumentException("Enter a server link or host."), request.Port, request.InviteCode);
                await management.AddServerAsync(link, token);
            }, management));
        app.MapPost("/api/servers/remove", (ServerRemoval request, ClientManagement management, CancellationToken token) =>
            Change(async () => await management.RemoveServerAsync(request.Host, request.Port, token), management));
        app.MapPost("/api/refresh", (ClientManagement management, CancellationToken token) =>
            Change(async () => { await management.RefreshAsync(token); }, management));
    }

    private static async Task<IResult> Change(Func<Task> change, ClientManagement management)
    {
        try
        {
            await change();
            return Results.Ok(management.Snapshot());
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidDataException)
        {
            return Results.BadRequest(new
            {
                error = exception.Message
            });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            return Results.BadRequest(new
            {
                error = "Cannot save the client configuration. Check the service account and data directory."
            });
        }
    }
}
