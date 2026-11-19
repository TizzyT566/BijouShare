using System.Net;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Hosting.WindowsServices;
using BijouShare.Server;
using BijouShare.Shared;

try
{
    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("BijouShare requires Windows.");
    if (args.Contains("--open-management", StringComparer.Ordinal))
    {
        if (args.Length != 1)
            throw new ArgumentException("Use --open-management by itself to open the installed server's web UI.");
        if (!Environment.UserInteractive || WindowsServiceHelpers.IsWindowsService())
            throw new InvalidOperationException("Open server management from a signed-in Windows session.");
        await ServerTray.OpenInstalledManagementAsync();
        return 0;
    }
    if (args.Contains("--prepare-service-storage", StringComparer.Ordinal))
    {
        if (args.Length != 1)
            throw new ArgumentException("Server storage preparation accepts no options.");
        try
        {
            ServiceStorageSetup.Prepare();
            return 0;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or Win32Exception or
            UnauthorizedAccessException or System.Security.SecurityException or IdentityNotMappedException)
        {
            ReportStorageFailure(error);
            return 1;
        }
    }
    if (args.Contains("--help") || args.Contains("-h"))
    {
        Console.WriteLine("""
            BijouShare.Server — Windows LAN file server and administration UI

            BijouShare.Server.exe [--data-dir <absolute-directory>] [configuration options]
            BijouShare.Server.exe --init-admin [--data-dir <absolute-directory>]
            BijouShare.Server.exe --tray-only
            BijouShare.Server.exe --open-management
            BijouShare.Server.exe --self-test
            BijouShare.Server.exe --benchmark [--benchmark-output <report.json>]
            BijouShare.Server.exe --create-test-fixture <new-directory>

            Interactive runs show a BijouShare Server notification icon. Click it for setup or sign-in.
            --init-admin uses the same tray and setup flow and preserves existing credentials.
            --tray-only shows the icon for the installed server service in your Windows session.
            --open-management opens the installed server's web UI once in your default browser.
            --no-browser runs the server headlessly for services and diagnostics.
            Administration defaults to http://127.0.0.1:5080; encrypted file traffic uses TCP 7443.
            Configuration examples: --Server:Port 7443 --Server:ListenAddress 0.0.0.0 --urls http://127.0.0.1:5080
            """);
        return 0;
    }
    var dataArgument = CommandOption(args, "--data-dir");
    if (args.Count(x => x is "--self-test" or "--init-admin" or "--create-test-fixture" or "--benchmark") > 1)
        throw new ArgumentException("Select only one setup or test command.");
    if (args.Contains("--benchmark"))
        return await PerformanceBenchmarks.RunAsync(CommandOption(args, "--benchmark-output") ?? "artifacts/benchmarks/results.json");
    if (args.Contains("--self-test"))
        return await ServerSelfTests.RunAsync();
    var fixtureIndex = Array.IndexOf(args, "--create-test-fixture");
    if (fixtureIndex >= 0)
    {
        ServerSelfTests.WriteAcceptanceFixture(CommandOption(args, "--create-test-fixture")!);
        return 0;
    }
    var isService = WindowsServiceHelpers.IsWindowsService();
    if (args.Contains("--tray-only") && args.Length != 1)
        throw new ArgumentException("Use --tray-only by itself to open the installed server's notification icon.");
    if (!isService && Environment.UserInteractive &&
        (args.Contains("--tray-only") || (args.All(argument => argument == "--init-admin") && ServerTray.IsInstalledExecutable())))
    {
        var companion = Path.Combine(AppContext.BaseDirectory, "BijouShare.Server.Tray.exe");
        if (File.Exists(companion))
        {
            using var launched = Process.Start(new ProcessStartInfo(companion, "--tray-only") { UseShellExecute = false });
            return 0;
        }
        return ServerTray.RunCompanion();
    }
    if (args.Contains("--tray-only"))
        throw new ArgumentException("Use --tray-only in a signed-in Windows session.");
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        Args = args.Where(argument => argument is not ("--init-admin" or "--no-browser")).ToArray(),
        ContentRootPath = AppContext.BaseDirectory
    });
    builder.WebHost.ConfigureKestrel(server => server.Limits.MaxRequestBodySize = 128 * 1024);
    var options = builder.Configuration.GetSection("Server").Get<ServerOptions>() ?? new();
    if (dataArgument is not null)
        options.DataDirectory = dataArgument;
    var interactive = !isService && Environment.UserInteractive && !args.Contains("--no-browser");
    var firstIcon = true;
    using var iconInstance = interactive ? ServerTray.ClaimStandaloneIcon(options.DataDirectory, out firstIcon) : null;
    if (!firstIcon && args.All(argument => argument is "--init-admin" or "--data-dir" || argument == dataArgument))
        return 0;
    using var storageLease = StorageLease.Acquire(options.DataDirectory, includeLocalService: true);
    var store = new StateStore(options);
    var webPorts = WebPortListener.Configure(builder, store.Read(s => s.WebPort));
    builder.Services.AddWindowsService(o => o.ServiceName = "BijouShare.Server");
    builder.Services.AddSingleton(options);
    builder.Services.AddSingleton(store);
    builder.Services.AddSingleton<AuditLog>();
    builder.Services.AddSingleton<FileService>();
    builder.Services.AddSingleton<FileServer>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<FileServer>());
    builder.Services.AddSingleton<ServerPortSettings>();
    if (isService)
        builder.Services.AddHostedService<ServerTrayEndpoint>();
    builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(store.DataDirectory, "web-keys")))
        .ProtectKeysWithDpapi(true).SetApplicationName("BijouShare.Server");
    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
    {
        o.Cookie.Name = "BijouShare.Admin";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.ExpireTimeSpan = TimeSpan.FromHours(4);
        o.SlidingExpiration = false;
        o.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; };
        o.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        o.Events.OnValidatePrincipal = context =>
        {
            if (!store.Read(s => s.Admin is { } admin && context.Principal?.Identity?.Name == admin.Name &&
                context.Principal.FindFirst("credential")?.Value == AdminApi.CredentialVersion(admin)))
                context.RejectPrincipal();
            return Task.CompletedTask;
        };
    });
    builder.Services.AddAuthorization();
    builder.Services.ConfigureHttpJsonOptions(o =>
    {
        o.SerializerOptions.RespectNullableAnnotations = true;
        o.SerializerOptions.RespectRequiredConstructorParameters = true;
        o.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
        o.SerializerOptions.MaxDepth = 32;
    });
    builder.Services.AddAntiforgery(o =>
    {
        o.HeaderName = "X-CSRF-TOKEN";
        o.Cookie.Name = "BijouShare.Antiforgery";
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });
    builder.Services.AddRateLimiter(o =>
    {
        o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        o.OnRejected = async (context, token) =>
        {
            context.HttpContext.Response.Headers.RetryAfter = "60";
            await context.HttpContext.Response.WriteAsJsonAsync(new
            {
                error = "Too many sign-in attempts. Try again in a minute."
            }, token);
        };
        o.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "local", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 8,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
        o.AddPolicy("setup", context => RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "local", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 32,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    });
    await using var app = builder.Build();
    webPorts.Attach(app.Services.GetRequiredService<IServer>());
    app.Use(async (context, next) =>
    {
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
        context.Response.Headers.CacheControl = "no-cache, no-store";
        context.Response.Headers.Pragma = "no-cache";
        var address = context.Connection.RemoteIpAddress;
        if (address?.IsIPv4MappedToIPv6 == true)
            address = address.MapToIPv4();
        if ((!store.IsInitialized || context.Request.Path.Equals("/api/setup", StringComparison.OrdinalIgnoreCase)) &&
            !ServerSetupSecurity.IsLocalRequest(context))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Complete server setup from a browser on this computer."
            });
            return;
        }
        if (address is not null && !IPAddress.IsLoopback(address) && !context.Request.IsHttps)
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("Remote administration requires HTTPS.");
            return;
        }
        await next();
    });
    app.UseDefaultFiles();
    app.UseStaticFiles();
    app.UseRouting();
    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();
    app.Use(async (context, next) =>
    {
        if (context.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(context.Request.Method))
        {
            try
            {
                await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException) { context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = "Invalid CSRF token. Refresh the page." }); return; }
        }
        await next();
    });
    app.MapAdminApi();
    await app.StartAsync();
    using var tray = interactive ? ServerTray.StartForHost(app) : null;
    await app.WaitForShutdownAsync();
    return Environment.ExitCode;
}
catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException or
    System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or PlatformNotSupportedException)
{
    Console.Error.WriteLine($"BijouShare.Server: {ex.Message}");
    return 1;
}

static void ReportStorageFailure(Exception error)
{
    var native = error.GetBaseException() as Win32Exception;
    var reason = native is null ? error.Message : $"{error.Message} (Windows error {native.NativeErrorCode}: {native.Message})";
    Console.Error.WriteLine($"BijouShare.Server: {reason}");
    int code = native?.NativeErrorCode ?? (error.HResult & 0xffff);
    int id = error switch
    {
        InvalidDataException => 4202,
        UnauthorizedAccessException or System.Security.SecurityException => 4201,
        _ when code == 5 => 4201,
        _ when code is 32 or 33 => 4203,
        _ => 4204
    };
    try
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.IsSystem)
            EventLog.WriteEntry("BijouShare.Server", $"Server storage preparation failed. {reason}", EventLogEntryType.Error, id);
    }
    catch (Exception loggingError) when (loggingError is Win32Exception or InvalidOperationException or
        IOException or UnauthorizedAccessException or System.Security.SecurityException)
    {
        // The MSI must retain the original storage failure even when the event log is unavailable.
    }
}

static string? CommandOption(string[] arguments, string name)
{
    var index = Array.IndexOf(arguments, name);
    if (index < 0)
        return null;
    if (Array.LastIndexOf(arguments, name) != index || index + 1 >= arguments.Length || arguments[index + 1].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(arguments[index + 1]))
        throw new ArgumentException($"{name} requires one value and may appear only once. Use --help for usage.");
    return arguments[index + 1];
}
