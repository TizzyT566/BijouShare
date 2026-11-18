using System.Diagnostics;
using System.Net;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting.WindowsServices;
using BijouShare.Server;
using BijouShare.Shared;

try
{
    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("BijouShare requires Windows.");
    if (args.Contains("--help") || args.Contains("-h"))
    {
        Console.WriteLine("""
            BijouShare.Server — Windows LAN file server and administration UI

            BijouShare.Server.exe [--data-dir <absolute-directory>] [configuration options]
            BijouShare.Server.exe --init-admin [--data-dir <absolute-directory>]
            BijouShare.Server.exe --self-test
            BijouShare.Server.exe --benchmark [--benchmark-output <report.json>]
            BijouShare.Server.exe --create-test-fixture <new-directory>

            Run without arguments to start the server and open first-time setup in its local web UI.
            --init-admin opens the same setup/sign-in page; existing credentials are not reset.
            --no-browser starts without opening a browser (for services and diagnostics).
            Administration defaults to http://127.0.0.1:5080; encrypted file traffic uses TCP 7443.
            Configuration examples: --Server:Port 7443 --Server:ListenAddress 0.0.0.0 --urls http://127.0.0.1:5080
            Stop an installed instance before using the same data directory from another process.
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
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        Args = args.Where(argument => argument is not ("--init-admin" or "--no-browser")).ToArray(),
        ContentRootPath = AppContext.BaseDirectory
    });
    builder.WebHost.ConfigureKestrel(server => server.Limits.MaxRequestBodySize = 128 * 1024);
    var options = builder.Configuration.GetSection("Server").Get<ServerOptions>() ?? new();
    if (dataArgument is not null)
        options.DataDirectory = dataArgument;
    using var storageLease = StorageLease.Acquire(options.DataDirectory, includeLocalService: true);
    var store = new StateStore(options);
    builder.Services.AddWindowsService(o => o.ServiceName = "BijouShare.Server");
    builder.Services.AddSingleton(options);
    builder.Services.AddSingleton(store);
    builder.Services.AddSingleton<AuditLog>();
    builder.Services.AddSingleton<FileService>();
    builder.Services.AddHostedService<FileServer>();
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
    var app = builder.Build();
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
    if ((!store.IsInitialized || args.Contains("--init-admin")) && !args.Contains("--no-browser") && !WindowsServiceHelpers.IsWindowsService())
        app.Lifetime.ApplicationStarted.Register(() => OpenManagementBrowser(app.Urls));
    await app.RunAsync();
    return Environment.ExitCode;
}
catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException or
    System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or PlatformNotSupportedException)
{
    Console.Error.WriteLine($"BijouShare.Server: {ex.Message}");
    return 1;
}

static void OpenManagementBrowser(IEnumerable<string> addresses)
{
    var url = addresses.Select(value => Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null)
        .FirstOrDefault(uri => uri is not null && (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address)))?.AbsoluteUri;
    if (url is null)
    {
        Console.WriteLine("Complete server setup from a loopback web endpoint on this computer.");
        return;
    }
    Console.WriteLine($"Server management: {url}");
    try
    {
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }
    catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
    {
        Console.WriteLine($"Open server management in your browser: {url}");
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
