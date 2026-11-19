using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting.Server;

namespace BijouShare.Server;

internal static class WebPortSelfTests
{
    internal static async Task RunAsync(Action<bool, string> check)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        // Schannel needs a Windows key container for the test server's TLS credentials.
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pkcs12), null,
            X509KeyStorageFlags.UserKeySet);
        using var handler = new HttpClientHandler
        {
            UseProxy = false,
            ServerCertificateCustomValidationCallback = (_, peer, _, _) => peer?.Thumbprint == certificate.Thumbprint
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

        foreach (var scheme in new[] { "http", "https" })
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls($"{scheme}://127.0.0.1:0");
            builder.WebHost.ConfigureKestrel(options => options.ConfigureHttpsDefaults(https => https.ServerCertificate = certificate));
            var listener = WebPortListener.Configure(builder, null);
            await using var app = builder.Build();
            listener.Attach(app.Services.GetRequiredService<IServer>());
            app.MapGet("/", () => "BijouShare");
            app.MapPost("/change/{port:int}", async (int port, HttpContext context) =>
            {
                await using var pending = await listener.PrepareAsync(port, context.RequestAborted);
                pending.Commit(context.Response);
                return Results.Ok();
            });
            await app.StartAsync();
            try
            {
                var previous = listener.CurrentPort!.Value;
                string Url(int port) => $"{scheme}://127.0.0.1:{port}/";
                using var reservation = new TcpListener(IPAddress.Loopback, 0);
                reservation.Start();
                var next = ((IPEndPoint)reservation.LocalEndpoint).Port;
                if (scheme == "http")
                {
                    try
                    {
                        await using var unexpected = await listener.PrepareAsync(next, CancellationToken.None);
                        throw new InvalidOperationException("An occupied web port was accepted.");
                    }
                    catch (IOException) { }
                    check(listener.CurrentPort == previous && await client.GetStringAsync(Url(previous)) == "BijouShare",
                        "A port owned by another application leaves the original web UI reachable");
                }
                reservation.Stop();
                using var response = await client.PostAsync(Url(previous) + $"change/{next}", null);
                check(response.IsSuccessStatusCode && listener.CurrentPort == next && ServerTray.LocalAddress(app.Urls, listener.CurrentPort)?.Port == next,
                    $"The {scheme.ToUpperInvariant()} Save response completes on the original port and the same console serves the replacement");
                using var reversed = await client.PostAsync(Url(next) + $"change/{previous}", null);
                check(reversed.IsSuccessStatusCode && await client.GetStringAsync(Url(previous)) == "BijouShare",
                    $"An immediate {scheme.ToUpperInvariant()} port reversal serves a fresh listener on the original port");
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                while (app.Urls.Any(url => BindingAddress.Parse(url).Port == next)) await Task.Delay(50, deadline.Token);
                check(ServerTray.LocalAddress(app.Urls, listener.CurrentPort)?.Port == previous,
                    $"The tray resolves the new {scheme.ToUpperInvariant()} port after Kestrel retires the original listener");
            }
            finally { await app.StopAsync(); }
        }
    }
}
