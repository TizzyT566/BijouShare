using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace BijouShare.Server;

// Keep the existing Kestrel host, middleware and TLS settings. Separate endpoint names let Kestrel
// bind the replacement without first draining the endpoint that is serving the Save request.
internal sealed class WebPortListener
{
    private sealed class Endpoints : ConfigurationProvider, IConfigurationSource
    {
        public IConfigurationProvider Build(IConfigurationBuilder builder) => this;

        public void SetUrls(params string[] urls)
        {
            Data = urls.ToDictionary(url => $"Endpoints:BijouShare-{BindingAddress.Parse(url).Port}:Url",
                url => (string?)url, StringComparer.OrdinalIgnoreCase);
            OnReload();
        }
    }

    private readonly Endpoints endpoints = new();
    private readonly SemaphoreSlim handoff = new(1, 1);
    private const int BindTimeoutSeconds = 6;
    private string? activeUrl;
    private IServerAddressesFeature? addresses;
    // Access under handoff. Kestrel reloads asynchronously after SetUrls returns.
    private int? retiringPort;

    public bool CanChangePort => activeUrl is not null;
    public int? CurrentPort
    {
        get
        {
            var url = Volatile.Read(ref activeUrl);
            if (url is null) return null;
            var port = BindingAddress.Parse(url).Port;
            if (port != 0) return port;
            return BoundPorts() is [var bound, ..] ? bound : null;
        }
    }

    public static WebPortListener Configure(WebApplicationBuilder builder, int? savedPort)
    {
        var listener = new WebPortListener();
        builder.Services.AddSingleton(listener);
        var settings = builder.Configuration.GetSection("Kestrel");
        var urls = builder.Configuration["urls"]?.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // Keep externally defined endpoints (including per-endpoint certificates, HTTP/3 and multiple
        // ports) under their original configuration. A single URLs binding has one editable port.
        if (urls is not [var url] || settings.GetSection("Endpoints").GetChildren().Any() ||
            builder.Configuration.GetValue<bool>("preferHostingUrls"))
            return listener;

        var binding = BindingAddress.Parse(url);
        if (binding.Scheme is not ("http" or "https") || binding.PathBase.Length != 0 || binding.IsUnixPipe || binding.IsNamedPipe)
            return listener;

        listener.activeUrl = savedPort is { } port ? WithPort(url, port) : url;
        listener.endpoints.SetUrls(listener.activeUrl);
        var configuration = new ConfigurationBuilder().AddConfiguration(settings).Add(listener.endpoints).Build();
        builder.WebHost.ConfigureKestrel(options => options.Configure(configuration, reloadOnChange: true));
        return listener;
    }

    private static string WithPort(string url, int port)
    {
        var binding = BindingAddress.Parse(url);
        return $"{binding.Scheme}://{binding.Host}:{port}";
    }

    public void Attach(IServer server) => addresses = server.Features.Get<IServerAddressesFeature>();

    private int[] BoundPorts() => addresses?.Addresses.Select(address => BindingAddress.Parse(address).Port).ToArray() ?? [];

    private async Task WaitForPortAsync(int port, bool bound, CancellationToken request)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(request);
        timeout.CancelAfter(TimeSpan.FromSeconds(BindTimeoutSeconds));
        try
        {
            while (BoundPorts().Contains(port) != bound)
                await Task.Delay(40, timeout.Token);
        }
        catch (OperationCanceledException) when (!request.IsCancellationRequested)
        {
            throw new IOException($"The web UI could not finish changing port {port}.");
        }
    }

    public async Task<PreparedChange> PrepareAsync(int port, CancellationToken token)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        await handoff.WaitAsync(token);
        try
        {
            var previous = activeUrl ?? throw new InvalidOperationException("This web UI uses externally configured endpoints.");
            // A quick reversal must wait for the old instance of the target to disappear.
            // Do this on the next save; the retiring request itself needs to finish draining.
            if (retiringPort is { } retiring)
            {
                await WaitForPortAsync(retiring, false, token);
                retiringPort = null;
            }
            var previousPort = CurrentPort ?? throw new IOException("The current web UI listener is unavailable.");
            var replacement = WithPort(previous, port);
            endpoints.SetUrls(previous, replacement);
            try
            {
                // The addresses feature is populated by Kestrel after successful binding. An unrelated
                // HTTP server on the requested port must never count as readiness.
                await WaitForPortAsync(port, true, token);
                return new PreparedChange(this, previous, previousPort, replacement, port);
            }
            catch
            {
                endpoints.SetUrls(previous);
                retiringPort = port;
                throw;
            }
        }
        catch
        {
            handoff.Release();
            throw;
        }
    }

    internal sealed class PreparedChange(WebPortListener owner, string previous, int previousPort,
        string replacement, int replacementPort) : IAsyncDisposable
    {
        private int committed;
        private int retired;

        public void Commit(HttpResponse response)
        {
            response.OnCompleted(RetirePrevious);
            Volatile.Write(ref owner.activeUrl, replacement);
            Volatile.Write(ref committed, 1);
            _ = RetireAfterTimeout();
        }

        private async Task RetireAfterTimeout()
        {
            // Also retire if the browser disconnects without completing the response.
            await Task.Delay(TimeSpan.FromSeconds(10));
            await RetirePrevious();
        }

        private Task RetirePrevious()
        {
            if (Interlocked.Exchange(ref retired, 1) == 0)
            {
                owner.endpoints.SetUrls(replacement);
                owner.retiringPort = previousPort;
                owner.handoff.Release();
            }
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            if (Volatile.Read(ref committed) == 0 && Interlocked.Exchange(ref retired, 1) == 0)
            {
                owner.endpoints.SetUrls(previous);
                owner.retiringPort = replacementPort;
                owner.handoff.Release();
            }
            return ValueTask.CompletedTask;
        }
    }
}
