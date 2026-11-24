using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BijouShare.Shared;

/// <summary>Checkpoints cumulative counters in the service's private storage. Rate history stays in memory.</summary>
public sealed class TransferLedger
{
    private readonly string filePath;
    private readonly ILogger logger;
    private readonly object gate = new();
    // The server records a device and the aggregate together under the checkpoint's capture lock.
    internal object SyncRoot => gate;
    private readonly object flushGate = new();
    private readonly Dictionary<string, TransferMeter> meters = new(StringComparer.Ordinal);
    private Dictionary<string, TransferSample> saved = [];

    public TransferLedger(string filePath, ILogger logger)
    {
        this.filePath = filePath;
        this.logger = logger;
        try
        {
            if ((File.GetAttributes(filePath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The transfer statistics file must be an ordinary file.");
            using var stream = File.OpenRead(filePath);
            var entries = JsonSerializer.Deserialize<Dictionary<string, TransferSample>>(stream);
            if (entries == null || entries.Values.Any(t => t.ReadBytes < 0 || t.WriteBytes < 0))
                throw new JsonException("Invalid transfer totals.");
            foreach (var (key, totals) in entries)
                meters.Add(key, new(totals.ReadBytes, totals.WriteBytes));
            saved = entries;
        }
        catch (FileNotFoundException) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            logger.LogWarning(ex, "Could not load transfer totals. Monitoring will start at zero.");
        }
    }

    public TransferMeter For(string key)
    {
        lock (gate)
        {
            if (!meters.TryGetValue(key, out var meter)) meters.Add(key, meter = new());
            return meter;
        }
    }

    public bool TryGet(string key, [NotNullWhen(true)] out TransferMeter? meter)
    {
        lock (gate) return meters.TryGetValue(key, out meter);
    }

    public void Remove(string key)
    {
        lock (gate) meters.Remove(key);
    }

    public void Flush()
    {
        lock (flushGate)
        {
            Dictionary<string, TransferSample> current;
            lock (gate)
                current = meters.ToDictionary(entry => entry.Key, entry => entry.Value.Totals(), StringComparer.Ordinal);
            if (current.Count == saved.Count && current.All(e => saved.TryGetValue(e.Key, out var value) && value == e.Value))
                return;
            try
            {
                PrivateStorage.AtomicWrite(filePath, JsonSerializer.SerializeToUtf8Bytes(current));
                saved = current;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                logger.LogWarning(ex, "Could not save transfer totals. The counters are still available in memory.");
            }
        }
    }
}

public sealed class TransferCheckpointService(TransferLedger ledger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken)) ledger.Flush();
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { await base.StopAsync(cancellationToken); }
        finally { ledger.Flush(); }
    }
}
