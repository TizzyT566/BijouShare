using BijouShare.Shared;
using Microsoft.Extensions.Logging.Abstractions;

namespace BijouShare.Server;

internal static class TransferMeterSelfTests
{
    public static async Task RunAsync(string root, Action<bool, string> check)
    {
        long second = 100;
        var meter = new TransferMeter(30, 40, () => second);
        meter.AddRead(5);
        meter.AddWrite(7);
        check(meter.Snapshot().Samples.All(s => s == default) && meter.Totals() == new TransferSample(35, 47),
            "Transfer counters include current activity while graph rates use completed seconds");
        second++;
        check(meter.Snapshot().Samples[^1] == new TransferSample(5, 7), "The newest transfer sample contains one second of reads and writes");
        second += 59;
        meter.AddWrite(12);
        var oldest = meter.Snapshot().Samples;
        check(oldest.Length == 60 && oldest[0] == new TransferSample(5, 7) && oldest.Skip(1).All(s => s == default),
            "A full minute of transfer history is retained while the next second fills");
        second += 3600;
        check(meter.Snapshot().Samples.All(s => s == default) && meter.Totals() == new TransferSample(35, 59),
            "Idle or sleeping devices lose stale graph samples and keep cumulative totals");
        Parallel.For(0, 4096, _ => { meter.AddRead(2); meter.AddWrite(3); });
        check(meter.Totals() == new TransferSample(35 + 8192, 59 + 12288), "Concurrent transfers preserve both byte counters");

        string path = Path.Combine(root, "test-transfer-totals.json");
        TransferLedger Open() => new(path, NullLogger.Instance);
        var ledger = Open();
        ledger.For("first").AddWrite(8);
        ledger.For("second").AddRead(10);
        using (var checkpoint = new TransferCheckpointService(ledger))
        {
            await checkpoint.StartAsync(CancellationToken.None);
            await checkpoint.StopAsync(CancellationToken.None);
        }
        var restored = Open();
        check(restored.For("first").Totals() == new TransferSample(0, 8) && restored.For("second").Totals() == new TransferSample(10, 0)
            && restored.For("second").Snapshot().Samples.All(s => s == default),
            "Shutdown saves independent counters and restart begins a fresh speed history");
        restored.Remove("first");
        restored.Flush();
        check(!Open().TryGet("first", out _), "Removing a transfer record persists across restart");
    }
}
