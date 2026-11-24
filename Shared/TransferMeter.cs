using System.Text.Json.Serialization;

namespace BijouShare.Shared;

public readonly record struct TransferSample(long ReadBytes, long WriteBytes);
// Keep lifetime counters exact when JavaScript receives more than 2^53 bytes.
public sealed record TransferSnapshot(
    [property: JsonNumberHandling(JsonNumberHandling.WriteAsString | JsonNumberHandling.AllowReadingFromString)] long ReadBytes,
    [property: JsonNumberHandling(JsonNumberHandling.WriteAsString | JsonNumberHandling.AllowReadingFromString)] long WriteBytes,
    TransferSample[] Samples);

/// <summary>File payload bytes in the client's read and write directions. Each graph point is a completed second.</summary>
public sealed class TransferMeter
{
    internal const int HistorySeconds = 60;
    // One extra slot keeps the oldest displayed second while the current second fills.
    private const int Capacity = HistorySeconds + 1;
    private readonly object gate = new();
    private readonly Func<long> clock;
    private (long Second, TransferSample Bytes)[]? history;
    private TransferSample totals;

    internal static long CurrentSecond => Environment.TickCount64 / 1000;

    public TransferMeter(long readBytes = 0, long writeBytes = 0)
        : this(readBytes, writeBytes, static () => CurrentSecond) { }

    internal TransferMeter(long readBytes, long writeBytes, Func<long> clock)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(readBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(writeBytes);
        totals = new(readBytes, writeBytes);
        this.clock = clock;
    }

    public void AddRead(long bytes) => Add(bytes, 0, null);
    public void AddWrite(long bytes) => Add(0, bytes, null);
    internal void AddAt(long read, long write, long second) => Add(read, write, second);

    private void Add(long read, long write, long? at)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(read);
        ArgumentOutOfRangeException.ThrowIfNegative(write);
        if (read == 0 && write == 0) return;
        lock (gate)
        {
            long second = at ?? clock();
            history ??= new (long, TransferSample)[Capacity];
            ref var slot = ref history[(int)(second % Capacity)];
            var previous = slot.Second == second ? slot.Bytes : default;
            slot = (second, new(previous.ReadBytes + read, previous.WriteBytes + write));
            totals = new(totals.ReadBytes + read, totals.WriteBytes + write);
        }
    }

    public TransferSample Totals()
    {
        lock (gate) return totals;
    }

    public TransferSnapshot Snapshot() => SnapshotAt(clock());

    internal TransferSnapshot SnapshotAt(long second)
    {
        lock (gate)
        {
            long first = second - HistorySeconds;
            var samples = new TransferSample[HistorySeconds];
            for (int i = 0; history != null && i < samples.Length; i++)
            {
                long sampleSecond = first + i;
                if (sampleSecond < 0) continue;
                ref var slot = ref history[(int)(sampleSecond % Capacity)];
                if (slot.Second == sampleSecond) samples[i] = slot.Bytes;
            }
            return new(totals.ReadBytes, totals.WriteBytes, samples);
        }
    }
}
