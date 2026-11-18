using System.Collections.Concurrent;
using System.Threading.Channels;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed record AuditEvent(DateTime Time, string Actor, string Action, string Target, string Result)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; init; }
}
public sealed class AuditLog : IDisposable
{
    private readonly StateStore store;
    private readonly ILogger<AuditLog> logger;
    private readonly ConcurrentQueue<AuditEvent> recent = new();
    private readonly object gate = new();
    private readonly object lifecycle = new();
    private readonly TimeProvider clock;
    private readonly Channel<AuditEvent> pending = Channel.CreateBounded<AuditEvent>(new BoundedChannelOptions(8192)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait
    });
    private readonly Task writerTask;
    private StreamWriter? writer;
    private string? currentFile;
    private int disposed;
    public AuditLog(StateStore store, ILogger<AuditLog> logger) : this(store, logger, TimeProvider.System)
    {
    }
    internal AuditLog(StateStore store, ILogger<AuditLog> logger, TimeProvider clock)
    {
        this.store = store;
        this.logger = logger;
        this.clock = clock;
        LoadRecent();
        Directory.CreateDirectory(Path.Combine(store.DataDirectory, "audit"));
        writerTask = Task.Run(DrainAsync);
    }
    public AuditEvent[] Recent() => recent.Reverse().Take(200).ToArray();
    public void Write(string actor, string action, string target, string result = "OK", string? detail = null)
    {
        lock (lifecycle)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            var entry = Record(actor, action, target, result, detail);
            Persist(entry, flush: true);
        }
    }
    public void WriteFrequent(string actor, string action, string target, string result = "OK")
    {
        lock (lifecycle)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            var entry = Record(actor, action, target, result);
            if (!pending.Writer.TryWrite(entry))
                Persist(entry, flush: true); // Bounded backpressure; never drop audit evidence.
        }
    }
    private AuditEvent Record(string actor, string action, string target, string result, string? detail = null)
    {
        var entry = new AuditEvent(clock.GetUtcNow().UtcDateTime, Limit(actor, 200), Limit(action, 80), Limit(target, 2048), Limit(result, 200))
        {
            Detail = detail is null ? null : Limit(detail, 512)
        };
        recent.Enqueue(entry);
        while (recent.Count > 200)
            recent.TryDequeue(out _);
        return entry;
    }
    private void Persist(AuditEvent entry, bool flush)
    {
        lock (gate)
        {
            try
            {
                var file = Path.Combine(store.DataDirectory, "audit", $"{entry.Time:yyyy-MM-dd}.jsonl");
                if (writer is null || currentFile != file)
                {
                    CloseWriter();
                    writer = new StreamWriter(new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 64 * 1024), new System.Text.UTF8Encoding(false), 64 * 1024);
                    currentFile = file;
                }
                writer.WriteLine(System.Text.Encoding.UTF8.GetString(Wire.Encode(entry)));
                if (flush)
                    writer.Flush();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                CloseWriter();
                logger.LogError(ex, "Cannot persist audit record");
            }
        }
    }
    // Detach before disposing: failed rollover/flush must not leave a disposed writer cached.
    private void CloseWriter()
    {
        var previous = writer;
        writer = null;
        currentFile = null;
        try
        {
            previous?.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { logger.LogError(ex, "Cannot close audit file"); }
    }
    private void FlushWriter()
    {
        lock (gate)
        {
            try
            {
                writer?.Flush();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                CloseWriter();
                logger.LogError(ex, "Cannot flush audit records");
            }
        }
    }
    private async Task DrainAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        while (await timer.WaitForNextTickAsync())
        {
            // Bound each pass so a continuously busy producer cannot postpone the flush forever.
            for (var drained = 0; drained < 8192 && pending.Reader.TryRead(out var entry); drained++)
                Persist(entry, flush: false);
            FlushWriter();
            if (pending.Reader.Completion.IsCompleted)
                return;
        }
    }
    public void Dispose()
    {
        lock (lifecycle)
        {
            if (disposed != 0)
                return;
            disposed = 1;
            pending.Writer.TryComplete();
        }
        writerTask.GetAwaiter().GetResult();
        lock (gate)
            CloseWriter();
    }
    private static string Limit(string? value, int length)
    {
        if (string.IsNullOrEmpty(value))
            return "unknown";
        return value.Length <= length ? value : value[..(length - 1)] + "…";
    }
    private void LoadRecent()
    {
        try
        {
            var directory = Path.Combine(store.DataDirectory, "audit");
            if (!Directory.Exists(directory))
                return;
            var entries = new List<AuditEvent>();
            foreach (var file in Directory.EnumerateFiles(directory, "????-??-??.jsonl").OrderDescending().Take(3))
            {
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var offset = Math.Max(0, stream.Length - 1024 * 1024);
                stream.Seek(offset, SeekOrigin.Begin);
                using var reader = new StreamReader(stream);
                if (offset > 0)
                    reader.ReadLine(); // Discard a partial line at the tail boundary.
                while (reader.ReadLine() is { } line)
                {
                    if (line.Length > 32768)
                        continue;
                    try
                    {
                        var entry = Wire.Decode<AuditEvent>(System.Text.Encoding.UTF8.GetBytes(line));
                        entries.Add(entry);
                    }
                    catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidDataException) { }
                }
                if (entries.Count >= 200)
                    break;
            }
            foreach (var entry in entries.OrderBy(x => x.Time).TakeLast(200))
                recent.Enqueue(entry);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "Cannot reload recent audit records");
        }
    }
}
