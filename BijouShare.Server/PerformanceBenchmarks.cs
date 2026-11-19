using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Server;

public static class PerformanceBenchmarks
{
    public static async Task<int> RunAsync(string output)
    {
        const int totalBytes = 64 * 1024 * 1024;
        const int directoryFiles = 2048;
        var root = Path.GetFullPath(Path.Combine("artifacts", "benchmarks", Guid.NewGuid().ToString("N")));
        using var identityKem = HybridKem.Generate();
        var fixture = ServerSelfTests.CreateFixture(root, identityKem);
        var (store, options, device, privateKey, publicKey) = fixture;
        var export = Path.Combine(root, "share");
        var directory = Path.Combine(export, "many-files");
        Directory.CreateDirectory(directory);
        for (var index = 0; index < directoryFiles; index++)
            File.WriteAllText(Path.Combine(directory, $"item-{index:D5}.txt"), "benchmark");
        var payload = GC.AllocateUninitializedArray<byte>(totalBytes);
        RandomNumberGenerator.Fill(payload);
        File.WriteAllBytes(Path.Combine(export, "source.bin"), payload);
        var expectedHash = SHA3_256.HashData(payload);
        var results = new List<object>();
        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        using var files = new FileService(store, audit);
        using var server = new FileServer(options, store, files, audit, NullLogger<FileServer>.Instance);
        await server.StartAsync(CancellationToken.None);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        async Task<(TcpClient Socket, RpcClientSession Session)> Connect()
        {
            var socket = new TcpClient();
            try
            {
                var transport = await AuthenticatedClient.ConnectAsync(socket, "127.0.0.1", options.Port,
                    device.PublicIdentity!, privateKey, identityKem, store.ServerId, timeout.Token);
                return (socket, new RpcClientSession(transport));
            }
            catch { socket.Dispose(); throw; }
        }
        try
        {
            var (socket, session) = await Connect();
            using (socket)
            using (session)
            {
                Task<RpcResponse> Call(RpcRequest request) => session.CallAsync(request, timeout.Token);
                await Call(new()
                {
                    Operation = "Ping"
                });
                async Task Measure(string name, long bytes, int operations, Func<Task> operation)
                {
                    var allocated = GC.GetTotalAllocatedBytes(false);
                    var stopwatch = Stopwatch.StartNew();
                    await operation();
                    stopwatch.Stop();
                    var result = new
                    {
                        name,
                        milliseconds = stopwatch.Elapsed.TotalMilliseconds,
                        mibPerSecond = bytes == 0 ? (double?)null : bytes / 1048576d / stopwatch.Elapsed.TotalSeconds,
                        operationsPerSecond = operations / stopwatch.Elapsed.TotalSeconds,
                        allocatedMiB = (GC.GetTotalAllocatedBytes(false) - allocated) / 1048576d
                    };
                    results.Add(result);
                    Console.WriteLine(System.Text.Encoding.UTF8.GetString(Wire.Encode(result)));
                }
                var writeHandle = (await Call(new()
                {
                    Operation = "Open",
                    Path = "/Team/target.bin",
                    Mode = FileMode.CreateNew,
                    Access = AccessMask.GenericRead | AccessMask.GenericWrite,
                    Share = FileShare.ReadWrite | FileShare.Delete
                })).Handle;
                await Measure("sequential-write-64MiB", totalBytes, totalBytes / Wire.MaxChunk, async () =>
                {
                    for (var offset = 0; offset < totalBytes; offset += Wire.MaxChunk)
                        await Call(new()
                        {
                            Operation = "Write",
                            Handle = writeHandle,
                            Offset = offset,
                            Data = payload,
                            DataOffset = offset,
                            BorrowedCount = Math.Min(Wire.MaxChunk, totalBytes - offset)
                        });
                });
                await Call(new()
                {
                    Operation = "Close",
                    Handle = writeHandle
                });
                if (!KeyAgreement.Equals(expectedHash, SHA3_256.HashData(File.ReadAllBytes(Path.Combine(export, "target.bin")))))
                    throw new InvalidDataException("Benchmark write corruption.");
                var readHandle = (await Call(new()
                {
                    Operation = "Open",
                    Path = "/Team/source.bin",
                    Access = AccessMask.GenericRead,
                    Share = FileShare.ReadWrite | FileShare.Delete
                })).Handle;
                var received = GC.AllocateUninitializedArray<byte>(totalBytes);
                await Measure("sequential-read-64MiB", totalBytes, totalBytes / Wire.MaxChunk, async () =>
                {
                    for (var offset = 0; offset < totalBytes; offset += Wire.MaxChunk)
                    {
                        var response = await Call(new()
                        {
                            Operation = "Read",
                            Handle = readHandle,
                            Offset = offset,
                            Count = Math.Min(Wire.MaxChunk, totalBytes - offset)
                        });
                        response.Data!.CopyTo(received, offset);
                    }
                });
                if (!KeyAgreement.Equals(expectedHash, SHA3_256.HashData(received)))
                    throw new InvalidDataException("Benchmark read corruption.");
                Array.Clear(received);
                await Measure("parallel-read-64MiB-16-outstanding", totalBytes, totalBytes / Wire.MaxChunk, async () =>
                {
                    await Parallel.ForEachAsync(Enumerable.Range(0, totalBytes / Wire.MaxChunk),
                        new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = timeout.Token }, async (index, _) =>
                        {
                            var offset = index * Wire.MaxChunk;
                            var response = await Call(new()
                            {
                                Operation = "Read",
                                Handle = readHandle,
                                Offset = offset,
                                Count = Wire.MaxChunk
                            });
                            response.Data!.CopyTo(received, offset);
                        });
                });
                if (!KeyAgreement.Equals(expectedHash, SHA3_256.HashData(received)))
                    throw new InvalidDataException("Concurrent benchmark read corruption.");
                await Measure("random-read-4KiB", 1000L * 4096, 1000, async () =>
                {
                    for (var index = 0; index < 1000; index++)
                        await Call(new()
                        {
                            Operation = "Read",
                            Handle = readHandle,
                            Offset = (index * 7919L % (totalBytes / 4096)) * 4096,
                            Count = 4096
                        });
                });
                async Task MeasureListing(string label, int pageCount, string? pattern, int addedLatencyMs, int expected)
                {
                    var pages = 0;
                    await Measure(label, 0, expected, async () =>
                    {
                        long offset = 0;
                        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        while (true)
                        {
                            if (addedLatencyMs > 0) await Task.Delay(addedLatencyMs, timeout.Token);
                            var response = await Call(new()
                            {
                                Operation = "List", Path = "/Team/many-files", Offset = offset,
                                Count = pageCount, SearchPattern = pattern
                            });
                            pages++;
                            foreach (var entry in response.Entries!)
                                if (!names.Add(entry.Name)) throw new InvalidDataException("Duplicate directory entry.");
                            if (!response.More) break;
                            if (response.Length <= offset) throw new InvalidDataException("Directory cursor did not advance.");
                            offset = response.Length;
                        }
                        if (names.Count != expected) throw new InvalidDataException("Incomplete benchmark listing.");
                    });
                    Console.WriteLine($"{label}: {pages} listing request(s)");
                }
                await MeasureListing("directory-list-2048", 0, "*", 0, directoryFiles);
                await MeasureListing("directory-legacy-60ms", 256, null, 60, directoryFiles);
                await MeasureListing("directory-current-60ms", 0, "*", 60, directoryFiles);
                await MeasureListing("directory-filtered-60ms", 0, "item-000??.txt", 60, 100);
                var listing = new RpcRequest { Operation = "List", Path = "/Team/many-files", SearchPattern = "*" };
                var full = await Call(listing);
                var basic = await Call(listing with { BasicDirectoryInfo = true });
                if (full.More || basic.More || basic.Entries is not null || basic.Data is not null ||
                    full.Entries?.Count != directoryFiles || basic.Items?.Count != directoryFiles ||
                    !full.Entries.Select(DirectoryItem.FromEntry).OrderBy(e => e.Name, StringComparer.Ordinal)
                        .SequenceEqual(basic.Items.OrderBy(e => e.Name, StringComparer.Ordinal)))
                    throw new InvalidDataException("Compact listing changed the directory contents.");
                Console.WriteLine($"Directory listing JSON ({directoryFiles} entries): full {Wire.Encode(full).Length:N0} bytes, Explorer {Wire.Encode(basic).Length:N0} bytes.");
                await Call(new()
                {
                    Operation = "Close",
                    Handle = readHandle
                });
            }
        }
        finally { await server.StopAsync(CancellationToken.None); CryptographicOperations.ZeroMemory(privateKey); }
        var destination = Path.GetFullPath(output);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.WriteAllBytes(destination, Wire.Encode(new
        {
            environment = "same-machine encrypted TCP; warm OS file cache; isolated generated data",
            chunkBytes = Wire.MaxChunk,
            fixture = root,
            results
        }));
        Console.WriteLine($"Benchmark report: {destination}");
        return 0;
    }
}
