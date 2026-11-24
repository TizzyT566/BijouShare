using System.Net.Sockets;
using BijouShare.Shared;
using Microsoft.Extensions.Logging.Abstractions;

namespace BijouShare.Server;

internal static class ServerTransferSelfTests
{
    internal static async Task CheckDeviceAccountingAsync(ServerOptions options, StateStore store, Device first,
        ServerTransfers transfers, TransferLedger ledger, string totalsPath, Action<bool, string> check, CancellationToken token)
    {
        var before = transfers.Snapshot(store).Aggregate;
        using var ec = KeyAgreement.NewKey();
        using var kem = HybridKem.Generate();
        var request = TestRegistration.Create(first.Name, Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()), kem);
        var second = store.Enroll(request, first.GroupIds);
        using (var socket = new TcpClient())
        using (var transport = await AuthenticatedClient.ConnectAsync(socket, "127.0.0.1", options.Port,
            second.PublicIdentity, ec.ExportPkcs8PrivateKey(), kem, store.ServerId, token, binaryPayloads: false))
        {
            async Task<RpcResponse> Call(RpcRequest rpc)
            {
                await transport.SendAsync(rpc, token);
                return await transport.ReceiveAsync<RpcResponse>(token);
            }

            var handle = (await Call(new()
            {
                Operation = "Open", Path = "/Team/traffic.bin", Mode = FileMode.CreateNew,
                Access = AccessMask.GenericRead | AccessMask.GenericWrite, Share = FileShare.ReadWrite
            })).Handle;
            await Call(new() { Operation = "Write", Handle = handle, Data = [1, 2, 3, 4, 5] });
            var partial = await Call(new() { Operation = "Write", Handle = handle, Offset = 3, Data = [6, 7, 8, 9], PagingIo = true });
            var read = await Call(new() { Operation = "Read", Handle = handle, Count = 4096 });
            var failed = await Call(new() { Operation = "Write", Handle = Guid.NewGuid(), Data = [99] });
            await Call(new() { Operation = "Close", Handle = handle });
            check(partial.Length == 2 && read.Data is [1, 2, 3, 6, 7] && failed.Error == "InvalidHandle",
                "JSON file operations report actual bytes for truncated paging writes and short reads");
        }

        var summary = transfers.Snapshot(store);
        check(summary.Devices.Single(d => d.Id == second.Id).Traffic is { ReadBytes: 5, WriteBytes: 7 } &&
            summary.Devices.Single(d => d.Id == first.Id).Traffic.WriteBytes == before.WriteBytes &&
            summary.Aggregate.ReadBytes == before.ReadBytes + 5 && summary.Aggregate.WriteBytes == before.WriteBytes + 7,
            "Device totals stay separate for identical display names and ignore rejected writes and metadata");

        ledger.Flush();
        var reloaded = new ServerTransfers(new TransferLedger(totalsPath, NullLogger.Instance)).Snapshot(store);
        check(reloaded.Devices.Single(d => d.Id == second.Id).Traffic is { ReadBytes: 5, WriteBytes: 7 } &&
            reloaded.Aggregate.ReadBytes == summary.Aggregate.ReadBytes && reloaded.Aggregate.WriteBytes == summary.Aggregate.WriteBytes,
            "Stored server and per-device transfer totals survive restart");

        store.Update(state =>
        {
            var index = state.Devices.FindIndex(d => d.Id == second.Id);
            return state.Devices[index] = state.Devices[index] with { Enabled = false };
        });
        store.RemoveBlockedDevice(second.Id, transfers.Forget);
        var replacement = store.Enroll(request, first.GroupIds);
        summary = transfers.Snapshot(store);
        check(replacement.Id == second.Id && replacement.EnrollmentId != second.EnrollmentId &&
            summary.Devices.Single(d => d.Id == replacement.Id).Traffic is { ReadBytes: 0, WriteBytes: 0 } &&
            !ledger.TryGet(second.EnrollmentId.ToString("N"), out _) && summary.Aggregate.ReadBytes == before.ReadBytes + 5 &&
            summary.Aggregate.WriteBytes == before.WriteBytes + 7,
            "Forgetting an enrollment removes its counters and keeps historical bytes in the server total");

        var aggregateBefore = summary.Aggregate.WriteBytes;
        var counters = transfers.ForDevice(replacement);
        Parallel.For(0, 128, _ =>
        {
            counters.AddWrite(2);
            var concurrent = transfers.Snapshot(store);
            if (concurrent.Aggregate.WriteBytes - aggregateBefore != concurrent.Devices.Single(d => d.Id == replacement.Id).Traffic.WriteBytes)
                throw new InvalidOperationException("A snapshot observed a half-recorded transfer.");
        });
        check(transfers.Snapshot(store).Aggregate.WriteBytes == aggregateBefore + 256,
            "Concurrent server snapshots keep device and aggregate counters consistent");
    }
}
