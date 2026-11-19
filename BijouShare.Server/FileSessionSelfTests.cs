using System.Net.Sockets;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class FileSessionSelfTests
{
    internal static async Task RunAsync(ServerOptions options, StateStore store, FileService files, Device device,
        byte[] privateKey, HybridKem kem, Action<bool, string> check, CancellationToken token)
    {
        async Task<RpcClientSession> Connect()
        {
            var socket = new TcpClient();
            try
            {
                var transport = await AuthenticatedClient.ConnectAsync(socket, "127.0.0.1", options.Port,
                    device.PublicIdentity, privateKey, kem, store.ServerId, token);
                return new RpcClientSession(transport);
            }
            catch { socket.Dispose(); throw; }
        }
        async Task Expect(RpcClientSession rpc, RpcRequest request, string error, string label)
        {
            try { await rpc.CallAsync(request, token); }
            catch (RemoteException ex) when (ex.Code == error) { check(true, label); return; }
            throw new InvalidOperationException(label);
        }
        static RpcRequest Resume(Guid ticket = default) => new() { Operation = "ResumeSession", Handle = ticket };
        var open = new RpcRequest
        {
            Operation = "Open", Path = "/Team/session-resume.bin", Mode = FileMode.OpenOrCreate,
            Access = AccessMask.GenericRead | AccessMask.GenericWrite, Share = FileShare.ReadWrite | FileShare.Delete
        };
        using var first = await Connect();
        var ticket = (await first.CallAsync(Resume(), token)).Handle;
        var handle = (await first.CallAsync(open, token)).Handle;
        await first.CallAsync(new() { Operation = "Write", Handle = handle, Data = [1, 2, 3] }, token);
        await first.CallAsync(new() { Operation = "Lock", Handle = handle, Length = 3 }, token);
        using var independent = await Connect();
        var separate = (await independent.CallAsync(Resume(), token)).Handle;
        check(ticket != Guid.Empty && separate != ticket, "Two mounted connections for the same device receive separate session tickets");
        await Expect(independent, new() { Operation = "Read", Handle = handle, Count = 1 }, "InvalidHandle",
            "A separate connection cannot use another mount's open handle");
        var reader = (await independent.CallAsync(open with { Mode = FileMode.Open, Access = AccessMask.GenericRead }, token)).Handle;
        using (var takeover = await Connect())
        {
            check((await takeover.CallAsync(Resume(ticket), token)).Handle == ticket,
                "A fresh authenticated transport can take over its live predecessor");
            await takeover.CallAsync(new() { Operation = "Write", Handle = handle, Offset = 1, Data = [5] }, token);
            try
            {
                await first.CallAsync(new() { Operation = "Read", Handle = handle, Count = 1 }, token);
                throw new InvalidOperationException("The superseded connection retained file access.");
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            { check(true, "The superseded transport is fenced before takeover acknowledges success"); }
        }
        using var resumed = await Connect();
        check((await resumed.CallAsync(Resume(ticket), token)).Handle == ticket &&
            (await resumed.CallAsync(new() { Operation = "Read", Handle = handle, Count = 3 }, token)).Data is [1, 5, 3],
            "Socket loss and reconnect preserve the underlying writer and file contents");
        var appendHandle = (await resumed.CallAsync(open with { Path = "/Team/wake-append.bin", Mode = FileMode.CreateNew }, token)).Handle;
        var append = new RpcRequest { Operation = "Write", Append = true, Handle = appendHandle, Data = [7], OutcomeId = 10 };
        await Expect(resumed, new() { Operation = "GetOutcome", OutcomeId = 10 }, "OutcomeNotExecuted",
            "A returning device can distinguish an unsent request from a lost reply");
        await resumed.CallAsync(append with { RecoveryAttempt = true }, token);
        var recorded = await resumed.CallAsync(new() { Operation = "GetOutcome", OutcomeId = 10 }, token);
        await resumed.CallAsync(append with { RecoveryAttempt = true }, token);
        check(recorded.Length == 1 && (await resumed.CallAsync(new() { Operation = "Read", Handle = appendHandle, Count = 8 }, token)).Data is [7],
            "A recovered append returns the original byte count and changes the file exactly once");
        await Expect(resumed, append with { OutcomeId = 9, RecoveryAttempt = true }, "OutcomeUnknown",
            "An older missing write cannot be applied after a later mutation");
        await resumed.CallAsync(new() { Operation = "Close", Handle = appendHandle }, token);
        var exclusive = open with { Path = "/Team/orphan-open.bin", Share = FileShare.None, OutcomeId = 11 };
        await resumed.CallAsync(exclusive, token);
        var abandon = new RpcRequest { Operation = "AbandonOpen", OutcomeId = 11 };
        await independent.CallAsync(abandon, token);
        await Expect(independent, exclusive with { OutcomeId = 0 }, "SharingViolation",
            "An abandonment request on another mount cannot release this open");
        await resumed.CallAsync(abandon, token);
        await resumed.CallAsync(abandon, token);
        var reopened = await independent.CallAsync(exclusive with { OutcomeId = 0, Mode = FileMode.Open }, token);
        check(reopened.Handle != Guid.Empty, "An open with a lost handle can be abandoned twice without deleting the file or retaining a lock");
        await independent.CallAsync(new() { Operation = "Close", Handle = reopened.Handle }, token);
        await Expect(independent, open, "SharingViolation", "The original single-writer reservation survives a disconnect");
        await Expect(independent, new() { Operation = "Read", Handle = reader, Count = 1 }, "LockViolation",
            "The resumed byte-range lock still applies to an independent reader");
        await resumed.CallAsync(new() { Operation = "EndSession" }, token);
        check((await independent.CallAsync(open, token)).Handle != Guid.Empty &&
            (await independent.CallAsync(new() { Operation = "Read", Handle = reader, Count = 3 }, token)).Data is [1, 5, 3],
            "Ending a logical session releases its writer and byte-range locks immediately");
        using var stale = await Connect();
        check((await stale.CallAsync(Resume(ticket), token)).Handle != ticket, "A closed ticket receives a fresh logical session");
        await Expect(stale, new() { Operation = "Read", Handle = handle, Count = 1 }, "InvalidHandle",
            "A closed ticket cannot revive an earlier open handle");
        await stale.CallAsync(new() { Operation = "EndSession" }, token);
        await independent.CallAsync(new() { Operation = "EndSession" }, token);

        // Exercise expiration without leaving files locked for the actual grace period.
        var clock = new LeaseClock();
        var leases = new FileSessionLeases(store, files, clock);
        using var stop = new CancellationTokenSource();
        var owner = new FileSessionLeases.Owner(stop);
        var detached = await leases.AttachAsync(device, Guid.Empty, owner, token);
        files.Execute(detached.FileSession, device.Id, open, device);
        leases.Detach(detached, owner, end: false);
        using var key = KeyAgreement.NewKey();
        var second = store.Enroll(TestRegistration.Create("Lease isolation", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())), []);
        using var otherStop = new CancellationTokenSource();
        var differentOwner = new FileSessionLeases.Owner(otherStop);
        var other = await leases.AttachAsync(second, detached.Ticket, differentOwner, token);
        check(other.Ticket != detached.Ticket, "Another enrolled device cannot claim a detached file session with its ticket");
        store.Update(state =>
        {
            var index = state.Devices.FindIndex(d => d.Id == second.Id);
            return state.Devices[index] = state.Devices[index] with { Enabled = false };
        });
        leases.Sweep();
        check(otherStop.IsCancellationRequested, "A maintenance sweep promptly fences a blocked enrollment's transport");
        leases.Detach(other, differentOwner, end: false);
        store.RemoveBlockedDevice(second.Id);
        clock.Advance(FileSessionLeases.Grace + TimeSpan.FromSeconds(1));
        leases.Sweep();
        using var replacementStop = new CancellationTokenSource();
        var replacementOwner = new FileSessionLeases.Owner(replacementStop);
        var replacement = await leases.AttachAsync(device, detached.Ticket, replacementOwner, token);
        check(replacement.Ticket != detached.Ticket && files.Execute(replacement.FileSession, device.Id, open, device).Handle != Guid.Empty,
            "An expired detached session releases its writer and gets a fresh ticket on reconnect");
        leases.Detach(replacement, replacementOwner, end: true);

        var tickets = new List<Guid>();
        for (var index = 0; index < 9; index++)
        {
            var connection = new FileSessionLeases.Owner(stop);
            var entry = await leases.AttachAsync(device, Guid.Empty, connection, token);
            tickets.Add(entry.Ticket);
            leases.Detach(entry, connection, end: false);
            clock.Advance(TimeSpan.FromSeconds(1));
        }
        var recentOwner = new FileSessionLeases.Owner(stop);
        var retained = await leases.AttachAsync(device, tickets[^1], recentOwner, token);
        check(retained.Ticket == tickets[^1], "A recently detached session remains available within its per-device limit");
        leases.Detach(retained, recentOwner, end: true);
        var evictedOwner = new FileSessionLeases.Owner(stop);
        var evicted = await leases.AttachAsync(device, tickets[0], evictedOwner, token);
        check(evicted.Ticket != tickets[0], "The per-device cap evicts the oldest excess detached session");
        leases.Detach(evicted, evictedOwner, end: true);
        leases.Sweep(shutdown: true);

        var receipts = new OperationReceipts();
        var mutations = 0;
        RpcResponse Apply() { mutations++; return new(); }
        for (long id = 2; id <= 141; id++)
            receipts.Execute(append with { OutcomeId = id }, 1, Apply);
        var query = new RpcRequest { Operation = "GetOutcome", OutcomeId = 2 };
        check(receipts.Execute(query, 1, Apply).Error == "OutcomeUnknown" &&
            receipts.Execute(append with { OutcomeId = 2, RecoveryAttempt = true }, 1, Apply).Error == "OutcomeUnknown" &&
            receipts.Execute(query with { OutcomeId = 141 }, 2, Apply).Error == "OutcomeUnknown" && mutations == 140,
            "Evicted receipts and receipts from an earlier authorization revision fail closed");
        check(receipts.Execute(append with { OutcomeId = 1 }, 1, Apply).Error is null && mutations == 141,
            "A first dispatch delayed behind the receipt window still executes");
        check(receipts.Execute(new RpcRequest { Operation = "Cleanup", DeleteOnClose = true, RecoveryAttempt = true, OutcomeId = 142 }, 1, Apply)
            .Error == "OutcomeUnknown" && mutations == 141,
            "Recovery never starts a delayed pathname deletion after an outage");
    }

    private sealed class LeaseClock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => timestamp;
        internal void Advance(TimeSpan by) => timestamp += by.Ticks;
    }
}
