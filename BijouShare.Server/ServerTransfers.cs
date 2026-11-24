using BijouShare.Shared;

namespace BijouShare.Server;

public sealed class ServerTransfers
{
    private readonly TransferLedger ledger;
    private readonly TransferMeter aggregate;
    private readonly TransferMeter idle = new();

    internal ServerTransfers(TransferLedger ledger)
    {
        this.ledger = ledger;
        aggregate = ledger.For("aggregate");
    }

    internal sealed class Counters(TransferMeter aggregate, TransferMeter device, object ledgerGate)
    {
        internal void ReadSent(RpcResponse result)
        {
            // Only reads return file payloads, and the final read may fill only part of a pooled buffer.
            var bytes = result.DataCount;
            if (bytes > 0)
                Add(bytes, 0);
        }

        internal void AddWrite(long bytes) => Add(0, bytes);

        private void Add(long read, long write)
        {
            lock (ledgerGate)
            {
                var second = TransferMeter.CurrentSecond;
                device.AddAt(read, write, second);
                aggregate.AddAt(read, write, second);
            }
        }
    }

    internal sealed record DeviceTraffic(Guid Id, string Name, TransferSnapshot Traffic);
    internal sealed record Overview(TransferSnapshot Aggregate, DeviceTraffic[] Devices);

    internal Counters ForDevice(Device device) => new(aggregate, ledger.For(device.EnrollmentId.ToString("N")), ledger.SyncRoot);

    internal void Forget(Guid enrollmentId) => ledger.Remove(enrollmentId.ToString("N"));

    internal Overview Snapshot(StateStore store)
    {
        var devices = store.Read(state => state.Devices.ToArray());
        lock (ledger.SyncRoot)
        {
            var second = TransferMeter.CurrentSecond;
            var idleSnapshot = idle.SnapshotAt(second);
            return new(aggregate.SnapshotAt(second), devices.Select(device => new DeviceTraffic(device.Id, device.Name,
                ledger.TryGet(device.EnrollmentId.ToString("N"), out var meter) ? meter.SnapshotAt(second) : idleSnapshot)).ToArray());
        }
    }
}
