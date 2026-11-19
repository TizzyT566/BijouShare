namespace BijouShare.Server;

// Only fresh, authenticated transports may attach. A ticket identifies one mounted connection,
// independently of public device IDs and the transport connection IDs written to the audit log.
internal sealed class FileSessionLeases(StateStore store, FileService files, TimeProvider clock)
{
    internal static readonly TimeSpan Grace = TimeSpan.FromHours(24);
    private const int MaxDetachedPerDevice = 8, MaxDetached = 128;
    private readonly object gate = new();
    private readonly Dictionary<Guid, Lease> entries = [];

    internal sealed class Owner(CancellationTokenSource lifetime)
    {
        internal void Fence() => _ = lifetime.CancelAsync();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal sealed class Lease(Device device)
    {
        internal Guid Ticket { get; } = Guid.NewGuid();
        internal Guid FileSession { get; } = Guid.NewGuid();
        internal Device Device { get; } = device;
        internal OperationReceipts Receipts { get; } = new();
        internal Owner? Owner;
        internal long DetachedAt;
        internal bool Discard;
    }

    internal async Task<Lease> AttachAsync(Device device, Guid ticket, Owner next, CancellationToken token)
    {
        while (true)
        {
            Task drain;
            lock (gate)
            {
                token.ThrowIfCancellationRequested();
                if (!IsCurrent(device))
                    throw new UnauthorizedAccessException();
                if (!entries.TryGetValue(ticket, out var lease) || !lease.Device.HasSameIdentity(device) || lease.Discard)
                    return NewLease(device, next);
                if (lease.Owner is not { } previous)
                {
                    if (Expired(lease))
                    {
                        Remove(lease);
                        return NewLease(device, next);
                    }
                    lease.Owner = next;
                    return lease;
                }
                // A laptop can reconnect before TCP on the server notices loss of its old adapter.
                // Never attach until already accepted operations have completed on that transport.
                previous.Fence();
                drain = previous.Drained.Task;
            }
            await drain.WaitAsync(token);
        }
    }

    private Lease NewLease(Device device, Owner owner)
    {
        var lease = new Lease(device) { Owner = owner };
        entries.Add(lease.Ticket, lease);
        return lease;
    }

    internal void Detach(Lease lease, Owner owner, bool end)
    {
        lock (gate)
        {
            if (!ReferenceEquals(lease.Owner, owner))
                return;
            try
            {
                lease.Owner = null;
                if (end || lease.Discard || !IsCurrent(lease.Device))
                {
                    Remove(lease);
                    return;
                }
                lease.DetachedAt = clock.GetTimestamp();
                // An empty logical session can still hold the outcome of the final close or rename.
                var detached = entries.Values.Where(item => item.Owner is null).OrderBy(item => item.DetachedAt).ToArray();
                var sameDevice = detached.Where(item => item.Device.Id == lease.Device.Id).ToArray();
                foreach (var excess in sameDevice.Take(Math.Max(0, sameDevice.Length - MaxDetachedPerDevice)))
                    Remove(excess);
                var remaining = detached.Where(item => entries.ContainsKey(item.Ticket)).ToArray();
                foreach (var excess in remaining.Take(Math.Max(0, remaining.Length - MaxDetached)))
                    Remove(excess);
            }
            finally { owner.Drained.TrySetResult(); }
        }
    }

    private bool IsCurrent(Device authenticated) =>
        store.FindRegisteredDevice(authenticated.Id) is { Enabled: true } current && current.HasSameIdentity(authenticated);

    private bool Expired(Lease lease) => clock.GetElapsedTime(lease.DetachedAt) >= Grace;

    private void Remove(Lease lease)
    {
        entries.Remove(lease.Ticket);
        files.ReleaseSession(lease.FileSession);
    }

    internal void Sweep(bool shutdown = false)
    {
        lock (gate)
        {
            foreach (var lease in entries.Values.ToArray())
            {
                if (!shutdown && IsCurrent(lease.Device) && (lease.Owner is not null || !Expired(lease)))
                    continue;
                if (lease.Owner is { } owner)
                {
                    lease.Discard = true;
                    owner.Fence();
                }
                else Remove(lease);
            }
        }
    }

    internal async Task RunAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), clock);
        try
        {
            while (await timer.WaitForNextTickAsync(token))
                Sweep();
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
}
