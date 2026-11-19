using BijouShare.Shared;

namespace BijouShare.Server;

// A lost reply can be looked up on the same authenticated file session.
// Receipts contain only small operation results, never file data or request buffers.
internal sealed class OperationReceipts
{
    private const int Capacity = 128;
    private readonly Dictionary<long, (long Revision, RpcResponse Result)> recent = new();
    private readonly Queue<long> order = new();
    private readonly object gate = new();
    private long discardedThrough;
    private long highestStarted;

    internal RpcResponse Execute(RpcRequest request, long revision, Func<RpcResponse> execute)
    {
        var id = request.OutcomeId;
        if (id == 0)
            return execute();

        lock (gate)
        {
            if (recent.TryGetValue(id, out var receipt))
            {
                if (request.Operation != "GetOutcome" && !request.RecoveryAttempt)
                    return RpcResponse.Fail("InvalidParameter");
                return receipt.Revision == revision ? receipt.Result : RpcResponse.Fail("OutcomeUnknown");
            }
            // IDs are assigned before entering the send queue. A delayed first dispatch can
            // legitimately arrive below this watermark. Only recovery needs proof of absence.
            if (id <= discardedThrough && (request.Operation == "GetOutcome" || request.RecoveryAttempt))
                return RpcResponse.Fail("OutcomeUnknown");
            if (request.Operation == "GetOutcome")
                return RpcResponse.Fail("OutcomeNotExecuted");
            // A recovered mutation must not overtake a later operation on the original lease.
            // Opening an existing path can safely resolve it now when the first open never ran.
            if (request.RecoveryAttempt && id < highestStarted &&
                !(request.Operation == "Open" && request.Mode == FileMode.Open && !request.DeleteOnClose))
                return RpcResponse.Fail("OutcomeUnknown");
            // These operations address a pathname that another program could have replaced
            // during the outage. Recover a recorded result, but don't start one late.
            if (request.RecoveryAttempt && (request.DeleteOnClose || request.Operation is "Move" or "Times" or "Attributes" ||
                request.Operation == "Open" && request.Mode is FileMode.Create or FileMode.Truncate))
                return RpcResponse.Fail("OutcomeUnknown");
            if (order.Count == Capacity)
            {
                var oldest = order.Dequeue();
                discardedThrough = Math.Max(discardedThrough, oldest);
                recent.Remove(oldest);
            }
            highestStarted = Math.Max(highestStarted, id);
            order.Enqueue(id);
            // Record the attempt before touching the filesystem. An unexpected exception must
            // never look like proof that an append, rename or delete did not take place.
            recent.Add(id, (revision, RpcResponse.Fail("OutcomeUnknown")));
            try
            {
                var result = execute();
                recent[id] = (revision, result);
                return result;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                recent[id] = (revision, RpcResponse.Fail(FileService.ErrorCode(ex)));
                throw;
            }
        }
    }
}
