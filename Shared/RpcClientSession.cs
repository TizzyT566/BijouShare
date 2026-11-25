using System.Collections.Concurrent;

namespace BijouShare.Shared;

/// <summary>Bounds and correlates concurrent RPCs over one authenticated symmetric-encryption session.</summary>
public sealed class RpcClientSession : IDisposable
{
    private readonly SecureTransport transport;
    private readonly SemaphoreSlim legacyGate = new(1, 1);
    private readonly SemaphoreSlim window = new(16, 16);
    private readonly SemaphoreSlim sendOrder = new(1, 1);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentDictionary<long, TaskCompletionSource<RpcResponse>> pending = new();
    private readonly Task receiver;
    private long nextId;
    private int disposed;
    private Exception? failure;
    internal Exception? Failure => Volatile.Read(ref failure);
    public bool BinaryPayloads => transport.BinaryPayloads;
    public bool SupportsNetworkServices => transport.SupportsNetworkServices;
    public bool IsClosed => Volatile.Read(ref disposed) != 0;
    public string? UserName => transport.RemoteUserName;
    public string? DeviceName => transport.RemoteDeviceName;

    public RpcClientSession(SecureTransport transport)
    {
        this.transport = transport;
        receiver = transport.BinaryPayloads ? ReceiveRepliesAsync() : Task.CompletedTask;
    }

    public async Task<RpcResponse> CallAsync(RpcRequest request, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, shutdown.Token);
        if (!transport.BinaryPayloads)
        {
            await legacyGate.WaitAsync(linked.Token);
            try
            {
                await transport.SendAsync(request, linked.Token);
                var response = await transport.ReceiveAsync<RpcResponse>(linked.Token);
                if (response.Error is not null)
                    throw new RemoteException(response.Error);
                return response;
            }
            catch (RemoteException) { throw; }
            catch (Exception ex) { Fail(ex); throw; }
            finally { legacyGate.Release(); }
        }
        await window.WaitAsync(linked.Token);
        long id = 0;
        var completion = new TaskCompletionSource<RpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await sendOrder.WaitAsync(linked.Token);
            try
            {
                id = Interlocked.Increment(ref nextId);
                if (id <= 0 || !pending.TryAdd(id, completion))
                    throw new IOException("RPC sequence exhausted.");
                await transport.SendAsync(request with
                {
                    RequestId = id
                }, linked.Token);
            }
            finally { sendOrder.Release(); }
            var response = await completion.Task.WaitAsync(linked.Token);
            if (response.Error is not null)
                throw new RemoteException(response.Error);
            return response;
        }
        catch (RemoteException) { throw; }
        catch (Exception ex)
        {
            // A request canceled while waiting to send has no remote outcome to resolve.
            // Once assigned an ID, never keep or retry a potentially partially sent request.
            if (id != 0)
                Fail(ex);
            throw;
        }
        finally { pending.TryRemove(id, out _); window.Release(); }
    }

    private async Task ReceiveRepliesAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var response = await transport.ReceiveAsync<RpcResponse>(shutdown.Token);
                if (response.RequestId <= 0 || !pending.TryGetValue(response.RequestId, out var completion) ||
                    !completion.TrySetResult(response))
                    throw new InvalidDataException("Unexpected or duplicate RPC response.");
            }
        }
        catch (Exception ex)
        {
            Interlocked.CompareExchange(ref failure, ex, null);
            foreach (var item in pending.Values)
                item.TrySetException(new IOException("File connection ended.", ex));
            Dispose();
        }
    }

    private void Fail(Exception error)
    {
        Interlocked.CompareExchange(ref failure, error, null);
        Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        shutdown.Cancel();
        transport.Dispose();
        foreach (var item in pending.Values)
            item.TrySetException(new IOException("File connection closed."));
    }
}
