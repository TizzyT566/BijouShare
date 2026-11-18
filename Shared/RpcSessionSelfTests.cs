using System.Threading.Channels;

namespace BijouShare.Shared;

internal static class RpcSessionSelfTests
{
    public static async Task RunAsync(byte[] material, Action<bool, string> check)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using (var stream = new MemoryStream())
        using (var transport = new SecureTransport(stream, material, false))
        using (var session = new RpcClientSession(transport))
        {
            try
            {
                await session.CallAsync(new(), deadline.Token);
                throw new InvalidOperationException("Accepted a missing legacy response.");
            }
            catch (EndOfStreamException)
            {
                check(session.IsClosed, "A failed legacy RPC marks its session closed");
            }
        }

        var (clientStream, serverStream) = DuplexStream.Pair();
        using (clientStream)
        using (serverStream)
        using (var server = new SecureTransport(serverStream, material, true, true))
        using (var transport = new SecureTransport(clientStream, material, false, true))
        using (var session = new RpcClientSession(transport))
        {
            clientStream.PauseWrites = new(TaskCreationOptions.RunContinuationsAsynchronously);
            var first = session.CallAsync(new()
            {
                Offset = 7
            }, deadline.Token);
            await clientStream.WriteStarted.Task.WaitAsync(deadline.Token);
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var queued = session.CallAsync(new()
            {
                Offset = 8
            }, cancel.Token);
            await cancel.CancelAsync();
            try
            {
                await queued;
                throw new InvalidOperationException("A canceled queued RPC completed successfully.");
            }
            catch (OperationCanceledException)
            {
                check(!session.IsClosed, "Canceling an unsent queued RPC preserves other in-flight requests");
            }
            clientStream.PauseWrites.TrySetResult();
            var request = await server.ReceiveAsync<RpcRequest>(deadline.Token);
            await server.SendAsync(new RpcResponse { RequestId = request.RequestId, Length = request.Offset }, deadline.Token);
            request.ReleasePayload();
            check((await first).Length == 7, "An in-flight request completes after another queued request is canceled");
            var followup = session.CallAsync(new()
            {
                Offset = 9
            }, deadline.Token);
            request = await server.ReceiveAsync<RpcRequest>(deadline.Token);
            await server.SendAsync(new RpcResponse { RequestId = request.RequestId, Length = request.Offset }, deadline.Token);
            request.ReleasePayload();
            check((await followup).Length == 9 && !session.IsClosed, "A connection remains reusable after unsent cancellation");
        }

        (clientStream, serverStream) = DuplexStream.Pair();
        using (clientStream)
        using (serverStream)
        using (var server = new SecureTransport(serverStream, material, true, true))
        using (var transport = new SecureTransport(clientStream, material, false, true))
        using (var session = new RpcClientSession(transport))
        {
            async Task ReverseReplies()
            {
                long previous = 0;
                for (var batch = 0; batch < 4; batch++)
                {
                    var requests = new List<RpcRequest>();
                    for (var index = 0; index < 16; index++)
                    {
                        var request = await server.ReceiveAsync<RpcRequest>(deadline.Token);
                        if (request.RequestId <= previous)
                            throw new InvalidOperationException("Requests arrived outside ID order.");
                        previous = request.RequestId;
                        requests.Add(request);
                    }
                    foreach (var request in requests.AsEnumerable().Reverse())
                    {
                        try
                        {
                            await server.SendAsync(new RpcResponse { RequestId = request.RequestId, Length = request.Offset }, deadline.Token);
                        }
                        finally { request.ReleasePayload(); }
                    }
                }
            }
            var peer = ReverseReplies();
            var calls = Enumerable.Range(0, 64).Select(index => session.CallAsync(new() { Offset = index }, deadline.Token)).ToArray();
            var replies = await Task.WhenAll(calls).WaitAsync(deadline.Token);
            await peer;
            check(replies.Select((reply, index) => reply.Length == index).All(x => x),
                "Reversed responses correlate correctly across four full request windows");

            var denied = session.CallAsync(new(), deadline.Token);
            var deniedRequest = await server.ReceiveAsync<RpcRequest>(deadline.Token);
            await server.SendAsync(new RpcResponse { RequestId = deniedRequest.RequestId, Error = "AccessDenied" }, deadline.Token);
            deniedRequest.ReleasePayload();
            try
            {
                await denied;
                throw new InvalidOperationException("An RPC ignored its remote error.");
            }
            catch (RemoteException ex) when (ex.Code == "AccessDenied")
            {
                check(!session.IsClosed, "An ordinary remote permission error does not close the RPC session");
            }
        }

        (clientStream, serverStream) = DuplexStream.Pair();
        using (clientStream)
        using (serverStream)
        using (var server = new SecureTransport(serverStream, material, true, true))
        using (var transport = new SecureTransport(clientStream, material, false, true))
        using (var session = new RpcClientSession(transport))
        {
            var calls = Enumerable.Range(0, 32).Select(_ => session.CallAsync(new(), deadline.Token)).ToArray();
            var request = await server.ReceiveAsync<RpcRequest>(deadline.Token);
            request.ReleasePayload();
            server.Dispose();
            try
            {
                await Task.WhenAll(calls).WaitAsync(deadline.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
            check(session.IsClosed && calls.All(call => call.IsCompleted && !call.IsCompletedSuccessfully),
                "Connection loss promptly fails every outstanding and queued RPC");
        }

        (clientStream, serverStream) = DuplexStream.Pair();
        using (clientStream)
        using (serverStream)
        using (var server = new SecureTransport(serverStream, material, true, true))
        using (var transport = new SecureTransport(clientStream, material, false, true))
        using (var session = new RpcClientSession(transport))
        using (var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token))
        {
            var call = session.CallAsync(new()
            {
                Operation = "Write",
                Data = [1, 2, 3]
            }, cancel.Token);
            var request = await server.ReceiveAsync<RpcRequest>(deadline.Token);
            request.ReleasePayload();
            await cancel.CancelAsync();
            try
            {
                await call;
                throw new InvalidOperationException("An uncertain write completed after cancellation.");
            }
            catch (OperationCanceledException)
            {
                check(session.IsClosed, "Cancellation after sending closes the session instead of replaying an uncertain write");
            }
        }
    }

    private sealed class DuplexStream(Channel<byte[]> input, Channel<byte[]> output) : Stream
    {
        private byte[]? current;
        private int position;
        private int disposed;
        public TaskCompletionSource? PauseWrites
        {
            get; set;
        }
        public TaskCompletionSource WriteStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public static (DuplexStream Client, DuplexStream Server) Pair()
        {
            var left = Channel.CreateUnbounded<byte[]>();
            var right = Channel.CreateUnbounded<byte[]>();
            return (new(left, right), new(right, left));
        }
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException(); set => throw new NotSupportedException();
        }
        public override void Flush()
        {
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0)
                return 0;
            if (current is null || position == current.Length)
            {
                try
                {
                    current = await input.Reader.ReadAsync(cancellationToken);
                }
                catch (ChannelClosedException) { return 0; }
                position = 0;
            }
            var count = Math.Min(buffer.Length, current.Length - position);
            current.AsMemory(position, count).CopyTo(buffer);
            position += count;
            return count;
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            WriteStarted.TrySetResult();
            if (PauseWrites is not null)
                await PauseWrites.Task.WaitAsync(cancellationToken);
            if (!output.Writer.TryWrite(buffer.ToArray()))
                throw new IOException("Peer closed.");
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing && Interlocked.Exchange(ref disposed, 1) == 0)
            {
                input.Writer.TryComplete();
                output.Writer.TryComplete();
            }
            base.Dispose(disposing);
        }
    }
}
