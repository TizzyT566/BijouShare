using System.Collections.Concurrent;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class MultiServerSelfTests
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        await RoutingAndHandles(check);
        await FailureIsolation(check);
        await AuthenticatedNames(check);
        await OfflineRecovery(check);
    }

    private static async Task AuthenticatedNames(Action<bool, string> check)
    {
        string? folder = null;
        var identity = new string('a', 64);
        var remote = new FakeConnection(71);
        using (var router = new MultiServerConnection(new[]
            { ("127.0.0.1:7443", (IRemoteConnection)remote, (Func<string?>)(() => folder), (Func<string?>)(() => identity)) }))
        {
            check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 },
                "An undiscovered server never creates a folder from its configured IP address");
            folder = "DarkArchives_838cff90d76c4ed0";
            await router.RefreshAsync(CancellationToken.None);
            check(router.Call(new() { Operation = "List" }).Response.Entries is [{ Name: "DarkArchives_838cff90d76c4ed0" }],
                "Authenticated discovery creates the exact server-name and short-hash folder");
            var opened = router.Call(new()
            {
                Operation = "Open",
                Path = "/" + folder + "/Team/file",
                Access = AccessMask.GenericRead
            });
            var oldPath = "/" + folder + "/Team/file";
            folder = "RenamedArchives_1234567890abcdef";
            await router.RefreshAsync(CancellationToken.None);
            check(router.Call(new() { Operation = "List" }).Response.Entries is [{ Name: "RenamedArchives_1234567890abcdef" }],
                "An authenticated rename refreshes the root namespace without retaining an IP alias");
            check(router.MaxTransferSizeFor(oldPath) == Wire.LegacyMaxChunk &&
                router.Call(new() { Operation = "Read", Path = oldPath, Handle = opened.Response.Handle, Count = 1 }, opened.Generation).Response.Data is [71],
                "A retained file handle stays bound to its server after the displayed folder name changes");
            Expect("NotFound", () => router.Call(new() { Operation = "Stat", Path = oldPath }), check,
                "New path requests cannot reuse a server's old displayed folder name");
        }

        var first = new FakeConnection(81);
        var second = new FakeConnection(82);
        var healthy = new FakeConnection(83);
        const string collision = "SameName_0123456789abcdef";
        using (var router = new MultiServerConnection(new[]
        {
            ("one", (IRemoteConnection)first, (Func<string?>)(() => collision), (Func<string?>)(() => new string('a', 64))),
            ("two", (IRemoteConnection)second, (Func<string?>)(() => collision), (Func<string?>)(() => new string('b', 64))),
            ("healthy", (IRemoteConnection)healthy, (Func<string?>)(() => "Other_ffffffffffffffff"), (Func<string?>)(() => new string('c', 64)))
        }))
        {
            await router.RefreshAsync(CancellationToken.None);
            check(router.Call(new() { Operation = "List" }).Response.Entries is [{ Name: "Other_ffffffffffffffff" }],
                "Different full identities sharing one short display ID cannot shadow each other's folders");
            var before = first.Calls.Count + second.Calls.Count;
            Expect("ServerIdentityConflict", () => router.Call(new() { Operation = "Open", Path = "/" + collision + "/Team/file" }), check,
                "Short-hash collisions fail closed instead of selecting an arbitrary server");
            check(first.Calls.Count + second.Calls.Count == before &&
                router.Statuses.Any(status => status.Name == "Other_ffffffffffffffff" && status.Connected),
                "A short-ID collision sends no file requests and leaves other servers usable");
            second.Failure = "Disconnected";
            await router.RefreshAsync(CancellationToken.None);
            Expect("ServerIdentityConflict", () => router.Call(new() { Operation = "Stat", Path = "/" + collision }), check,
                "A remembered offline identity still prevents a different key from taking its colliding short folder name");
        }
    }

    private static async Task RoutingAndHandles(Action<bool, string> check)
    {
        var office = new FakeConnection(11) { MaxTransferSize = Wire.MaxChunk, FreeBytes = 100, TotalBytes = 1000 };
        var home = new FakeConnection(22) { MaxTransferSize = Wire.LegacyMaxChunk, FreeBytes = 200, TotalBytes = 2000 };
        using var router = new MultiServerConnection(new (string Name, IRemoteConnection Connection)[] { ("Office", office), ("Home", home) });
        await router.RefreshAsync(CancellationToken.None);
        office.Calls.Clear();
        home.Calls.Clear();

        var first = router.Call(new()
        {
            Operation = "List",
            Path = "/",
            Count = 1
        }).Response;
        var second = router.Call(new()
        {
            Operation = "List",
            Path = "/",
            Count = 1,
            Offset = first.Length
        }).Response;
        check(first.Entries is [{ IsDirectory: true }] && first.More &&
            second.Entries is [{ IsDirectory: true }] && !second.More &&
            first.Entries.Concat(second.Entries).Select(entry => entry.Name).ToHashSet(StringComparer.Ordinal).SetEquals(new[] { "Office", "Home" }) &&
            office.Calls.IsEmpty && home.Calls.IsEmpty,
            "One virtual root lists and pages server folders without contacting any server");

        var root = router.Call(new()
        {
            Operation = "Stat",
            Path = "/"
        }).Response.Entry;
        var folder = router.Call(new()
        {
            Operation = "Stat",
            Path = "\\oFfIcE\\"
        }).Response.Entry;
        var openedFolder = router.Call(new()
        {
            Operation = "Open",
            Path = "/Office",
            Access = AccessMask.GenericRead
        }).Response;
        check(root is { Name: "", IsDirectory: true } && folder is { Name: "Office", IsDirectory: true } &&
            openedFolder.Handle == Guid.Empty && openedFolder.Entry is { Name: "Office", IsDirectory: true } &&
            office.Calls.IsEmpty && home.Calls.IsEmpty,
            "Server folder metadata and read-only opens are synthetic and preserve the configured alias");

        foreach (var path in new[] { "/", "/Office" })
            Expect("AccessDenied", () => router.Call(new() { Operation = "Open", Path = path, Access = AccessMask.GenericWrite }), check,
                "The synthetic namespace rejects writable opens at " + path);
        check(office.Calls.IsEmpty && home.Calls.IsEmpty, "Rejected synthetic namespace mutations never reach a server");

        var shares = (await router.CallAsync(new()
        {
            Operation = "List",
            Path = "/Office",
            Count = 17,
            Offset = 3
        })).Response;
        check(shares.Entries is [{ Name: "Team" }] && office.Calls.Last() is { Request.Operation: "List", Request.Path: "/", Request.Count: 17, Request.Offset: 3 } && home.Calls.IsEmpty,
            "Listing a server folder routes to that server's virtual root with pagination intact");
        await router.CallAsync(new()
        {
            Operation = "Stat",
            Path = "\\hOmE\\Team\\data.bin"
        });
        check(home.Calls.Last().Request.Path == "/Team/data.bin" && home.Calls.Last().Request.Operation == "Stat",
            "Windows paths and case-insensitive aliases route to the correct server-relative path");
        await router.CallAsync(new()
        {
            Operation = "Stat",
            Path = "/Office/Team/ leading-space.txt"
        });
        check(office.Calls.Last().Request.Path == "/Team/ leading-space.txt",
            "Server routing preserves valid Windows child filenames that begin with spaces");
        check(router.MaxTransferSizeFor("/Office/Team/data.bin") == Wire.MaxChunk &&
            router.MaxTransferSizeFor("/Home/Team/data.bin") == Wire.LegacyMaxChunk,
            "Transfer chunk limits are selected independently for each server");

        var officeOpen = router.Call(new()
        {
            Operation = "Open",
            Path = "/Office/Team/data.bin",
            Access = AccessMask.GenericRead
        });
        var homeOpen = router.Call(new()
        {
            Operation = "Open",
            Path = "/Home/Team/data.bin",
            Access = AccessMask.GenericRead
        });
        check(officeOpen.Response.Handle != Guid.Empty && homeOpen.Response.Handle != Guid.Empty &&
            officeOpen.Response.Handle != homeOpen.Response.Handle && officeOpen.Response.Handle != office.RemoteHandle &&
            homeOpen.Response.Handle != home.RemoteHandle && officeOpen.Generation == homeOpen.Generation,
            "Identical remote handle IDs and generations on different servers receive distinct local handles");

        var officeRead = router.Call(new()
        {
            Operation = "Read",
            Path = "/Office/Team/data.bin",
            Handle = officeOpen.Response.Handle,
            Count = 1
        }, officeOpen.Generation);
        var homeRead = await router.CallAsync(new()
        {
            Operation = "Read",
            Path = "/Home/Team/data.bin",
            Handle = homeOpen.Response.Handle,
            Count = 1
        }, homeOpen.Generation);
        check(officeRead.Response.Data is [11] && homeRead.Response.Data is [22] &&
            office.Calls.Last().Request.Handle == office.RemoteHandle && home.Calls.Last().Request.Handle == home.RemoteHandle &&
            office.Calls.Last().ExpectedGeneration == office.Generation && home.Calls.Last().ExpectedGeneration == home.Generation,
            "Local handles retain their owning server, remote handle, and child connection generation");

        var before = office.Calls.Count + home.Calls.Count;
        Expect("InvalidHandle", () => router.Call(new() { Operation = "Read", Path = "/Office/Team/data.bin", Handle = officeOpen.Response.Handle, Count = 1 }, officeOpen.Generation + 1), check,
            "A stale local generation is rejected before forwarding IO");
        Expect("InvalidHandle", () => router.Call(new() { Operation = "Read", Path = "/Office/Team/data.bin", Handle = homeOpen.Response.Handle, Count = 1 }, homeOpen.Generation), check,
            "A handle cannot be redirected through a different server folder");
        check(office.Calls.Count + home.Calls.Count == before, "Rejected local handle operations contact neither endpoint");

        foreach (var handle in new[] { Guid.Empty, officeOpen.Response.Handle })
            Expect("NotSameDevice", () => router.Call(new() { Operation = "Move", Path = "/Office/Team/data.bin", Destination = "/Home/Team/moved.bin", Handle = handle }, handle == Guid.Empty ? null : officeOpen.Generation), check,
                "Cross-server moves are rejected before any remote mutation");
        check(office.Calls.Count + home.Calls.Count == before, "Cross-server move rejection sends no request to either server");

        router.Call(new()
        {
            Operation = "Move",
            Path = "/Office/Team/data.bin",
            Destination = "/Office/Team/moved.bin",
            Handle = officeOpen.Response.Handle
        }, officeOpen.Generation);
        check(office.Calls.Last() is { Request.Operation: "Move", Request.Path: "/Team/data.bin", Request.Destination: "/Team/moved.bin" } &&
            office.Calls.Last().Request.Handle == office.RemoteHandle,
            "A move within one server strips the alias from both source and destination");

        router.Call(new()
        {
            Operation = "Cleanup",
            Path = "/Office/Team/moved.bin",
            Handle = officeOpen.Response.Handle
        }, officeOpen.Generation);
        var paging = router.Call(new()
        {
            Operation = "Read",
            Path = "/Office/Team/moved.bin",
            Handle = officeOpen.Response.Handle,
            Count = 1,
            PagingIo = true
        }, officeOpen.Generation);
        check(paging.Response.Data is [11] && office.Calls.Last().Request.PagingIo,
            "Cleanup retains the server mapping for late paging IO until final close");
        router.Call(new()
        {
            Operation = "Close",
            Path = "/Office/Team/moved.bin",
            Handle = officeOpen.Response.Handle
        }, officeOpen.Generation);
        before = office.Calls.Count + home.Calls.Count;
        Expect("InvalidHandle", () => router.Call(new() { Operation = "Read", Path = "/Office/Team/moved.bin", Handle = officeOpen.Response.Handle, Count = 1 }, officeOpen.Generation), check,
            "Final close removes the local handle mapping");
        check(office.Calls.Count + home.Calls.Count == before &&
            router.Call(new() { Operation = "Read", Path = "/Home/Team/data.bin", Handle = homeOpen.Response.Handle, Count = 1 }, homeOpen.Generation).Response.Data is [22],
            "Closing one server's handle leaves a colliding handle on another server usable");

        home.Generation++;
        Expect("InvalidHandle", () => router.Call(new() { Operation = "Read", Path = "/Home/Team/data.bin", Handle = homeOpen.Response.Handle, Count = 1 }, homeOpen.Generation), check,
            "A reconnected child cannot inherit a handle from its earlier generation");
        check(home.Calls.Last().ExpectedGeneration == homeOpen.Generation,
            "The router retains the original child generation instead of rebinding stale handles");

        before = office.Calls.Count + home.Calls.Count;
        Expect("NotFound", () => router.Call(new() { Operation = "Stat", Path = "/Unknown/Team/file" }), check,
            "An unconfigured server alias is not routed to an arbitrary endpoint");
        Expect("InvalidParameter", () => router.Call(new() { Operation = "Stat", Path = "/Office/../Home/Team/file" }), check,
            "Traversal cannot cross synthetic server folders");
        check(office.Calls.Count + home.Calls.Count == before, "Invalid server paths fail before contacting an endpoint");

        var statuses = await router.RefreshAsync(CancellationToken.None);
        before = office.Calls.Count + home.Calls.Count;
        var space = router.Call(new()
        {
            Operation = "Space",
            Path = "/"
        }).Response;
        var officeSpace = router.Call(new()
        {
            Operation = "Space",
            Path = "/Office"
        }).Response;
        check(statuses.Count == 2 && statuses.All(status => status.Connected) && space.FreeBytes == 300 && space.TotalBytes == 3000 &&
            officeSpace.FreeBytes == 100 && officeSpace.TotalBytes == 1000 && office.Calls.Count + home.Calls.Count == before,
            "Root and server-folder capacity use cached independent probes without synchronous network IO");
    }

    private static async Task FailureIsolation(Action<bool, string> check)
    {
        var healthy = new FakeConnection(31) { FreeBytes = 80, TotalBytes = 800 };
        var pending = new FakeConnection(32) { Failure = "PendingApproval" };
        using (var router = new MultiServerConnection(new (string, IRemoteConnection)[] { ("Ready", healthy), ("Waiting", pending) }))
        {
            var statuses = await router.RefreshAsync(CancellationToken.None);
            var root = router.Call(new()
            {
                Operation = "List",
                Path = "/"
            }).Response;
            check(statuses.Single(status => status.Name == "Ready").Connected &&
                statuses.Single(status => status.Name == "Waiting") is { Connected: false, Error: "PendingApproval" } &&
                root.Entries!.Select(entry => entry.Name).ToHashSet(StringComparer.Ordinal).SetEquals(new[] { "Ready" }),
                "Pending server settings retain their approval status while only a healthy server appears on the drive");
            Expect("NotFound", () => router.Call(new() { Operation = "List", Path = "/Waiting" }), check,
                "A pending server has no mounted folder until authenticated connection succeeds");
            var file = router.Call(new()
            {
                Operation = "Open",
                Path = "/Ready/Team/file",
                Access = AccessMask.GenericRead
            });
            check(router.Call(new() { Operation = "Read", Path = "/Ready/Team/file", Handle = file.Response.Handle, Count = 1 }, file.Generation).Response.Data is [31],
                "A failed or pending endpoint does not interrupt another server's file IO");
            var space = router.Call(new()
            {
                Operation = "Space",
                Path = "/"
            }).Response;
            check(space.FreeBytes == 80 && space.TotalBytes == 800,
                "Unavailable endpoints do not contribute unprobed capacity to the drive");
        }
        check(healthy.Disposed && pending.Disposed, "Disposing the aggregate connection releases each child connection");

        using (var router = new MultiServerConnection(new (string, IRemoteConnection)[]
            { ("Ready", new FakeConnection(61)), ("ChangedKey", new FakeConnection(62) { FailureException = new ServerIdentityMismatchException() }) }))
        {
            var statuses = await router.RefreshAsync(CancellationToken.None);
            check(statuses.Single(status => status.Name == "Ready").Connected &&
                statuses.Single(status => status.Name == "ChangedKey") is { Connected: false, Error: "ServerIdentityChanged" },
                "A server pin mismatch fails closed for that endpoint without faulting a healthy peer");
            Expect("NotFound", () => router.Call(new() { Operation = "List", Path = "/ChangedKey" }), check,
                "A server with a changed identity has no mounted folder and its pin remains unchanged");
        }

        using (var router = new MultiServerConnection(new (string, IRemoteConnection)[]
            { ("Pending", new FakeConnection(51) { Failure = "PendingApproval" }), ("Offline", new FakeConnection(52) { Failure = "Disconnected" }) }))
        {
            var statuses = await router.RefreshAsync(CancellationToken.None);
            var listing = router.Call(new()
            {
                Operation = "List",
                Path = "/"
            }).Response;
            var space = router.Call(new()
            {
                Operation = "Space",
                Path = "/"
            }).Response;
            check(statuses.All(status => !status.Connected) && listing.Entries is { Count: 0 } &&
                space.FreeBytes == 0 && space.TotalBytes == 0,
                "The drive root stays usable even when every server is offline or awaiting approval");
        }

        var ready = new FakeConnection(41);
        var slow = new FakeConnection(42) { StallProbe = true };
        using (var router = new MultiServerConnection(new (string, IRemoteConnection)[] { ("Ready", ready), ("Slow", slow) }))
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var statuses = await router.RefreshAsync(timeout.Token).WaitAsync(timeout.Token);
            check(statuses.Single(status => status.Name == "Ready").Connected && !statuses.Single(status => status.Name == "Slow").Connected,
                "A healthy server becomes ready without waiting for a stalled peer's network timeout");
            check(router.Call(new()
            {
                Operation = "List",
                Path = "/"
            }).Response.Entries!.Count == 1,
                "A stalled probe leaves the healthy server visible and never blocks root enumeration");
        }
        check(slow.Disposed && slow.ProbeToken.IsCancellationRequested, "Aggregate shutdown cancels and disposes a stalled child probe");
    }

    private static async Task OfflineRecovery(Action<bool, string> check)
    {
        const string folder = "Archives_aaaaaaaaaaaaaaaa";
        var savedIdentity = new string('a', 64);
        var archive = new FakeConnection(91);
        var healthy = new FakeConnection(92);
        using var router = new MultiServerConnection(new[]
        {
            ("archive", (IRemoteConnection)archive, (Func<string?>)(() => folder), (Func<string?>)(() => savedIdentity)),
            ("healthy", (IRemoteConnection)healthy, (Func<string?>)(() => "Other_bbbbbbbbbbbbbbbb"), (Func<string?>)(() => new string('b', 64)))
        });
        check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 } && router.Statuses.Count == 2,
            "Remembered server identities stay configured but create no folders before successful connection");
        await router.RefreshAsync(CancellationToken.None);
        check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 2 },
            "Successful authenticated probes reveal both configured server folders");
        var opened = router.Call(new()
        {
            Operation = "Open",
            Path = "/" + folder + "/Team/file",
            Access = AccessMask.GenericRead
        });
        archive.ReadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        archive.ReleaseRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var inFlight = router.CallAsync(new()
        {
            Operation = "Read",
            Path = "/" + folder + "/Team/file",
            Handle = opened.Response.Handle,
            Count = 1
        }, opened.Generation);
        await archive.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        archive.Failure = "Disconnected";
        Expect("Disconnected", () => router.Call(new() { Operation = "List", Path = "/" + folder }), check,
            "An IO disconnect records the failed server without affecting other endpoints");
        archive.ReleaseRead.SetResult();
        check((await inFlight).Response.Data is [91] && router.Call(new() { Operation = "List" }).Response.Entries is [{ Name: "Other_bbbbbbbbbbbbbbbb" }],
            "An older in-flight success cannot resurrect a folder after a newer disconnect");
        await router.RefreshAsync(CancellationToken.None);
        check(router.Statuses.Any(status => status.Name == folder && !status.Connected && status.Error == "Disconnected") &&
            router.Call(new() { Operation = "List" }).Response.Entries is [{ Name: "Other_bbbbbbbbbbbbbbbb" }] && savedIdentity == new string('a', 64),
            "Failed periodic retries keep an offline folder hidden while retaining its remembered identity and status");
        Expect("NotFound", () => router.Call(new() { Operation = "Stat", Path = "/" + folder }), check,
            "An offline server folder is absent for direct path lookups as well as root listings");
        archive.Failure = null;
        await router.RefreshAsync(CancellationToken.None);
        check(router.Call(new()
        {
            Operation = "List"
        }).Response.Entries!.Select(entry => entry.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(new[] { folder, "Other_bbbbbbbbbbbbbbbb" }) && router.Statuses.All(status => status.Connected),
            "A later successful probe restores the same server folder without reconfiguring the shared drive");

        var probed = new FakeConnection(93);
        using var single = new MultiServerConnection(new (string, IRemoteConnection)[] { ("Probed", probed) });
        await single.RefreshAsync(CancellationToken.None);
        probed.DelayedOperation = "Space";
        probed.ReadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        probed.ReleaseRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var staleProbe = single.RefreshAsync(CancellationToken.None);
        await probed.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        probed.Failure = "Disconnected";
        Expect("Disconnected", () => single.Call(new() { Operation = "List", Path = "/Probed" }), check,
            "A file request can report a disconnect while an older heartbeat probe is still completing");
        probed.ReleaseRead.SetResult();
        await staleProbe;
        check(single.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 } && !single.Statuses.Single().Connected,
            "A stale successful heartbeat cannot override a more recent connection failure");
    }

    private static void Expect(string code, Action action, Action<bool, string> check, string label)
    {
        try
        {
            action();
        }
        catch (RemoteException ex) when (ex.Code == code) { check(true, label); return; }
        throw new InvalidOperationException("Expected " + code + ": " + label);
    }

    private sealed record Invocation(RpcRequest Request, long? ExpectedGeneration);

    private sealed class FakeConnection(byte marker) : IRemoteConnection, IDisposable
    {
        // Deliberately collide across independent server sessions.
        public Guid RemoteHandle { get; } = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        public long Generation { get; set; } = 17;
        public int MaxTransferSize { get; init; } = Wire.MaxChunk;
        public long FreeBytes
        {
            get; init;
        }
        public long TotalBytes
        {
            get; init;
        }
        public string? Failure
        {
            get; set;
        }
        public Exception? FailureException
        {
            get; init;
        }
        public bool StallProbe
        {
            get; init;
        }
        public CancellationToken ProbeToken
        {
            get; private set;
        }
        public bool Disposed
        {
            get; private set;
        }
        public ConcurrentQueue<Invocation> Calls { get; } = new();
        public TaskCompletionSource? ReadStarted
        {
            get; set;
        }
        public TaskCompletionSource? ReleaseRead
        {
            get; set;
        }
        public string DelayedOperation { get; set; } = "Read";

        public RemoteReply Call(RpcRequest request, long? expectedGeneration = null)
        {
            Calls.Enqueue(new(request, expectedGeneration));
            if (FailureException is not null)
                throw FailureException;
            if (Failure is not null)
                throw new RemoteException(Failure);
            if (expectedGeneration is not null && expectedGeneration != Generation)
                throw new RemoteException("InvalidHandle");
            var response = request.Operation switch
            {
                "Open" => new RpcResponse { Handle = RemoteHandle, Entry = Entry("file", false) },
                "Read" => new RpcResponse { Data = [marker] },
                "List" => new RpcResponse { Entries = [Entry("Team", true)] },
                "Stat" => new RpcResponse { Entry = Entry("file", false) },
                "Space" => new RpcResponse { FreeBytes = FreeBytes, TotalBytes = TotalBytes },
                "Write" => new RpcResponse { Length = request.DataCount },
                _ => new RpcResponse()
            };
            return new(response, Generation);
        }

        public async Task<RemoteReply> CallAsync(RpcRequest request, long? expectedGeneration = null, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            if (StallProbe && request.Operation == "Ping")
            {
                ProbeToken = token;
                Calls.Enqueue(new(request, expectedGeneration));
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            }
            var result = Call(request, expectedGeneration);
            if (request.Operation == DelayedOperation && ReleaseRead is { } release)
            {
                ReadStarted?.TrySetResult();
                await release.Task.WaitAsync(token);
            }
            return result;
        }

        public void Dispose() => Disposed = true;
        private static RemoteEntry Entry(string name, bool directory) => new(name,
            directory ? FileAttributes.Directory : FileAttributes.Normal, directory ? 0 : 1,
            DateTime.UnixEpoch, DateTime.UnixEpoch, DateTime.UnixEpoch, Permission.FullControl);
    }
}
