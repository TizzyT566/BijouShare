using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using DokanNet;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class MultiServerSelfTests
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        await RoutingAndHandles(check);
        await ServerPermissions(check);
        await FailureIsolation(check);
        await InviteNotices(check);
        await EnrollmentLoss(check);
        await AuthenticatedNames(check);
        await OfflineRecovery(check);
        await WakeRecoveryWindow(check);
        await DeferredCloses(check);
        await ResumeDuringHandshake(check);
    }

    private static async Task EnrollmentLoss(Action<bool, string> check)
    {
        var remote = new FakeConnection(19);
        using var router = new MultiServerConnection([("Archive", (IRemoteConnection)remote)]);
        var revoked = 0;
        router.EnrollmentRevoked += () => Interlocked.Increment(ref revoked);
        async Task Probe(string? error)
        {
            remote.Failure = error;
            await router.RefreshAsync(CancellationToken.None);
        }
        foreach (var code in new[] { "PendingApproval", "InviteRequired", "DeviceRejected", "DeviceBlocked" })
            await Probe(code);
        check(revoked == 0, "A new registration that has never been admitted cannot revoke drive access");
        await Probe(null);
        foreach (var code in new[] { "Disconnected", "Timeout", "ConfigurationError", "AccessDenied", "InvalidInvite" })
            await Probe(code);
        check(revoked == 0, "Transport loss, file permission denials, and transient enrollment errors preserve elevated access");
        await Probe("PendingApproval");
        await Probe("Disconnected");
        await Probe("PendingApproval");
        await Probe("InviteRequired");
        check(revoked == 1, "An admitted device returning to enrollment reports one kick across subsequent outages and retries");
        foreach (var code in new[] { "InviteRequired", "DeviceBlocked", "DeviceRejected" })
        {
            await Probe(null);
            await Probe(code);
        }
        check(revoked == 4, "A fresh admission allows the drive to act on subsequent server blocks or enrollment withdrawals");
        await Probe(null);
        void FailOnce() => throw new IOException("Simulated grant-store write failure.");
        router.EnrollmentRevoked += FailOnce;
        try { await Probe("DeviceBlocked"); throw new InvalidOperationException("A failed revocation was acknowledged."); }
        catch (IOException) { }
        finally { router.EnrollmentRevoked -= FailOnce; }
        await Probe("DeviceBlocked");
        check(revoked == 6, "A failed revocation is retried when the server reaffirms the block");
    }

    private static async Task InviteNotices(Action<bool, string> check)
    {
        var remote = new FakeConnection(37) { Failure = "InviteRequired" };
        const string address = "archive.test:7443";
        using var router = new MultiServerConnection([(address, (IRemoteConnection)remote,
            (Func<string?>)(() => "Archive"), (Func<string?>)(() => null))]);
        var notices = new ConcurrentQueue<string>();
        router.InviteRequired += endpoint => notices.Enqueue(ClientTray.InviteRequiredNotice("N:", endpoint));
        // Activating a wad link requests an asynchronous refresh through this same path.
        router.RequestRefresh();
        await router.RefreshAsync(CancellationToken.None);
        remote.Failure = "Disconnected";
        await router.RefreshAsync(CancellationToken.None);
        remote.Failure = "InviteRequired";
        await router.RefreshAsync(CancellationToken.None);
        check(notices.TryDequeue(out var notice) && notices.IsEmpty && notice.Contains(address, StringComparison.Ordinal) &&
            notice.Contains("N:", StringComparison.Ordinal) && notice.Contains("This server is invite only.", StringComparison.Ordinal),
            "An invite-only server triggers one desktop notice with its endpoint and drive across retries");
        remote.Failure = null;
        await router.RefreshAsync(CancellationToken.None);
        remote.Failure = "InviteRequired";
        await router.RefreshAsync(CancellationToken.None);
        check(notices.Count == 1, "A new invite rejection after reconnecting can notify the user again");
    }

    private static async Task ServerPermissions(Action<bool, string> check)
    {
        var remote = new FakeConnection(71) { Granted = Permission.ReadAttributes | Permission.WriteData };
        var id = new string('a', 64);
        using var router = new MultiServerConnection(new (string, IRemoteConnection, Func<string?>, Func<string?>)[]
            { ("Server", remote, () => "Server", () => id) });
        await router.RefreshAsync(CancellationToken.None);
        var opened = router.Call(new() { Operation = "Open", Path = "/Server/Share/file", Access = AccessMask.WriteData });
        check(opened.Response.Entry!.Permissions == remote.Granted &&
            router.Call(new() { Operation = "Security", Path = "/Server/Share/file" }).Response.Permissions == remote.Granted,
            "The client preserves permissions assigned by server groups on the first authenticated session");
        router.Call(new() { Operation = "Write", Handle = opened.Response.Handle, Data = [1], Path = "/Server/Share/file" }, opened.Generation);
        check(remote.Calls.Last().Request.Operation == "Write", "An authenticated write is forwarded to the server for authorization");
        var directory = router.Call(new() { Operation = "Open", Path = "/Server", Access = AccessMask.GenericRead });
        id = new string('c', 64);
        Expect("InvalidHandle", () => router.Call(new() { Operation = "List", Handle = directory.Response.Handle, Path = "/Server" },
            directory.Generation), check, "A directory handle cannot switch to a different identity under the same displayed name");
    }

    private static async Task ResumeDuringHandshake(Action<bool, string> check)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var settings = ClientSettings.Create("Wake test");
        settings.AddDrive("N:");
        var endpoint = settings.AddServer("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, null, trustedServerId: new string('a', 64));
        using var router = new MultiServerConnection(settings, NullLoggerFactory.Instance);
        router.RequestRefresh();
        using var first = await listener.AcceptTcpClientAsync(deadline.Token);
        var oldHello = await SecureTransport.ReadPlainAsync<ClientHello>(first.GetStream(), deadline.Token);
        var recovery = router.RecoverAfterResumeAsync(deadline.Token);
        using var second = await listener.AcceptTcpClientAsync(deadline.Token);
        var newHello = await SecureTransport.ReadPlainAsync<ClientHello>(second.GetStream(), deadline.Token);
        await recovery;
        check(oldHello.DeviceId == newHello.DeviceId && oldHello.ClientPublicKey == newHello.ClientPublicKey &&
            !oldHello.Nonce.SequenceEqual(newHello.Nonce) && endpoint.FolderName is null &&
            router.MountedServerFolders.Length == 0,
            "After resume, a stalled handshake is replaced promptly using the saved device identity without exposing an unverified folder");
        endpoint.InvalidateSessions();
        var fresh = router.RefreshAsync(deadline.Token);
        using var third = await listener.AcceptTcpClientAsync(deadline.Token);
        var refreshedHello = await SecureTransport.ReadPlainAsync<ClientHello>(third.GetStream(), deadline.Token);
        await fresh;
        check(refreshedHello.DeviceId == oldHello.DeviceId && !refreshedHello.Nonce.SequenceEqual(newHello.Nonce),
            "Invalidating a saved endpoint refreshes its stale connection on the next probe");
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
            openedFolder.Handle != Guid.Empty && openedFolder.Entry is { Name: "Office", IsDirectory: true } &&
            office.Calls.IsEmpty && home.Calls.IsEmpty,
            "Server folder metadata and read-only opens are synthetic and preserve the configured alias");

        foreach (var path in new[] { "/", "/Office" })
            Expect("AccessDenied", () => router.Call(new() { Operation = "Open", Path = path, Access = AccessMask.GenericWrite }), check,
                "The synthetic namespace rejects writable opens at " + path);
        var labelOpen = new RpcRequest { Operation = "Open", Path = "/", Mode = FileMode.Open, Access = AccessMask.WriteData | 0x100000 };
        check(router.Call(labelOpen).Response.Entry?.IsDirectory == true, "Explorer can open the volume root to set its label");
        Expect("AccessDenied", () => router.Call(labelOpen with { Path = "/Office" }), check, "A server folder is not a volume-label handle");
        Expect("AccessDenied", () => router.Call(labelOpen with { DeleteOnClose = true }), check, "A label open cannot delete the root");
        Expect("IsDirectory", () => router.Call(new() { Operation = "Write", Path = "/" }), check, "A label open cannot write data to the root");
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
        long now = 1_000;
        using var router = new MultiServerConnection(new[]
        {
            ("archive", (IRemoteConnection)archive, (Func<string?>)(() => folder), (Func<string?>)(() => savedIdentity)),
            ("healthy", (IRemoteConnection)healthy, (Func<string?>)(() => "Other_bbbbbbbbbbbbbbbb"), (Func<string?>)(() => new string('b', 64)))
        }, () => now);
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
        now += 5_000;
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
        var open = single.Call(new() { Operation = "Open", Path = "/Probed/Team/file", Access = AccessMask.GenericWrite });
        probed.Failure = "Timeout";
        await single.RecoverAfterResumeAsync(CancellationToken.None);
        probed.Failure = null;
        var write = single.Call(new() { Operation = "Write", Handle = open.Response.Handle, Path = "/Probed/Team/file", Data = [42] }, open.Generation);
        check(single.Statuses.Single().Connected && write.Response.Length == 1,
            "An unsent wake probe on a busy session preserves the connected folder and existing writer");
        single.Call(new() { Operation = "Close", Handle = open.Response.Handle, Path = "/Probed/Team/file" }, open.Generation);
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

    private static async Task WakeRecoveryWindow(Action<bool, string> check)
    {
        const string folder = "Archive_aaaaaaaaaaaaaaaa";
        var identity = new string('a', 64);
        var verified = new FakeConnection(33);
        var unverified = new FakeConnection(34) { Failure = "Disconnected" };
        long now = 100;
        using var router = new MultiServerConnection(new[]
        {
            ("archive", (IRemoteConnection)verified, (Func<string?>)(() => folder), (Func<string?>)(() => identity)),
            ("unverified", (IRemoteConnection)unverified, (Func<string?>)(() => "Unseen"), (Func<string?>)(() => identity))
        }, () => now);
        await router.RefreshAsync(CancellationToken.None);
        verified.Failure = "Disconnected";
        Expect("Disconnected", () => router.Call(new() { Operation = "List", Path = "/" + folder }), check,
            "The first file request after adapter loss reports the transport failure");
        check(router.HasRecoveringFolders && router.MountedServerFolders.SequenceEqual([folder]) &&
            router.Statuses.All(status => !status.Connected),
            "A known folder briefly stays routable when I/O detects adapter loss before the Windows notification");
        now += 1_000;
        await router.RecoverAfterResumeAsync(CancellationToken.None);
        now += 15_000;
        await router.RecoverAfterResumeAsync(CancellationToken.None, resumed: false);
        check(router.MountedServerFolders.SequenceEqual([folder]) &&
            router.Call(new() { Operation = "Stat", Path = "/" + folder }).Response.Entry!.Name == folder,
            "Server paths survive delayed Wi-Fi recovery without exposing a never-connected endpoint");
        var calls = verified.Calls.Count;
        Expect("Disconnected", () => router.Call(new() { Operation = "Open", Path = "/" + folder + "/Team/file" }), check,
            "Access beneath a recovering folder still goes through the authenticated connection");
        check(verified.Calls.Count == calls + 1, "A recovering folder cannot fabricate a remote file handle");
        now += 15_000;
        check(router.Call(new() { Operation = "List" }).Response.Entries!.Count == 0 && !router.HasRecoveringFolders,
            "Repeated network notifications cannot keep an offline server visible beyond the original grace period");
        verified.Failure = null;
        await router.RefreshAsync(CancellationToken.None, retryOnly: true);
        check(router.MountedServerFolders.SequenceEqual([folder]), "A fresh probe restores the original folder after the grace period");
        await router.RecoverAfterResumeAsync(CancellationToken.None);
        verified.Failure = "Disconnected";
        await router.RefreshAsync(CancellationToken.None);
        verified.Failure = "DeviceBlocked";
        await router.RefreshAsync(CancellationToken.None, retryOnly: true);
        check(router.MountedServerFolders.Length == 0 && !router.HasRecoveringFolders &&
            router.Statuses.Any(status => status.Error == "DeviceBlocked"),
            "An explicit device block ends wake grace immediately and remains visible in connection status");
        calls = verified.Calls.Count;
        await router.RefreshAsync(CancellationToken.None, retryOnly: true);
        check(verified.Calls.Count == calls, "Fast recovery retries skip explicit enrollment failures");
    }

    private static async Task DeferredCloses(Action<bool, string> check)
    {
        var peer = new FakeConnection(35);
        var identity = new string('a', 64);
        using var router = new MultiServerConnection(new[]
        {
            ("archive", (IRemoteConnection)peer, (Func<string?>)(() => "Archive"), (Func<string?>)(() => identity))
        });
        await router.RefreshAsync(CancellationToken.None);
        var open = new RpcRequest { Operation = "Open", Path = "/Archive/Team/file", Access = AccessMask.WriteData };
        void MissClose(RemoteReply file)
        {
            peer.Failure = "Disconnected";
            Expect("Disconnected", () => router.Call(new()
            {
                Operation = "Close", Path = open.Path, Handle = file.Response.Handle
            }, file.Generation), check, "A final close reports loss of its transport");
            peer.Failure = null;
            peer.Calls.Clear();
        }

        var original = router.Call(open);
        peer.Failure = "Disconnected";
        Expect("Disconnected", () => router.Call(new()
        {
            Operation = "Cleanup", Path = open.Path, Handle = original.Response.Handle, DeleteOnClose = true
        }, original.Generation), check, "An unconfirmed cleanup with delete intent reports its error");
        MissClose(original);
        peer.DelayedOperation = "Close";
        peer.ReadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        peer.ReleaseRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstOpen = router.CallAsync(open);
        await peer.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var probe = router.RefreshAsync(CancellationToken.None);
        var otherOpen = router.CallAsync(open);
        var close = peer.Calls.Single(call => call.Request.Operation == "Close");
        check(close.ExpectedGeneration == original.Generation && close.Request.Handle == peer.RemoteHandle &&
            !close.Request.DeleteOnClose && close.Request.Path != open.Path && peer.Calls.All(call => call.Request.Operation != "Cleanup") &&
            !firstOpen.IsCompleted && !otherOpen.IsCompleted,
            "Concurrent reopens and probes wait for one exact-generation handle release without replaying delete intent");
        peer.ReleaseRead.SetResult();
        await Task.WhenAll(firstOpen, otherOpen, probe);
        check(peer.Calls.Count(call => call.Request.Operation == "Close") == 1 &&
            peer.Calls.Count(call => call.Request.Operation == "Open") == 2,
            "Both waiting opens proceed after a single recovery close");

        MissClose(firstOpen.Result);
        peer.CloseFailure = "InvalidHandle";
        await router.RefreshAsync(CancellationToken.None);
        await router.RefreshAsync(CancellationToken.None);
        check(peer.Calls.Count(call => call.Request.Operation == "Close") == 1 && router.Statuses.Single().Connected,
            "A close whose response was lost accepts an already-released handle exactly once");
        peer.CloseFailure = null;
        MissClose(otherOpen.Result);
        peer.CloseFailure = "OutcomeUnknown";
        await router.RefreshAsync(CancellationToken.None);
        check(router.Statuses.Single().Error == "Disconnected", "An uncertain release leaves the endpoint eligible for reconnect");
        peer.CloseFailure = null;
        peer.ReleaseRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await router.CallAsync(open).WaitAsync(TimeSpan.FromSeconds(15));
            throw new InvalidOperationException("A stalled deferred release admitted a new open");
        }
        catch (RemoteException ex) when (ex.Code == "Timeout")
        {
            check(peer.Calls.All(call => call.Request.Operation != "Open"), "A stalled release returns a timeout inside the Dokan callback budget");
        }
        peer.ReleaseRead.SetResult();
        await router.RefreshAsync(CancellationToken.None);
        check(router.Statuses.Single().Connected && peer.Calls.Count(call => call.Request.Operation == "Close") == 3,
            "An unfinished release survives both a lost outcome and the bounded drain deadline");
        MissClose(router.Call(open));
        peer.Generation++;
        await router.RefreshAsync(CancellationToken.None);
        check(peer.Calls.All(call => call.Request.Operation != "Close"), "A fresh lease discards old releases before dispatch");
        MissClose(router.Call(open));
        peer.Failure = "DeviceBlocked";
        await router.RefreshAsync(CancellationToken.None);
        peer.Failure = null;
        await router.RefreshAsync(CancellationToken.None);
        check(peer.Calls.All(call => call.Request.Operation != "Close"), "Revocation retires pending releases before re-enrollment");
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
        public Permission Granted { get; init; } = Permission.FullControl;
        // Deliberately collide across independent server sessions.
        public Guid RemoteHandle { get; } = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        public long Generation { get; set; } = 17;
        public string? CloseFailure { get; set; }
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
            if (request.Operation == "Close" && CloseFailure is { } closeFailure)
                throw new RemoteException(closeFailure);
            var response = request.Operation switch
            {
                "Open" => new RpcResponse { Handle = RemoteHandle, Entry = Entry("file", false) },
                "Read" => new RpcResponse { Data = [marker] },
                "List" => new RpcResponse { Entries = [Entry("Team", true)] },
                "Stat" => new RpcResponse { Entry = Entry("file", false) },
                "Security" => new RpcResponse { Permissions = Granted },
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
        private RemoteEntry Entry(string name, bool directory) => new(name,
            directory ? FileAttributes.Directory : FileAttributes.Normal, directory ? 0 : 1,
            DateTime.UnixEpoch, DateTime.UnixEpoch, DateTime.UnixEpoch, Granted);
    }
}
