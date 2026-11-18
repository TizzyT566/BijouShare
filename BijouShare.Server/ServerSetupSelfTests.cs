using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class ServerSetupSelfTests
{
    public static async Task RunAsync()
    {
        var count = 0;
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        CheckStorageAcl(Check);
        await CheckTrayAsync(Check);
        var root = Path.GetFullPath(Path.Combine("artifacts", "server-setup-tests", Guid.NewGuid().ToString("N")));
        var options = new ServerOptions { DataDirectory = root };
        var store = new StateStore(options);
        var installDirectory = Directory.CreateDirectory(Path.Combine(root, "installer-directory"));
        using (ServiceStorageSetup.OpenDirectory(installDirectory))
        {
            try
            {
                Directory.Move(installDirectory.FullName, installDirectory.FullName + "-moved");
                throw new InvalidOperationException("The installer's open directory was renamed.");
            }
            catch (IOException ex) when ((ex.HResult & 0xffff) == 32)
            {
                Check(true, "Windows blocks renaming the data directory while the installer sets its permissions");
            }
        }
        installDirectory.Delete();
        var publicKey = store.ServerPublicKey;
        var kemPublicKey = store.ServerMlKemPublicKey;
        var initialRevision = store.Revision;
        Check(!store.IsInitialized && !File.Exists(Path.Combine(root, "state.json")),
            "A fresh server can start web setup without configured administrator credentials");
        const string password = "Setup-only-password-42!";
        foreach (var invalid in new (string? Server, string? Admin, string? Password, string? Confirmation)[]
        {
            (null, "operator", password, password), ("", "operator", password, password),
            ("two words", "operator", password, password), ("TestServer", null, password, password),
            ("TestServer", "", password, password), ("TestServer", " operator ", password, password),
            ("TestServer", "operator", null, null), ("TestServer", "operator", "", ""),
            ("TestServer", "operator", new string(' ', 14), new string(' ', 14)),
            ("TestServer", "operator", "short", "short"), ("TestServer", "operator", password, null),
            ("TestServer", "operator", password, ""), ("TestServer", "operator", password, password + "mismatch")
        })
        {
            try
            {
                store.TryCompleteSetup(invalid.Server, invalid.Admin, invalid.Password, invalid.Confirmation);
                throw new InvalidOperationException("Incomplete server setup was accepted.");
            }
            catch (ArgumentException) { }
        }
        Check(!store.IsInitialized && store.Revision == initialRevision && !File.Exists(Path.Combine(root, "state.json")),
            "All setup fields require valid explicit input without applying defaults or partially saving state");
        var attempts = await Task.WhenAll(new[] { "FirstAdmin", "SecondAdmin" }.Select(admin => Task.Run(() =>
            (Admin: admin, Completed: store.TryCompleteSetup("ChosenServer", admin, password, password)))));
        var winner = attempts.Single(attempt => attempt.Completed).Admin;
        Check(attempts.Count(attempt => attempt.Completed) == 1 && store.IsInitialized &&
            store.ServerName == "ChosenServer" && store.AuthenticateAdmin(winner, password) is not null,
            "Concurrent first-run setup commits exactly one administrator and the explicit server name");
        Check(store.ServerPublicKey == publicKey && store.ServerMlKemPublicKey == kemPublicKey &&
            store.ServerId == ServerIdentityNaming.Id(Convert.FromBase64String(publicKey), Convert.FromBase64String(kemPublicKey)),
            "Web setup retains the generated ECDH and ML-KEM server identity when setting the chosen name");
        var revision = store.Revision;
        var bytes = File.ReadAllBytes(Path.Combine(root, "state.json"));
        Check(!store.TryCompleteSetup("HijackedServer", "Attacker", "Another-password-42!", "Another-password-42!") &&
            store.Revision == revision && bytes.SequenceEqual(File.ReadAllBytes(Path.Combine(root, "state.json"))) &&
            store.AuthenticateAdmin(winner, password) is not null,
            "Completed setup cannot be replayed to reset credentials or replace server identity metadata");
        var reloaded = new StateStore(options);
        Check(reloaded.IsInitialized && reloaded.ServerName == "ChosenServer" && reloaded.ServerPublicKey == publicKey &&
            !reloaded.TryCompleteSetup("Again", "AnotherAdmin", password, password),
            "The one-time setup decision survives a server restart");

        DefaultHttpContext Context(string remote, string host, string? origin = null, string? fetchSite = null)
        {
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse(remote);
            context.Request.Scheme = "http";
            context.Request.Host = HostString.FromUriComponent(host);
            if (origin is not null)
                context.Request.Headers.Origin = origin;
            if (fetchSite is not null)
                context.Request.Headers["Sec-Fetch-Site"] = fetchSite;
            return context;
        }
        Check(ServerSetupSecurity.IsLocalRequest(Context("127.0.0.1", "127.0.0.1:5080", "http://127.0.0.1:5080")) &&
            ServerSetupSecurity.IsLocalRequest(Context("::1", "localhost:5080")) &&
            ServerSetupSecurity.IsLocalRequest(Context("::ffff:127.0.0.1", "127.0.0.1:5080")),
            "Server setup accepts same-origin loopback requests over IPv4, IPv6, and mapped IPv4");
        Check(!ServerSetupSecurity.IsLocalRequest(Context("192.168.1.2", "127.0.0.1:5080")) &&
            !ServerSetupSecurity.IsLocalRequest(Context("127.0.0.1", "attacker.invalid:5080")) &&
            !ServerSetupSecurity.IsLocalRequest(Context("127.0.0.1", "127.0.0.1:5080", "https://attacker.invalid")) &&
            !ServerSetupSecurity.IsLocalRequest(Context("127.0.0.1", "127.0.0.1:5080", fetchSite: "cross-site")),
            "Server setup rejects remote clients, foreign Hosts and Origins, and cross-site requests");
        var portProbe = new TcpListener(IPAddress.Loopback, 0);
        portProbe.Start();
        var filePort = ((IPEndPoint)portProbe.LocalEndpoint).Port;
        portProbe.Stop();
        var waitingOptions = new ServerOptions { DataDirectory = Path.Combine(root, "waiting-server"), ListenAddress = "127.0.0.1", Port = filePort };
        var waitingStore = new StateStore(waitingOptions);
        using var audit = new AuditLog(waitingStore, NullLogger<AuditLog>.Instance);
        using var files = new FileService(waitingStore, audit);
        using var server = new FileServer(waitingOptions, waitingStore, files, audit, NullLogger<FileServer>.Instance);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await server.StartAsync(deadline.Token);
        try
        {
            using var rejected = new TcpClient();
            try
            {
                await rejected.ConnectAsync(IPAddress.Loopback, filePort, deadline.Token);
                throw new InvalidOperationException("The file protocol started before web setup completed.");
            }
            catch (SocketException) { Check(true, "File connections and enrollment remain unavailable until initial setup is committed"); }
            waitingStore.TryCompleteSetup("ReadyServer", "FileAdmin", password, password);
            var connected = false;
            while (!deadline.IsCancellationRequested)
            {
                using var client = new TcpClient();
                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, filePort, deadline.Token);
                    connected = true;
                    break;
                }
                catch (SocketException) { await Task.Delay(50, deadline.Token); }
            }
            Check(connected, "Completing web setup starts the encrypted file listener without restarting the server");
        }
        finally { await server.StopAsync(CancellationToken.None); }
        // Simulate an address that is unavailable at startup, then supply an available local address on retry.
        var localAddresses = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses).Select(item => item.Address).ToHashSet();
        var absentAddress = Enumerable.Range(1, 254).Select(last => IPAddress.Parse($"192.0.2.{last}"))
            .FirstOrDefault(address => !localAddresses.Contains(address));
        if (absentAddress is not null)
        {
            waitingOptions.ListenAddress = absentAddress.ToString();
            var warning = new ListenerWarning();
            using var recovering = new FileServer(waitingOptions, waitingStore, files, audit, warning);
            using var recoveryDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await recovering.StartAsync(recoveryDeadline.Token);
            try
            {
                await warning.Seen.Task.WaitAsync(recoveryDeadline.Token);
                waitingOptions.ListenAddress = "127.0.0.1";
                while (true)
                {
                    using var client = new TcpClient();
                    try { await client.ConnectAsync(IPAddress.Loopback, filePort, recoveryDeadline.Token); break; }
                    catch (SocketException) { await Task.Delay(100, recoveryDeadline.Token); }
                }
                Check(true, "A file listener waiting for its LAN address resumes accepting connections without a service restart");
            }
            finally { await recovering.StopAsync(CancellationToken.None); }
        }
        Console.WriteLine($"Server setup: {count} checks passed.");
    }

    private static void CheckStorageAcl(Action<bool, string> check)
    {
        var administrator = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var ordinaryUser = new SecurityIdentifier("S-1-5-21-1-2-3-1002");
        var members = new HashSet<SecurityIdentifier> { administrator };
        const string protectedAcl = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)";
        var legacy = new RawSecurityDescriptor(protectedAcl + $"(A;OICI;FA;;;{administrator})");
        check(ServiceStorageSetup.IsTrusted(legacy, members),
            "Service setup adopts an administrator-owned legacy directory with an explicit grant to a verified local administrator");
        check(!ServiceStorageSetup.IsTrusted(legacy, new HashSet<SecurityIdentifier>()) &&
            !ServiceStorageSetup.IsTrusted(new RawSecurityDescriptor(protectedAcl + $"(A;OICI;FA;;;{administrator})(A;OICI;FA;;;{ordinaryUser})"), members),
            "A former administrator or a second unprivileged writer prevents storage adoption");
        check(!ServiceStorageSetup.IsTrusted(new RawSecurityDescriptor($"O:{administrator}D:P(A;OICI;FA;;;SY)"), members) &&
            !ServiceStorageSetup.IsTrusted(new RawSecurityDescriptor(protectedAcl + $"(A;OICIID;FA;;;{administrator})"), members),
            "Trusted storage ownership and explicit administrator grants remain required for adoption");
        foreach (var broadWriter in new[] { WellKnownSidType.WorldSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.BuiltinUsersSid })
        {
            var sid = new SecurityIdentifier(broadWriter, null);
            check(!ServiceStorageSetup.IsTrusted(new RawSecurityDescriptor(protectedAcl + $"(A;OICI;GW;;;{sid})"),
                new HashSet<SecurityIdentifier> { sid }), $"Service setup refuses a writable {broadWriter} ACL");
        }
    }

    private static async Task CheckTrayAsync(Action<bool, string> check)
    {
        check(ServerTray.LocalAddress(["http://127.0.0.1:0", "https://localhost:5443"]) == new Uri("https://localhost:5443") &&
            ServerTray.LocalAddress(["http://+:5200"]) == new Uri("http://127.0.0.1:5200") &&
            ServerTray.LocalAddress(["http://[::]:5200"]) == new Uri("http://[::1]:5200"),
            "The tray preserves configured management schemes and ports and maps wildcard listeners to loopback");
        check(ServerTray.LocalAddress(["file:///c:/", "https://outside.example", "http://person@localhost",
            "http://localhost/#data", "http://localhost/?x", "http://localhost/path"]) is null,
            "The server tray opens only local HTTP management roots");
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        using var original = ServerTray.ClaimStandaloneIcon(directory, out var first);
        using var duplicate = ServerTray.ClaimStandaloneIcon(directory + Path.DirectorySeparatorChar, out var second);
        using var separate = ServerTray.ClaimStandaloneIcon(directory + "-other", out var other);
        check(first && !second && other, "Interactive server icons deduplicate per data directory and session");

        await CheckCompanionLifetimeAsync(check);

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddHostedService<ServerTrayEndpoint>();
        await using var app = builder.Build();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        try
        {
            var expected = new Uri(app.Urls.Single());
            var actual = await ServerTrayEndpoint.ReadAsync((uint)Environment.ProcessId);
            check(actual == expected && actual.Port > 0,
                "The service tray channel returns the actual bound Kestrel address, including an ephemeral port");
            var probes = 0;
            var opened = new List<Uri>();
            await ServerTray.OpenWhenReadyAsync(token => ++probes switch
            {
                1 => Task.FromException<Uri?>(new IOException("The service pipe is starting.")),
                2 => Task.FromResult<Uri?>(null),
                _ => ServerTrayEndpoint.ReadAsync((uint)Environment.ProcessId, token)
            }, opened.Add, TimeSpan.FromSeconds(5));
            check(probes == 3 && opened.SequenceEqual([expected]),
                "Post-install startup waits for the server and opens its actual port exactly once");
            try
            {
                await ServerTray.OpenWhenReadyAsync(_ => Task.FromResult<Uri?>(null), opened.Add, TimeSpan.FromMilliseconds(20));
                throw new InvalidOperationException("A missing server endpoint was reported as open.");
            }
            catch (IOException)
            {
                check(opened.Count == 1, "Post-install startup times out without opening a guessed server address");
            }
        }
        finally { await app.StopAsync(); }

        const uint differentPid = uint.MaxValue;
        using var imposter = ServerTrayEndpoint.CreatePipe(differentPid);
        await CheckInteractivePipeAccessAsync(imposter.GetAccessControl(), check);
        try
        {
            var connected = imposter.WaitForConnectionAsync();
            var read = ServerTray.OpenWhenReadyAsync(token => ServerTrayEndpoint.ReadAsync(differentPid, token),
                _ => throw new InvalidOperationException("Opened an untrusted service address."), TimeSpan.FromSeconds(5));
            await connected.WaitAsync(TimeSpan.FromSeconds(5));
            await read;
            throw new InvalidOperationException("Accepted a tray pipe hosted by another process.");
        }
        catch (UnauthorizedAccessException)
        {
            check(true, "The tray rejects a pipe owned by a different process than the Windows service");
        }
    }

    private static async Task CheckCompanionLifetimeAsync(Action<bool, string> check)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var checks = 0;
        await ServerTray.WaitForCompanionExitAsync(closed.Task, () => ++checks == 3,
            TimeSpan.FromMilliseconds(5), deadline.Token);
        check(checks == 3, "The companion stays alive while service registration exists and exits when it disappears");

        var waitingForClose = ServerTray.WaitForCompanionExitAsync(closed.Task, () => false, TimeSpan.FromMinutes(1), deadline.Token);
        closed.SetResult();
        await waitingForClose.WaitAsync(TimeSpan.FromSeconds(2));
        check(!deadline.IsCancellationRequested, "Closing the tray message loop releases the installed companion without waiting for its next service check");

        var running = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var waitingForExit = ServerTray.WaitForCompanionExitAsync(running.Task, () => false, TimeSpan.FromMinutes(1), deadline.Token);
        deadline.Cancel();
        await waitingForExit.WaitAsync(TimeSpan.FromSeconds(2));
        check(!running.Task.IsCompleted, "The companion exits immediately on a user exit request with its service still registered");
    }

    private static async Task CheckInteractivePipeAccessAsync(PipeSecurity serviceAcl, Action<bool, string> check)
    {
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var grant = serviceAcl.GetAccessRules(true, false, typeof(SecurityIdentifier)).OfType<PipeAccessRule>()
            .Single(rule => rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Equals(interactive));
        check(grant.PipeAccessRights == (PipeAccessRights.ReadData | PipeAccessRights.WriteData |
            PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize),
            "The desktop pipe grant contains only data exchange, attribute read and synchronization rights");

        // In the usual in-process tests the client's full-control service-owner ACE masks missing desktop rights.
        // Give this test identity only the real desktop grant, including when tests run in a noninteractive session.
        using var identity = WindowsIdentity.GetCurrent();
        var acl = new PipeSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new PipeAccessRule(identity.User!, grant.PipeAccessRights, AccessControlType.Allow));
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-3-4"), // OWNER RIGHTS
            PipeAccessRights.Synchronize, AccessControlType.Allow));
        var pid = (uint)Environment.ProcessId;
        using var pipe = NamedPipeServerStreamAcl.Create($"BijouShare.Server.Tray.{pid}", PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 512, 512, acl);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var expected = new Uri("http://127.0.0.1:5382");
        var query = new byte[1];
        async Task ReplyAsync()
        {
            await pipe.WaitForConnectionAsync(deadline.Token);
            await pipe.ReadExactlyAsync(query, deadline.Token);
            await ServerTrayEndpoint.WriteAsync(pipe, expected, deadline.Token);
        }
        var reply = ReplyAsync();
        var result = ServerTrayEndpoint.ReadAsync(pid, deadline.Token);
        await Task.WhenAll(reply, result);
        check(query[0] == 1 && await result == expected,
            "A tray helper with only the interactive user's access opens the service pipe, verifies its PID and reads its web address");
    }

    private sealed class ListenerWarning : ILogger<FileServer>
    {
        public TaskCompletionSource Seen { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool IsEnabled(LogLevel level) => level == LogLevel.Warning;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? error, Func<TState, Exception?, string> formatter)
        {
            if (level == LogLevel.Warning)
                Seen.TrySetResult();
        }
    }
}
