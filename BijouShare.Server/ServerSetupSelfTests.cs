using System.Net;
using System.Net.Sockets;
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
        var root = Path.GetFullPath(Path.Combine("artifacts", "server-setup-tests", Guid.NewGuid().ToString("N")));
        var options = new ServerOptions { DataDirectory = root };
        var store = new StateStore(options);
        var publicKey = store.ServerPublicKey;
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
        Check(store.ServerPublicKey == publicKey && store.ServerId == ServerIdentityNaming.Id("ChosenServer", Convert.FromBase64String(publicKey)),
            "Web setup preserves the generated server identity key while binding its ID to the chosen name");
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
        Console.WriteLine($"Server setup: {count} checks passed.");
    }
}
