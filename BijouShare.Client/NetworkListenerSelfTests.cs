using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using BijouShare.Shared;
using Microsoft.Extensions.Logging.Abstractions;

namespace BijouShare.Client;

internal static class NetworkListenerSelfTests
{
    internal static void Run(Action<bool, string> check)
    {
        string directory = Path.Combine(Path.GetTempPath(), "BijouShare-network-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "client.json");
            var settings = ClientSettings.Create("Network listener tests");
            settings.AttachPath(path);
            var id = new string('a', 64);
            var endpoint = settings.AddServer("127.0.0.1", 1, null, trustedServerId: id);
            var service = new NetworkServiceDescriptor(Guid.NewGuid(), "Test service", NetworkServiceProtocol.Both, 9, NetworkServiceAccess.Both);
            using var routes = new DriveConnections(settings, NullLoggerFactory.Instance);
            bool allow = false;
            IDisposable Guard(int port, NetworkServiceProtocol protocol) => allow ? new CancellationTokenSource()
                : throw new IOException("Windows could not protect this test listener.");
            using var manager = new NetworkServices(settings, routes, NullLoggerFactory.Instance, Guard);
            manager.ApplyCatalog(endpoint, [service], null);
            bool Reject(int port, string message)
            {
                try { manager.SetEnabledAsync(id, service.Id, true, port).GetAwaiter().GetResult(); return false; }
                catch (ArgumentException ex) { return ex.Message.Contains(message, StringComparison.OrdinalIgnoreCase); }
            }
            check(Reject(0, "65535") && Reject(65536, "65535"), "Network listeners reject local ports outside the TCP/UDP range");
            using var occupied = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)occupied.Client.LocalEndPoint!).Port;
            check(Reject(port, "protect"), "Local listeners fail closed when per-user protection is unavailable");
            allow = true;
            check(Reject(port, port.ToString()) && settings.NetworkListenerSnapshot().Length == 0,
                "A conflicting UDP port rolls back a dual-protocol listener without saving its selection");
            using (var reusable = new TcpListener(IPAddress.Loopback, port)) reusable.Start();
            occupied.Close();
            manager.SetEnabledAsync(id, service.Id, true, port).GetAwaiter().GetResult();
            try
            {
                var saved = ClientSettings.Load(path);
                check(saved.NetworkListenerSnapshot().Single().LocalPort == port,
                    "A listener's fingerprint, share and port persist in its Windows profile");
                manager.ApplyCatalog(endpoint, [], "Offline");
                bool Listening(NetworkServices source) => JsonSerializer.SerializeToElement(source.Snapshot(), Wire.Json)
                    .GetProperty("services")[0].GetProperty("listening").GetBoolean();
                check(Listening(manager) && settings.NetworkListenerSnapshot().Length == 1,
                    "A transient catalog failure preserves a listening service and its selection");
                manager.ApplyCatalog(endpoint, [], null);
                check(!Listening(manager), "Authoritative removal of a network service closes the listener");
                using var afterRestart = new NetworkServices(saved, routes, NullLoggerFactory.Instance, Guard);
                afterRestart.ApplyCatalog(saved.ServerSnapshot().Single(), [], "Waiting");
                check(Listening(afterRestart), "Restart during an outage reserves the protected port pending confirmed access");
                afterRestart.ApplyCatalog(saved.ServerSnapshot().Single(), [service], null);
                try { check(Listening(afterRestart), "An enabled listener binds its chosen port again when the server returns"); }
                finally { afterRestart.SetEnabledAsync(id, service.Id, false, null).GetAwaiter().GetResult(); }
                check(ClientSettings.Load(path).NetworkListenerSnapshot().Length == 0, "Disabling a listener persists across restarts");
            }
            finally { manager.SetEnabledAsync(id, service.Id, false, null).GetAwaiter().GetResult(); }
        }
        finally { Directory.Delete(directory, true); }
    }
}
