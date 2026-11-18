using System.Text;
using DokanNet;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Client;

internal static class ClientManagementSelfTests
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        var directory = Path.Combine(Path.GetTempPath(), "BijouShare-management-tests", Guid.NewGuid().ToString("N"));
        try
        {
            using var lease = StorageLease.Acquire(directory);
            var path = Path.Combine(directory, "client.json");
            var settings = ClientSettings.Create("Before setup");
            settings.SetupComplete = false;
            settings.AttachPath(path);
            using var router = new MultiServerConnection(settings, NullLoggerFactory.Instance);
            var drive = new ClientDriveState();
            var management = new ClientManagement(settings, router, NullLoggerFactory.Instance, drive);
            check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 } &&
                (await router.RefreshAsync(CancellationToken.None)).Count == 0 && router.Call(new()
                {
                    Operation = "Space"
                }).Response.TotalBytes == 0,
                "A client with no configured servers provides an empty, responsive virtual drive namespace");
            var operations = new DriveOperations(router, NullLogger<DriveOperations>.Instance);
            check(operations.FindFilesWithPattern("\\", "*", out var rootEntries, new MockDokanFileInfo()) == NtStatus.Success &&
                rootEntries.Select(entry => entry.FileName).SequenceEqual(new[] { ".", ".." }) &&
                rootEntries.All(entry => entry.Attributes == FileAttributes.Directory),
                "An empty mounted root supplies dot entries so native readers distinguish it from a missing directory");
            check(operations.FindFilesWithPattern("\\", "*.txt", out var matchingEntries, new MockDokanFileInfo()) == NtStatus.Success &&
                matchingEntries.Count == 0,
                "Empty-root dot entries respect native wildcard filtering");
            var invite = new string('A', 32);
            await management.AddServerAsync(new("127.0.0.1", 1, invite));
            var endpoint = settings.ServerSnapshot().Single();
            check(!File.Exists(path) && !settings.SetupComplete && router.Statuses.Count == 0,
                "Opening a server invite before first setup queues it without connecting or persisting an unfinished device");
            var snapshot = Encoding.UTF8.GetString(Wire.Encode(management.Snapshot()));
            check(!snapshot.Contains(invite, StringComparison.Ordinal) && !snapshot.Contains(settings.PublicKey, StringComparison.Ordinal) &&
                !snapshot.Contains("protectedPrivateKey", StringComparison.OrdinalIgnoreCase) && !snapshot.Contains("protectedInvite", StringComparison.OrdinalIgnoreCase),
                "Client management snapshots expose no invite or device private-key material");
            using var global = KeyAgreement.NewKey();
            var publicKey = global.ExportSubjectPublicKeyInfo();
            endpoint.ServerPublicKey = Convert.ToBase64String(publicKey);
            endpoint.SetIdentity(ServerIdentityNaming.Id("SavedServer", publicKey), "SavedServer", Convert.ToBase64String(publicKey));
            var configured = Wire.Encode(settings);
            router.Synchronize(settings, NullLoggerFactory.Instance);
            await router.RefreshAsync(CancellationToken.None);
            check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 } && !router.Statuses.Single().Connected &&
                settings.ServerSnapshot().Single().FolderName == endpoint.FolderName && Wire.Encode(settings).SequenceEqual(configured),
                "A remembered server that cannot reconnect keeps its keys and settings while its root folder stays hidden");
            await management.RemoveServerAsync(endpoint.Host, endpoint.Port);
            check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 } && router.Statuses.Count == 0 &&
                settings.ServerSnapshot().Length == 0 && settings.Host.Length == 0,
                "Removing the final server clears its routes and legacy endpoint while retaining the empty drive namespace");
            var id = settings.DeviceId;
            var key = settings.PublicKey;
            var available = ClientManagement.AvailableDriveLetters().FirstOrDefault();
            if (available is not null)
            {
                await management.UpdateDeviceAsync("My configured laptop", available);
                var reloaded = ClientSettings.Load(path);
                check(reloaded.SetupComplete && reloaded.DeviceName == "My configured laptop" && reloaded.MountPoint == available &&
                    reloaded.DeviceId == id && reloaded.PublicKey == key && reloaded.ServerSnapshot().Length == 0,
                    "Web setup persists the chosen device name and empty drive without replacing the persistent device identity");
                try
                {
                    await management.UpdateDeviceAsync("Invalid update", Path.GetPathRoot(Environment.SystemDirectory)!);
                    throw new InvalidOperationException("An occupied drive letter was accepted.");
                }
                catch (ArgumentException)
                {
                    check(settings.DeviceName == "My configured laptop" && settings.MountPoint == available,
                        "An occupied drive letter is rejected without partially changing device settings");
                }
            }
            check(ClientActivation.PipeName(directory) == ClientActivation.PipeName(directory.ToUpperInvariant()) &&
                ClientActivation.PipeName(directory) != ClientActivation.PipeName(directory + "-other"),
                "Client activation isolates data directories while preserving Windows path case equivalence");
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }
}
