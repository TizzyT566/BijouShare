using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
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
            using var connections = new DriveConnections(settings, NullLoggerFactory.Instance);
            var drive = new ClientDriveState();
            var management = new ClientManagement(settings, connections, drive);
            check(connections.Snapshot().Length == 0, "A fresh client has no drive workers");
            var nonce = Guid.NewGuid();
            var activation = new[] { "--elevated-drive", "W:", "123", nonce.ToString("N") };
            check(ElevatedDriveHelper.TryParse(activation, out var letter, out var pid, out var proof) &&
                letter == 'W' && pid == 123 && proof == nonce, "The elevated helper accepts a single drive letter, worker PID and request nonce");
            foreach (var malformed in new[]
            {
                new[] { "--elevated-drive", @"W:\Windows", "123", nonce.ToString("N") },
                new[] { "--elevated-drive", "W:", "-1", nonce.ToString("N") },
                new[] { "--elevated-drive", "W:", "123", Guid.Empty.ToString("N") },
                new[] { "--elevated-drive", "W:", "123", nonce.ToString("N"), "program.exe" }
            })
                check(!ElevatedDriveHelper.TryParse(malformed, out _, out _, out _), "Malformed elevated activation is rejected before opening any pipe");
            var invite = new string('A', 32);
            using var ec = KeyAgreement.NewKey();
            using var kem = HybridKem.Generate();
            var fingerprint = DeviceIdentity.Id(ec.ExportSubjectPublicKeyInfo(), kem.ExportPublicKey());
            await management.AddServerAsync(WadUri.Parse($"wad://127.0.0.1:1/{fingerprint}#{invite}"));
            var endpoint = settings.ServerSnapshot().Single();
            var pinned = ClientSettings.Load(path).ServerSnapshot().Single();
            check(pinned.TrustedServerId == fingerprint && settings.ForServer(endpoint).GetInviteCode() == invite &&
                connections.Snapshot().Length == 0, "A queued server retains the link fingerprint and invite before drive setup");
            using (var restarted = new DriveConnections(ClientSettings.Load(path), NullLoggerFactory.Instance))
                check(!settings.SetupComplete && restarted.Snapshot().Length == 0 && connections.Snapshot().Length == 0,
                    "A queued invitation creates no drive or connection when restarting before setup");
            var snapshot = Encoding.UTF8.GetString(Wire.Encode(management.Snapshot()));
            check(!snapshot.Contains(invite, StringComparison.Ordinal) && !snapshot.Contains(settings.PublicKey, StringComparison.Ordinal) &&
                !snapshot.Contains("protectedPrivateKey", StringComparison.OrdinalIgnoreCase) &&
                !snapshot.Contains("protectedMlKemPrivateSeed", StringComparison.OrdinalIgnoreCase) &&
                !snapshot.Contains("protectedInvite", StringComparison.OrdinalIgnoreCase),
                "Client management snapshots expose no invite or device private-key material");
            var id = settings.DeviceId;
            var key = settings.PublicKey;
            await management.UpdateDeviceAsync("My configured laptop");
            try
            {
                await management.SetElevatedAccessAsync(Path.GetPathRoot(Environment.SystemDirectory)!, true, CancellationToken.None);
                throw new InvalidOperationException("An unconfigured letter accepted elevated access.");
            }
            catch (ArgumentException)
            {
                check(settings.DriveSnapshot().Length == 0, "Elevated access cannot target an arbitrary drive on the machine");
            }
            var reloaded = ClientSettings.Load(path);
            check(reloaded.SetupComplete && reloaded.DeviceName == "My configured laptop" && reloaded.DriveSnapshot().Length == 0 &&
                reloaded.DeviceId == id && reloaded.PublicKey == key && reloaded.ServerSnapshot().Length == 1 &&
                connections.Snapshot().Length == 0,
                "Web setup persists the chosen name without mounting a drive or connecting an unassigned server");
            try
            {
                await management.ChangeDriveAsync(Path.GetPathRoot(Environment.SystemDirectory)!, ClientManagement.DriveChange.Add, "Projects", CancellationToken.None);
                throw new InvalidOperationException("An occupied drive letter was accepted.");
            }
            catch (ArgumentException)
            {
                check(settings.DriveSnapshot().Length == 0, "An occupied letter cannot partially create a drive");
            }

            var available = ClientManagement.AvailableDriveLetters().FirstOrDefault();
            if (available is not null)
            {
                foreach (var invalid in new[] { null, "", "  ", "Name?", new string('x', 33) })
                {
                    try
                    {
                        await management.ChangeDriveAsync(available, ClientManagement.DriveChange.Add, invalid, CancellationToken.None);
                        throw new InvalidOperationException("An invalid drive name was accepted.");
                    }
                    catch (ArgumentException) { }
                }
                check(settings.DriveSnapshot().Length == 0, "The backend requires a valid name before adding a drive");
                await management.ChangeDriveAsync(available, ClientManagement.DriveChange.Add, "Projects", CancellationToken.None);
                try
                {
                    await management.SetElevatedAccessAsync(available, true, CancellationToken.None);
                    throw new InvalidOperationException("An unmounted drive accepted elevated access.");
                }
                catch (ArgumentException)
                {
                    await management.SetElevatedAccessAsync(available, false, CancellationToken.None);
                    check(drive.ElevatedStatus(available) == ("Disabled", null),
                        "An unmounted drive rejects elevated access and accepts an explicit disable");
                }
                var router = connections.ForDrive(available);
                await management.ChangeDriveAsync(available, ClientManagement.DriveChange.Rename, "Media Library", CancellationToken.None);
                check(!settings.TryRenameDrive(available, "Projects", "Obsolete") &&
                    ClientSettings.Load(path).GetDriveName(available) == "Media Library" &&
                    Encoding.UTF8.GetString(Wire.Encode(management.Snapshot())).Contains("Media Library") &&
                    ReferenceEquals(router, connections.ForDrive(available)),
                    "Renaming persists, updates the console and preserves the mounted router despite a stale Explorer observation");
                var configured = Wire.Encode(settings);
                await router.RefreshAsync(CancellationToken.None);
                check(router.Call(new() { Operation = "List" }).Response.Entries is { Count: 0 } && !router.Statuses.Single().Connected &&
                    settings.ServerSnapshot(available).Single().FolderName == endpoint.FolderName && Wire.Encode(settings).SequenceEqual(configured),
                    "Explicitly adding the first drive routes the queued server there and preserves its settings while offline");
                await management.RemoveServerAsync(endpoint.Host, endpoint.Port);
                check(router.Statuses.Count == 0 && settings.ServerSnapshot().Length == 0,
                    "Removing the final server keeps its configured drive");
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
                await management.ChangeDriveAsync(available, ClientManagement.DriveChange.Remove, null, CancellationToken.None);
                check(connections.Snapshot().Length == 0 && ClientSettings.Load(path).DriveSnapshot().Length == 0 &&
                    ClientSettings.Load(path).DriveNames.Count == 0 && !settings.TryRenameDrive(available, "Media Library", "Stale"),
                    "Removing the last empty drive leaves a persistent zero-drive client");
            }
            check(ClientActivation.PipeName(directory) == ClientActivation.PipeName(directory.ToUpperInvariant()) &&
                ClientActivation.PipeName(directory) != ClientActivation.PipeName(directory + "-other"),
                "Client activation isolates data directories while preserving Windows path case equivalence");
            await CheckMountHandoffAsync(path, check);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    private static async Task CheckMountHandoffAsync(string path, Action<bool, string> check)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var root = File.OpenHandle(path);
        var pipeName = $"BijouShare.test.{Guid.NewGuid():N}";
        using var pipe = ClientActivation.CreatePipe(pipeName);
        using var peer = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        using var process = Process.GetCurrentProcess();
        var handshake = MountAliasPipe.AuthorizeMountAsync(pipe, process, root, 'A', timeout.Token);
        await peer.ConnectAsync(timeout.Token);
        var payload = new byte[sizeof(long)];
        await peer.ReadExactlyAsync(payload, timeout.Token);
        check(BinaryPrimitives.ReadInt64LittleEndian(payload) == root.DangerousGetHandle().ToInt64() &&
            ClientActivation.VerifyServerExecutable(peer) == Environment.ProcessId,
            "Only the bound root handle is offered by the expected local process");
        await peer.WriteAsync(new byte[] { (byte)MountAliasReply.Ready }, timeout.Token);
        var ack = new byte[1];
        await peer.ReadExactlyAsync(ack, timeout.Token);
        await handshake;
        using var owner = WindowsIdentity.GetCurrent();
        var expectedLogon = ElevatedDriveAlias.AuthenticationId(owner.AccessToken);
        bool identified = false;
        pipe.RunAsClient(() =>
        {
            using var caller = WindowsIdentity.GetCurrent(ifImpersonating: true);
            identified = caller?.ImpersonationLevel == TokenImpersonationLevel.Identification &&
                caller.User == owner.User && ElevatedDriveAlias.AuthenticationId(caller.AccessToken) == expectedLogon;
        });
        check(identified, "The restore pipe verifies the caller's SID and logon with an identification-only token");
        pipe.Dispose();
        check(ack[0] == (byte)MountAliasReply.Ready && await peer.ReadAsync(ack, timeout.Token) == 0,
            "An acknowledged drive handoff ends as soon as the mount's pipe closes");

        var secondName = $"BijouShare.test.{Guid.NewGuid():N}";
        using var second = ClientActivation.CreatePipe(secondName);
        using var wrongPeer = new NamedPipeClientStream(".", secondName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        using var otherProcess = Process.GetProcessById(0);
        var refused = MountAliasPipe.AuthorizeMountAsync(second, otherProcess, root, 'A', timeout.Token);
        await wrongPeer.ConnectAsync(timeout.Token);
        try
        {
            await refused;
            throw new InvalidOperationException("A different client process obtained the drive handle.");
        }
        catch (IOException) { }
        second.Dispose();
        check(await wrongPeer.ReadAsync(ack, timeout.Token) == 0, "A different pipe client PID receives no mount proof");

        var thirdName = $"BijouShare.test.{Guid.NewGuid():N}";
        using var third = ClientActivation.CreatePipe(thirdName);
        using var waitingPeer = new NamedPipeClientStream(".", thirdName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        var midHandshake = MountAliasPipe.AuthorizeMountAsync(third, process, root, 'A', stop.Token);
        await waitingPeer.ConnectAsync(timeout.Token);
        await waitingPeer.ReadExactlyAsync(payload, timeout.Token);
        await stop.CancelAsync();
        try
        {
            await midHandshake;
            throw new InvalidOperationException("The worker acknowledged an interrupted mount handoff.");
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested && !timeout.IsCancellationRequested) { }
        third.Dispose();
        check(await waitingPeer.ReadAsync(ack, timeout.Token) == 0, "An unmount cancels a pending handoff without acknowledging it");
    }
}
