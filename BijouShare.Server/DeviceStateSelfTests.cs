using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class DeviceStateSelfTests
{
    public static void Run(string root, Action<bool, string> check)
    {
        void Denied(Action action, string label)
        {
            try
            {
                action();
            }
            catch (Exception exception) when (exception is ArgumentException or UnauthorizedAccessException or InvalidDataException)
            {
                check(true, label);
                return;
            }
            throw new InvalidOperationException("FAIL: " + label);
        }
        var options = new ServerOptions { DataDirectory = Path.Combine(root, "device-state") };
        var store = new StateStore(options);
        var allow = new AppGroup(Guid.NewGuid(), "Allow");
        var deny = new AppGroup(Guid.NewGuid(), "Deny");
        var share = new ExportShare(Guid.NewGuid(), "Fixture", root, true);
        store.Update(state =>
        {
            state.Groups.AddRange([allow, deny]);
            state.Shares.Add(share);
            state.Rules.Add(new(Guid.NewGuid(), allow.Id, share.Id, "", Permission.FullControl, Permission.None, true));
            state.Rules.Add(new(Guid.NewGuid(), deny.Id, share.Id, "", Permission.None, Permission.ReadData, true));
            return true;
        });
        using var key = KeyAgreement.NewKey();
        using var otherKey = KeyAgreement.NewKey();
        var request = new EnrollmentRequest(Guid.NewGuid().ToString(), "Pending workstation", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        check(!store.QueueRegistration(request) && store.Read(state => state.Devices.Count == 0 && state.PendingDevices.Count == 1),
            "An unknown identity queues public approval information without gaining file access");
        var id = Guid.Parse(request.DeviceId);
        Denied(() => store.Identity(id), "A pending device cannot authenticate as an approved device");
        var revision = store.Revision;
        check(!store.QueueRegistration(request) && store.Revision == revision,
            "Unchanged pending registrations do not continuously rewrite state");
        var firstSeen = store.FindPendingDevice(id)!.FirstSeenUtc;
        request = request with
        {
            DeviceName = "Personal laptop"
        };
        check(!store.QueueRegistration(request) && store.Revision > revision &&
            store.FindPendingDevice(id) is { } renamedPending && renamedPending.Name == request.DeviceName &&
            renamedPending.FirstSeenUtc == firstSeen && renamedPending.ClientPublicKey == request.ClientPublicKey &&
            new StateStore(options).FindPendingDevice(id)!.Name == request.DeviceName,
            "A proven pending device can persist its chosen name while retaining its identity and first-seen time");
        Denied(() => store.QueueRegistration(request with { ClientPublicKey = Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()) }),
            "A pending device ID cannot be replaced by a different public key");
        Denied(() => store.QueueRegistration(request with { DeviceId = Guid.NewGuid().ToString() }),
            "A public key cannot be queued under a second device ID");
        store.RejectDevice(id);
        store = new StateStore(options);
        revision = store.Revision;
        Denied(() => store.QueueRegistration(request with { DeviceName = "Rejected rename" }),
            "Rejected registrations remain blocked after a server restart");
        check(store.Revision == revision && store.FindPendingDevice(id) is { Rejected: true } rejected && rejected.Name == request.DeviceName,
            "A rejected request cannot change its name or clear the administrator's decision");
        Denied(() => store.ApproveDevice(id, [allow.Id], new string('0', 64)), "Approval is bound to the pending public-key fingerprint");
        Denied(() => store.ApproveDevice(id, [Guid.NewGuid()], KeyAgreement.Fingerprint(request.ClientPublicKey)),
            "Approval rejects unknown groups without consuming a pending request");
        var device = store.ApproveDevice(id, [allow.Id, deny.Id], KeyAgreement.Fingerprint(request.ClientPublicKey));
        check(store.FindPendingDevice(id) is null && device.GroupIds.SequenceEqual(new[] { allow.Id, deny.Id }),
            "Explicit approval consumes a blocked request and attaches groups directly to the device");
        check((store.Permissions(device, share.Id, "child.txt") & Permission.ReadData) == 0 &&
            (store.Permissions(device, share.Id, "child.txt") & Permission.WriteData) != 0,
            "Device group denies take precedence over grants from every other group");
        check(store.Permissions(device with
        {
            GroupIds = []
        }, share.Id, "child.txt") == Permission.None,
            "A device with no group grants has no access");
        revision = store.Revision;
        check(store.QueueRegistration(request) && store.Revision == revision && store.FindRegisteredDevice(id)!.ServerPublicKey == device.ServerPublicKey,
            "Known devices reuse their approved identity and permanent server key pair");
        var renamedDevice = store.UpdateAuthenticatedDeviceName(device, "Home laptop");
        check(renamedDevice.Name == "Home laptop" && renamedDevice.GroupIds.SequenceEqual(device.GroupIds) &&
            renamedDevice.ClientPublicKey == device.ClientPublicKey && renamedDevice.ServerPublicKey == device.ServerPublicKey &&
            renamedDevice.ProtectedServerPrivateKey.SequenceEqual(device.ProtectedServerPrivateKey) && renamedDevice.Enabled &&
            new StateStore(options).FindRegisteredDevice(id)!.Name == "Home laptop",
            "An authenticated device rename persists without changing groups, identity keys, or enabled status");
        revision = store.Revision;
        store.UpdateAuthenticatedDeviceName(device, renamedDevice.Name);
        check(store.Revision == revision, "An unchanged approved device name does not rewrite state");
        Denied(() => store.UpdateAuthenticatedDeviceName(device with { ClientPublicKey = Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()) }, "Impostor"),
            "A different client public key cannot rename an approved device");
        Denied(() => store.UpdateAuthenticatedDeviceName(device with { ServerPublicKey = Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()) }, "Stale identity"),
            "A stale per-device server identity cannot rename an approved device");
        Denied(() => store.UpdateAuthenticatedDeviceName(device, " ambiguous "), "Device renames reject invalid names before changing state");
        device = renamedDevice;
        store.Update(state => { state.Devices[0] = device with { Enabled = false }; return true; });
        Denied(() => store.Identity(id), "A blocked approved device cannot authenticate");
        revision = store.Revision;
        Denied(() => store.UpdateAuthenticatedDeviceName(device, "Blocked rename"), "A blocked approved device cannot rename itself");
        check(store.Revision == revision && store.FindRegisteredDevice(id)!.Name == device.Name,
            "A blocked device rename leaves the stored name and authorization unchanged");
        check(store.QueueRegistration(request) && store.FindPendingDevice(id) is null,
            "Blocking an approved device preserves its identity without creating a new approval request");
        store.Update(state => { state.Devices[0] = device; return true; });

        var refreshRequest = new EnrollmentRequest(Guid.NewGuid().ToString(), "Seen again", Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()));
        store.QueueRegistration(refreshRequest);
        var refreshId = Guid.Parse(refreshRequest.DeviceId);
        var old = DateTime.UtcNow.AddMinutes(-10);
        store.Update(state => { state.PendingDevices[0] = state.PendingDevices[0] with { FirstSeenUtc = old, LastSeenUtc = old }; return true; });
        store.QueueRegistration(refreshRequest);
        check(store.FindPendingDevice(refreshId) is { } refreshed && refreshed.FirstSeenUtc == old && refreshed.LastSeenUtc > old,
            "A returning pending device refreshes last-seen at a bounded persistence interval");

        var queue = new StateStore(new ServerOptions { DataDirectory = Path.Combine(root, "queue-bound") });
        queue.Update(state =>
        {
            for (var index = 0; index < 256; index++)
            {
                using var identity = KeyAgreement.NewKey();
                var now = DateTime.UtcNow;
                state.PendingDevices.Add(new(Guid.NewGuid(), "Fixture " + index, Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo()), now, now));
            }
            return true;
        });
        Denied(() => queue.QueueRegistration(request), "The approval queue has a bounded number of identities");
        queue.Update(state => { state.PendingDevices = state.PendingDevices.Select(device => device with { Rejected = true }).ToList(); return true; });
        check(!queue.QueueRegistration(request) && queue.FindPendingDevice(id) is { Rejected: false },
            "Blocked identity records do not consume the waiting-for-approval capacity");
        Migration(root, check, Denied);
        ServerIdentitySelfTests.Run(root, check);
    }

    private static void Migration(string root, Action<bool, string> check, Action<Action, string> denied)
    {
        var data = Path.Combine(root, "legacy-migration");
        var store = new StateStore(new ServerOptions { DataDirectory = data });
        var group = new AppGroup(Guid.NewGuid(), "Migrated group");
        store.Update(state => { state.Groups.Add(group); return true; });
        using var first = KeyAgreement.NewKey();
        using var second = KeyAgreement.NewKey();
        using var third = KeyAgreement.NewKey();
        var devices = new[]
        {
            store.Enroll(new(Guid.NewGuid().ToString(), "Active", Convert.ToBase64String(first.ExportSubjectPublicKeyInfo())), [group.Id]),
            store.Enroll(new(Guid.NewGuid().ToString(), "Disabled account", Convert.ToBase64String(second.ExportSubjectPublicKeyInfo())), [group.Id]),
            store.Enroll(new(Guid.NewGuid().ToString(), "Disabled device", Convert.ToBase64String(third.ExportSubjectPublicKeyInfo())), [group.Id])
        };
        var active = Guid.NewGuid();
        var disabled = Guid.NewGuid();
        var bytes = Wire.Encode(new
        {
            admin = store.Read(state => state.Admin),
            users = new[] { new { id = active, name = "Legacy active", enabled = true, groupIds = new[] { group.Id } },
                new { id = disabled, name = "Legacy disabled", enabled = false, groupIds = new[] { group.Id } } },
            groups = new[] { group },
            shares = Array.Empty<ExportShare>(),
            rules = Array.Empty<AccessRule>(),
            devices = devices.Select((device, index) => new
            {
                device.Id,
                device.Name,
                userId = index == 1 ? disabled : active,
                device.ClientPublicKey,
                device.ProtectedServerPrivateKey,
                device.ServerPublicKey,
                enabled = index != 2
            }).ToArray()
        });
        var statePath = Path.Combine(data, "state.json");
        PrivateStorage.AtomicWrite(statePath, bytes);
        var migrated = new StateStore(new ServerOptions { DataDirectory = data });
        check(migrated.MigrationBackupPath is { } backup && Path.GetDirectoryName(backup) == data && File.ReadAllBytes(backup).SequenceEqual(bytes),
            "Legacy migration preserves an exact rollback copy inside the protected server data directory");
        check(migrated.Read(state => state.Devices.All(device => device.GroupIds.SequenceEqual(new[] { group.Id }))) &&
            migrated.Identity(devices[0].Id).ServerPublicKey == devices[0].ServerPublicKey &&
            migrated.Read(state => state.Devices.All(device => device.ProtectedServerPrivateKey.SequenceEqual(devices.Single(oldDevice => oldDevice.Id == device.Id).ProtectedServerPrivateKey))),
            "Migration preserves device keys and copies legacy user memberships directly onto devices");
        denied(() => migrated.Identity(devices[1].Id), "A disabled legacy account produces a blocked device after migration");
        denied(() => migrated.Identity(devices[2].Id), "A disabled legacy device remains blocked after migration");
        using var document = JsonDocument.Parse(File.ReadAllBytes(statePath));
        check(document.RootElement.GetProperty("schemaVersion").GetInt32() == 3 && !document.RootElement.TryGetProperty("users", out _),
            "Migrated state persists the device/group schema without user entities");
        var reloaded = new StateStore(new ServerOptions { DataDirectory = data });
        check(reloaded.MigrationBackupPath is null && Directory.EnumerateFiles(data, "*.before-device-groups-*.bak").Count() == 1,
            "The schema migration runs only once and never overwrites its rollback copy");
        var corrupt = Path.Combine(root, "invalid-legacy-migration");
        PrivateStorage.SecureDirectory(corrupt);
        var node = JsonNode.Parse(bytes)!;
        node["devices"]![0]!["userId"] = Guid.NewGuid().ToString();
        var corruptBytes = System.Text.Encoding.UTF8.GetBytes(node.ToJsonString(Wire.Json));
        var corruptPath = Path.Combine(corrupt, "state.json");
        PrivateStorage.AtomicWrite(corruptPath, corruptBytes);
        denied(() => _ = new StateStore(new ServerOptions { DataDirectory = corrupt }), "Migration fails closed for a missing legacy device owner");
        check(File.ReadAllBytes(corruptPath).SequenceEqual(corruptBytes), "A rejected legacy migration leaves the original state untouched");
    }
}
