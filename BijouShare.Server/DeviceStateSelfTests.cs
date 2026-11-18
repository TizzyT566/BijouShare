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
        var request = TestRegistration.Create("Pending workstation", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        check(!store.QueueRegistration(request) && store.Read(state => state.Devices.Count == 0 && state.PendingDevices.Count == 1),
            "An unknown identity queues public approval information without gaining file access");
        var id = TestRegistration.RecordId(request.DeviceId);
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
        var replacement = TestRegistration.Create("Replaced identity key", request.ClientPublicKey);
        Denied(() => store.QueueRegistration(replacement), "A new ML-KEM key cannot replace one bound to a pending ECDH key");
        var otherEc = otherKey.ExportSubjectPublicKeyInfo();
        var reusedKemId = DeviceIdentity.Id(otherEc, Convert.FromBase64String(request.ClientMlKemPublicKey!));
        Denied(() => store.QueueRegistration(request with { DeviceId = reusedKemId, ClientPublicKey = Convert.ToBase64String(otherEc) }),
            "A new ECDH key cannot claim an already-bound ML-KEM key");
        var samePrefix = request.DeviceId[..32] + new string(request.DeviceId[32] == '0' ? '1' : '0', 32);
        check(store.FindPendingDevice(samePrefix) is null, "Pending lookups require the entire client identity digest");
        store.RejectDevice(id);
        store = new StateStore(options);
        revision = store.Revision;
        Denied(() => store.QueueRegistration(request with { DeviceName = "Rejected rename" }),
            "Rejected registrations remain blocked after a server restart");
        check(store.Revision == revision && store.FindPendingDevice(id) is { Rejected: true } rejected && rejected.Name == request.DeviceName,
            "A rejected request cannot change its name or clear the administrator's decision");
        Denied(() => store.ApproveDevice(id, [allow.Id], new string('0', 64)), "Approval is bound to the pending public-key fingerprint");
        Denied(() => store.ApproveDevice(id, [Guid.NewGuid()], request.DeviceId),
            "Approval rejects unknown groups without consuming a pending request");
        var device = store.ApproveDevice(id, [allow.Id, deny.Id], request.DeviceId);
        check(store.FindRegisteredDevice(samePrefix) is null && store.FindRegisteredDevice(request.DeviceId)?.Id == id,
            "Approved device lookup requires the full digest even when the GUID prefix matches");
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
        check(store.QueueRegistration(request) && store.Revision == revision && store.FindRegisteredDevice(id)!.HasSameIdentity(device),
            "Known devices reuse their approved hybrid identity");
        var renamedDevice = store.UpdateAuthenticatedDeviceName(device, "Home laptop");
        check(renamedDevice.Name == "Home laptop" && renamedDevice.GroupIds.SequenceEqual(device.GroupIds) &&
            renamedDevice.HasSameIdentity(device) && renamedDevice.Enabled &&
            new StateStore(options).FindRegisteredDevice(id)!.Name == "Home laptop",
            "An authenticated device rename persists without changing groups, identity keys, or enabled status");
        revision = store.Revision;
        store.UpdateAuthenticatedDeviceName(device, renamedDevice.Name);
        check(store.Revision == revision, "An unchanged approved device name does not rewrite state");
        Denied(() => store.UpdateAuthenticatedDeviceName(device with { ClientPublicKey = Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()) }, "Impostor"),
            "A different client public key cannot rename an approved device");
        Denied(() => store.UpdateAuthenticatedDeviceName(device with { ClientMlKemPublicKey = replacement.ClientMlKemPublicKey! }, "Stale identity"),
            "A different ML-KEM identity cannot rename an approved device");
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

        var refreshRequest = TestRegistration.Create("Seen again", Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()));
        store.QueueRegistration(refreshRequest);
        var refreshId = TestRegistration.RecordId(refreshRequest.DeviceId);
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
                var fixture = TestRegistration.Create("Fixture " + index, Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo()));
                state.PendingDevices.Add(new(TestRegistration.RecordId(fixture.DeviceId), fixture.DeviceName, fixture.ClientPublicKey,
                    now, now, false, fixture.DeviceId, fixture.ClientMlKemPublicKey!));
            }
            return true;
        });
        Denied(() => queue.QueueRegistration(request), "The approval queue has a bounded number of identities");
        queue.Update(state => { state.PendingDevices = state.PendingDevices.Select(device => device with { Rejected = true }).ToList(); return true; });
        check(!queue.QueueRegistration(request) && queue.FindPendingDevice(id) is { Rejected: false },
            "Blocked identity records do not consume the waiting-for-approval capacity");
        Denied(() => store.Update(s => s.Groups.RemoveAll(group => group.Id == StateStore.AdministratorGroupId)),
            "The permanent Administrator group cannot be deleted");
        Denied(() => store.Update(s =>
        {
            var index = s.Groups.FindIndex(group => group.Id == StateStore.AdministratorGroupId);
            s.Groups[index] = s.Groups[index] with { Name = "Renamed" };
            return true;
        }), "The permanent Administrator group cannot be renamed");
        Denied(() => store.Update(s =>
        {
            s.Rules.Add(s.Rules[0] with { Id = Guid.NewGuid(), Path = "nested" });
            return true;
        }), "Duplicate group and share assignments are rejected even for distinct rule paths");
        ServerIdentitySelfTests.Run(root, check);
    }
}
