using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using BijouShare.Shared;

namespace BijouShare.Server;

public static class BackendSelfTests
{
    public static void Run()
    {
        var count = 0;
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        void Reject(Action action, string label)
        {
            try
            {
                action();
            }
            catch (Exception ex) when (ex is ArgumentException or JsonException or CryptographicException or InvalidDataException)
            {
                Check(true, label);
                return;
            }
            throw new InvalidOperationException("FAIL: " + label);
        }

        var root = Path.GetFullPath(Path.Combine("artifacts", "backend-tests", Guid.NewGuid().ToString("N")));
        var options = new ServerOptions { DataDirectory = root };
        var store = new StateStore(options);
        const string originalPassword = "Original-test-password-42!";
        const string replacementPassword = "Replacement-test-password-42!";
        store.InitializeAdmin("admin", originalPassword);
        var verified = store.AuthenticateAdmin("admin", originalPassword)!;
        Check(verified is not null, "Valid administrator credentials authenticate");
        Check(!store.VerifyAdmin(null, originalPassword) && !store.VerifyAdmin("admin", null), "Malformed null login values are rejected safely");
        Check(!store.VerifyAdmin("admin", new string('x', 1025)), "Oversized administrator passwords are rejected before hashing");
        store.ChangeAdminPassword("admin", originalPassword, replacementPassword);
        Check(!store.VerifyAdmin("admin", originalPassword) && store.VerifyAdmin("admin", replacementPassword), "Password changes invalidate the old credential");
        Check(AdminApi.CredentialVersion(verified!) != store.Read(s => AdminApi.CredentialVersion(s.Admin!)), "A cookie version remains bound to the password actually verified");
        Reject(() => store.ChangeAdminPassword("admin", originalPassword, "Another-test-password-42!"), "A stale password cannot authorize a second password change");

        var group = new AppGroup(Guid.NewGuid(), "Backend group");
        store.Update(s => { s.Groups.Add(group); return true; });
        Reject(() => store.Update(s => { s.Groups.Add(new(Guid.NewGuid(), "backend GROUP")); return true; }), "Group names are unique without regard to case");
        Reject(() => store.Update(s => { s.Groups.Add(null!); return true; }), "Null records cannot enter persisted application state");
        Reject(() => store.InitializeAdmin(" admin ", replacementPassword), "Administrator names reject ambiguous surrounding whitespace");

        using var client = KeyAgreement.NewKey();
        var publicKey = Convert.ToBase64String(client.ExportSubjectPublicKeyInfo());
        var device = store.Enroll(TestRegistration.Create("Backend device", publicKey), [group.Id]);
        Reject(() => store.Update(s => { s.Devices[0] = device with { GroupIds = null! }; return true; }), "Null device group memberships fail validation without corrupting state");
        Check(store.Read(s => s.Devices[0].GroupIds.SequenceEqual(new[] { group.Id })), "A rejected update leaves live device membership intact");
        Reject(() => store.Enroll(TestRegistration.Create("Alias device", "\n" + publicKey + "\n"), [group.Id]), "Equivalent encodings cannot enroll the same device public key twice");
        using var unknownUserKey = KeyAgreement.NewKey();
        Reject(() => store.Enroll(TestRegistration.Create("Unknown group device", Convert.ToBase64String(unknownUserKey.ExportSubjectPublicKeyInfo())), [Guid.NewGuid()]), "Approval cannot bind an unknown group");
        var loaded = new StateStore(options);
        Check(loaded.Identity(device.Id).HasSameIdentity(device), "Device key pairs survive validated state reloads");
        AllSharesRegressions(store, group, device, Check, Reject);
        DeviceStateSelfTests.Run(root, Check);

        using var replacement = KeyAgreement.NewKey();
        var badRoot = Path.Combine(root, "mismatched-state");
        PrivateStorage.SecureDirectory(badRoot);
        var badState = Wire.Decode<ServerState>(Wire.Encode(store.Read(s => s)));
        badState.ServerPublicKey = Convert.ToBase64String(replacement.ExportSubjectPublicKeyInfo());
        badState.ServerId = ServerIdentityNaming.Id(replacement.ExportSubjectPublicKeyInfo(), Convert.FromBase64String(badState.ServerMlKemPublicKey));
        PrivateStorage.AtomicWrite(Path.Combine(badRoot, "state.json"), Wire.Encode(badState));
        Reject(() => _ = new StateStore(new ServerOptions { DataDirectory = badRoot }), "Reload rejects a server private/public key mismatch");

        using var audit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        audit.Write("backend", "Regression", new string('x', 100_000));
        Check(audit.Recent()[0].Target.Length == 2048, "Audit fields are bounded against log flooding");
        using var reloadedAudit = new AuditLog(store, NullLogger<AuditLog>.Instance);
        Check(reloadedAudit.Recent().Any(x => x.Action == "Regression"), "Recent audit history survives a server restart");
        AuditLifecycleRegressions(root, Check);

        Reject(() => Wire.Decode<ClientHello>("{\"version\":1,\"deviceId\":\"test\",\"nonce\":null,\"ephemeralPublicKey\":\"AA==\"}"u8.ToArray()), "Handshake JSON rejects null nonnullable values");
        Reject(() => Wire.Decode<ClientHello>("{\"version\":1}"u8.ToArray()), "Handshake JSON rejects missing identity fields");
        foreach (var path in new[] { "//Team/file", "/Team/COM¹.txt", "/Team/LPT²", "/Team/" + new string('x', 256) })
            Reject(() => StateStore.NormalizeRelative(path), "Invalid Windows namespace is rejected: " + path[..Math.Min(path.Length, 40)]);
        foreach (var path in new[] { @"\\server\share", @"\\?\C:\share", @"C:\file:stream", "relative" })
            Reject(() => StateStore.NormalizeLocalSharePath(path), "Unsupported share roots fail before filesystem access: " + path);
        Console.WriteLine($"Backend: {count} checks passed.");
    }

    private static void AllSharesRegressions(StateStore store, AppGroup group, Device device,
        Action<bool, string> check, Action<Action, string> reject)
    {
        var first = new ExportShare(Guid.NewGuid(), "All", @"C:\Alpha", true);
        var next = new ExportShare(Guid.NewGuid(), "Beta", @"C:\Beta", true);
        var baseline = new AccessRule(Guid.NewGuid(), group.Id, StateStore.AllSharesId, "",
            Permission.FullControl & ~Permission.Delete, Permission.Delete, true);
        var exception = new AccessRule(Guid.NewGuid(), group.Id, first.Id, "private", Permission.Delete, Permission.ReadData, true);
        store.Update(s => { s.Shares.Add(first); return true; });
        check(store.Permissions(device, first.Id, "") == Permission.None, "All carries no implicit permissions");
        store.Update(s => { s.Rules.AddRange([baseline, exception]); return true; });
        store.Update(s => { s.Shares.Add(next); return true; });
        check(store.Permissions(device, first.Id, "private/file") == (Permission.FullControl & ~(Permission.Delete | Permission.ReadData)) &&
            store.Permissions(device, next.Id, "private/file") == (Permission.FullControl & ~Permission.Delete),
            "A real share named All can have its own deny, while the aggregate All rule covers future shares");
        check(store.Permissions(device with { GroupIds = [group.Id, StateStore.AdministratorGroupId] }, next.Id, "") ==
            (Permission.FullControl & ~Permission.Delete), "All denies still apply to Administrator group members");
        reject(() => store.Update(s => { s.Rules.Add(baseline with { Id = Guid.NewGuid() }); return true; }),
            "A group cannot have duplicate All permission assignments");
        reject(() => store.Update(s => { s.Rules[0] = baseline with { Path = "private" }; return true; }),
            "All rules reject ambiguous named paths");
        reject(() => store.Update(s => { s.Shares.Add(first with { Name = "Alias", Id = StateStore.AllSharesId }); return true; }),
            "A physical path cannot claim the All share identifier");
        store.Update(s =>
        {
            s.Rules[0] = baseline with { Inherit = false };
            s.Shares[1] = next with { Enabled = false };
            return true;
        });
        check(store.Permissions(device, first.Id, "") != Permission.None && store.Permissions(device, first.Id, "child") == Permission.None &&
            store.Permissions(device, next.Id, "") == Permission.None, "Root-only All rules honor inheritance and disabled exports");

        var options = new ServerOptions { DataDirectory = Path.Combine(store.DataDirectory, "legacy-share-policy") };
        PrivateStorage.SecureDirectory(options.DataDirectory);
        var statePath = Path.Combine(options.DataDirectory, "state.json");
        var legacy = store.Read(s => Wire.Decode<ServerState>(Wire.Encode(s)));
        legacy.SchemaVersion = 6;
        legacy.Shares = [first with { Id = StateStore.AllSharesId, Name = "aLL" }, next];
        legacy.Rules = [baseline];
        PrivateStorage.AtomicWrite(statePath, Wire.Encode(legacy));
        var migrated = new StateStore(options);
        var rekeyed = migrated.Read(s => s.Shares.Single(share => share.LocalPath == first.LocalPath));
        check(rekeyed.Name == "aLL" && rekeyed.Id != StateStore.AllSharesId &&
            migrated.Permissions(device, rekeyed.Id, "child") == (Permission.FullControl & ~Permission.Delete) &&
            migrated.Permissions(device, next.Id, "") == Permission.None &&
            new StateStore(options).Read(s => s.Shares.Contains(rekeyed) && s.Rules.Single().ShareId == rekeyed.Id),
            "Upgrade preserves an existing All export's name, data path and scoped rules even if its ID collides");
        legacy.Shares.RemoveAt(0);
        var invalid = Wire.Encode(legacy);
        PrivateStorage.AtomicWrite(statePath, invalid);
        reject(() => _ = new StateStore(options), "A legacy orphan rule cannot become an All grant during upgrade");
        check(File.ReadAllBytes(statePath).SequenceEqual(invalid), "Invalid legacy state is preserved unchanged");
    }

    private static void AuditLifecycleRegressions(string root, Action<bool, string> check)
    {
        var options = new ServerOptions { DataDirectory = Path.Combine(root, "audit-lifecycle") };
        var store = new StateStore(options);
        var clock = new AuditClock(new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditLog(store, NullLogger<AuditLog>.Instance, clock);
        try
        {
            audit.Write("test", "Before rollover", "fixture");
            clock.UtcNow = clock.UtcNow.AddDays(1);
            // A directory at the next daily file path deterministically denies opening that file.
            Directory.CreateDirectory(Path.Combine(store.DataDirectory, "audit", "2030-01-02.jsonl"));
            audit.Write("test", "Blocked rollover", "fixture");
            clock.UtcNow = clock.UtcNow.AddDays(-1);
            audit.Write("test", "Recovered", "fixture");
            var file = Path.Combine(store.DataDirectory, "audit", "2030-01-01.jsonl");
            using (var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new StreamReader(input))
            {
                var recovered = false;
                while (reader.ReadLine() is { } line)
                    recovered |= Wire.Decode<AuditEvent>(System.Text.Encoding.UTF8.GetBytes(line)).Action == "Recovered";
                check(recovered, "Audit logging recovers after a failed daily file rollover");
            }
            for (var index = 0; index < 200; index++)
                audit.WriteFrequent("test", "Queued", index.ToString());
            audit.Dispose();
            var queued = File.ReadAllLines(file).Select(line => Wire.Decode<AuditEvent>(System.Text.Encoding.UTF8.GetBytes(line)))
                .Where(entry => entry.Action == "Queued").ToArray();
            check(queued.Length == 200 && queued.Any(entry => entry.Target == "199"), "Audit disposal drains every queued record before closing its file");
            var rejected = 0;
            try
            {
                audit.Write("test", "Late", "fixture");
            }
            catch (ObjectDisposedException) { rejected++; }
            try
            {
                audit.WriteFrequent("test", "Late", "fixture");
            }
            catch (ObjectDisposedException) { rejected++; }
            check(rejected == 2, "Disposed audit logs reject both synchronous and queued writes");
        }
        finally { audit.Dispose(); }
    }

    private sealed class AuditClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
