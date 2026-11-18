using System.Security.Cryptography;
using System.Text.Json.Nodes;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class ServerIdentitySelfTests
{
    public static void Run(string root, Action<bool, string> check)
    {
        static void Reject(Action action)
        {
            try
            {
                action();
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidDataException or CryptographicException) { return; }
            throw new InvalidOperationException("Accepted an invalid server identity.");
        }

        var data = Path.Combine(root, "server-identity");
        var options = new ServerOptions { DataDirectory = data };
        var store = new StateStore(options);
        var firstPublic = store.ServerPublicKey;
        var firstPrivate = store.Read(state => state.ProtectedServerPrivateKey.ToArray());
        store.InitializeAdmin("admin", "Server-identity-test-password-42!", "DarkArchives");
        var firstId = store.ServerId;
        var reloaded = new StateStore(options);
        check(firstId == ServerIdentityNaming.Id("DarkArchives", Convert.FromBase64String(firstPublic)) &&
            reloaded.ServerId == firstId && reloaded.ServerPublicKey == firstPublic && reloaded.ServerName == "DarkArchives" &&
            reloaded.ServerFolderName == "DarkArchives_" + firstId[..16] &&
            reloaded.VerifyAdmin("admin", "Server-identity-test-password-42!"),
            "Administrator initialization persists the chosen name and its lowercase SHA-256 name/public-key server ID");
        reloaded.InitializeAdmin("admin", "Server-identity-reset-password-42!");
        check(reloaded.ServerId == firstId && reloaded.ServerName == "DarkArchives" && reloaded.ServerPublicKey == firstPublic &&
            reloaded.Read(state => state.ProtectedServerPrivateKey.SequenceEqual(firstPrivate)),
            "Resetting administrator credentials preserves the server name, identity key pair, and derived ID");
        reloaded.InitializeAdmin("admin", "Server-identity-renamed-password-42!", "DarkArchives-2");
        var renamed = new StateStore(options);
        check(renamed.ServerId != firstId && renamed.ServerName == "DarkArchives-2" && renamed.ServerPublicKey == firstPublic &&
            renamed.Read(state => state.ProtectedServerPrivateKey.SequenceEqual(firstPrivate)) &&
            renamed.ServerId == ServerIdentityNaming.Id("DarkArchives-2", Convert.FromBase64String(firstPublic)) &&
            renamed.ServerFolderName == "DarkArchives-2_" + renamed.ServerId[..16],
            "An intentional rename updates the name-bound folder ID while preserving the persistent identity key pair");
        foreach (var invalid in new[] { "", " name", "name ", "Dark_Archives", "Dark.Archives", "Dark Archives", "Dark/Archives", "é", "a\n", new string('a', 101) })
            Reject(() => StateStore.ValidateServerName(invalid));
        check(true, "Server names reject separators, whitespace, Unicode, and characters outside ASCII letters/digits/hyphens");
        foreach (var valid in new[] { "DarkArchives", "dark-archives-123", new string('A', 100) })
            StateStore.ValidateServerName(valid);
        check(true, "Server names accept the requested letters, digits, and hyphens up to the size limit");

        var group = new AppGroup(Guid.NewGuid(), "Existing devices");
        var share = new ExportShare(Guid.NewGuid(), "Documents", root, true);
        renamed.Update(state =>
        {
            state.Groups.Add(group);
            state.Shares.Add(share);
            state.Rules.Add(new(Guid.NewGuid(), group.Id, share.Id, "", Permission.FullControl, Permission.None, true));
            return true;
        });
        using var clientKey = KeyAgreement.NewKey();
        var identityBytes = PrivateStorage.Unprotect(firstPrivate);
        try
        {
            using var identity = KeyAgreement.ImportPrivate(identityBytes);
            var serverSecret = KeyAgreement.Agree(identity, clientKey.ExportSubjectPublicKeyInfo());
            var clientSecret = KeyAgreement.Agree(clientKey, Convert.FromBase64String(firstPublic));
            try
            {
                check(KeyAgreement.Equals(serverSecret, clientSecret), "The persistent server identity key pair proves matching ECDH agreement");
            }
            finally { CryptographicOperations.ZeroMemory(serverSecret); CryptographicOperations.ZeroMemory(clientSecret); }
        }
        finally { CryptographicOperations.ZeroMemory(identityBytes); }
        var device = renamed.Enroll(new(Guid.NewGuid().ToString(), "Existing device",
            Convert.ToBase64String(clientKey.ExportSubjectPublicKeyInfo())), [group.Id]);
        using var pendingKey = KeyAgreement.NewKey();
        var pendingRequest = new EnrollmentRequest(Guid.NewGuid().ToString(), "Existing blocked request",
            Convert.ToBase64String(pendingKey.ExportSubjectPublicKeyInfo()));
        renamed.QueueRegistration(pendingRequest);
        renamed.RejectDevice(Guid.Parse(pendingRequest.DeviceId));
        var statePath = Path.Combine(data, "state.json");
        var old = JsonNode.Parse(File.ReadAllBytes(statePath))!;
        old["schemaVersion"] = 2;
        old.AsObject().Remove("serverId");
        old.AsObject().Remove("serverName");
        old.AsObject().Remove("serverPublicKey");
        old.AsObject().Remove("protectedServerPrivateKey");
        var oldBytes = System.Text.Encoding.UTF8.GetBytes(old.ToJsonString(Wire.Json));
        PrivateStorage.AtomicWrite(statePath, oldBytes);

        var migrated = new StateStore(options);
        StateStore.ValidateServerName(migrated.ServerName);
        check(migrated.ServerId == ServerIdentityNaming.Id(migrated.ServerName, Convert.FromBase64String(migrated.ServerPublicKey)) &&
            migrated.MigrationBackupPath is { } backup &&
            Path.GetDirectoryName(backup) == data && File.ReadAllBytes(backup).SequenceEqual(oldBytes),
            "Schema 2 migration creates a persistent server identity and an exact protected rollback copy");
        var current = JsonNode.Parse(File.ReadAllBytes(statePath))!;
        current["schemaVersion"] = 2;
        current.AsObject().Remove("serverId");
        current.AsObject().Remove("serverName");
        current.AsObject().Remove("serverPublicKey");
        current.AsObject().Remove("protectedServerPrivateKey");
        check(JsonNode.DeepEquals(current, old) && migrated.Identity(device.Id).ServerPublicKey == device.ServerPublicKey &&
            migrated.FindPendingDevice(Guid.Parse(pendingRequest.DeviceId)) is { Rejected: true },
            "Server identity migration preserves administrator credentials, device keys, memberships, rules, shares, and blocked requests");
        var again = new StateStore(options);
        check(again.ServerId == migrated.ServerId && again.ServerName == migrated.ServerName && again.MigrationBackupPath is null &&
            Directory.EnumerateFiles(data, "state.json.before-server-identity-*.bak").Count() == 1,
            "Reloading schema 3 retains the server identity without repeating migration");

        var validBytes = File.ReadAllBytes(statePath);
        var missingId = JsonNode.Parse(validBytes)!;
        missingId.AsObject().Remove("serverId");
        var missingBytes = System.Text.Encoding.UTF8.GetBytes(missingId.ToJsonString(Wire.Json));
        PrivateStorage.AtomicWrite(statePath, missingBytes);
        Reject(() => _ = new StateStore(options));
        check(File.ReadAllBytes(statePath).SequenceEqual(missingBytes),
            "Schema 3 with a missing identity fails closed instead of silently replacing the server ID");
        var wrongHash = JsonNode.Parse(validBytes)!;
        wrongHash["serverId"] = new string('0', 64);
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(wrongHash.ToJsonString(Wire.Json)));
        Reject(() => _ = new StateStore(options));
        check(true, "A persisted server ID that does not hash its name and public key is rejected");
        var wrongName = JsonNode.Parse(validBytes)!;
        wrongName["serverName"] = "Tampered-name";
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(wrongName.ToJsonString(Wire.Json)));
        Reject(() => _ = new StateStore(options));
        check(true, "Changing only a persisted server name fails name-bound identity validation");
        using var replacement = KeyAgreement.NewKey();
        var replacementPublic = replacement.ExportSubjectPublicKeyInfo();
        var wrongPublic = JsonNode.Parse(validBytes)!;
        wrongPublic["serverPublicKey"] = Convert.ToBase64String(replacementPublic);
        wrongPublic["serverId"] = ServerIdentityNaming.Id(wrongPublic["serverName"]!.GetValue<string>(), replacementPublic);
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(wrongPublic.ToJsonString(Wire.Json)));
        Reject(() => _ = new StateStore(options));
        check(true, "A matching public-key hash cannot hide a mismatched protected server private key");
        var replacementPrivate = replacement.ExportPkcs8PrivateKey();
        try
        {
            var wrongPrivate = JsonNode.Parse(validBytes)!;
            wrongPrivate["protectedServerPrivateKey"] = Convert.ToBase64String(PrivateStorage.Protect(replacementPrivate));
            PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(wrongPrivate.ToJsonString(Wire.Json)));
            Reject(() => _ = new StateStore(options));
            check(true, "Replacing only the protected private key fails server identity validation");
        }
        finally { CryptographicOperations.ZeroMemory(replacementPrivate); }
        PrivateStorage.AtomicWrite(statePath, validBytes);
    }
}
