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
        var kemPublic = Convert.FromBase64String(store.ServerMlKemPublicKey);
        var kemSeed = store.Read(state => state.ProtectedServerMlKemSeed.ToArray());
        var firstPrivate = store.Read(state => state.ProtectedServerPrivateKey.ToArray());
        store.InitializeAdmin("admin", "Server-identity-test-password-42!", "DarkArchives");
        var firstId = store.ServerId;
        var reloaded = new StateStore(options);
        check(firstId == ServerIdentityNaming.Id(Convert.FromBase64String(firstPublic), kemPublic) &&
            reloaded.ServerId == firstId && reloaded.ServerPublicKey == firstPublic && reloaded.ServerName == "DarkArchives" &&
            reloaded.ServerFolderName == "DarkArchives_" + firstId[..16] &&
            reloaded.VerifyAdmin("admin", "Server-identity-test-password-42!"),
            "Administrator initialization persists the chosen name and the fingerprint of both server identity keys");
        reloaded.InitializeAdmin("admin", "Server-identity-reset-password-42!");
        check(reloaded.ServerId == firstId && reloaded.ServerName == "DarkArchives" && reloaded.ServerPublicKey == firstPublic &&
            reloaded.Read(state => state.ProtectedServerPrivateKey.SequenceEqual(firstPrivate) && state.ProtectedServerMlKemSeed.SequenceEqual(kemSeed)),
            "Resetting administrator credentials preserves the name, ECDH and ML-KEM pairs, and derived ID");
        reloaded.RenameServer("DarkArchives-2");
        var renamed = new StateStore(options);
        check(renamed.ServerId == firstId && renamed.ServerName == "DarkArchives-2" && renamed.ServerPublicKey == firstPublic &&
            renamed.Read(state => state.ProtectedServerPrivateKey.SequenceEqual(firstPrivate) && state.ProtectedServerMlKemSeed.SequenceEqual(kemSeed)) &&
            renamed.ServerId == ServerIdentityNaming.Id(Convert.FromBase64String(firstPublic), kemPublic) &&
            renamed.ServerFolderName == "DarkArchives-2_" + renamed.ServerId[..16],
            "An administrator rename updates the folder label while retaining the fingerprint and both private keys");
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
        var device = renamed.Enroll(TestRegistration.Create("Existing device",
            Convert.ToBase64String(clientKey.ExportSubjectPublicKeyInfo())), [group.Id]);
        using var pendingKey = KeyAgreement.NewKey();
        var pendingRequest = TestRegistration.Create("Existing blocked request",
            Convert.ToBase64String(pendingKey.ExportSubjectPublicKeyInfo()));
        renamed.SetInviteOnly(false);
        renamed.QueueRegistration(pendingRequest);
        renamed.RejectDevice(TestRegistration.RecordId(pendingRequest.DeviceId));
        var statePath = Path.Combine(data, "state.json");
        var current = new StateStore(options);
        check(current.Identity(device.Id).HasSameIdentity(device) && current.Identity(device.Id).GroupIds.SequenceEqual([group.Id]) &&
            current.FindPendingDevice(pendingRequest.DeviceId) is { Rejected: true } &&
            current.Permissions(device, share.Id, "") == Permission.FullControl,
            "Current state reload retains both device keys, memberships, access rules and rejected requests");
        var validBytes = File.ReadAllBytes(statePath);
        var previousState = JsonNode.Parse(validBytes)!.AsObject();
        previousState.Remove("inviteOnly");
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(previousState.ToJsonString(Wire.Json)));
        check(!new StateStore(options).Read(s => s.InviteOnly),
            "Upgrading a server that predates the invite-only setting preserves manual enrollment");
        var missingId = JsonNode.Parse(validBytes)!;
        missingId.AsObject().Remove("serverId");
        var missingBytes = System.Text.Encoding.UTF8.GetBytes(missingId.ToJsonString(Wire.Json));
        PrivateStorage.AtomicWrite(statePath, missingBytes);
        Reject(() => _ = new StateStore(options));
        check(File.ReadAllBytes(statePath).SequenceEqual(missingBytes),
            "Current state with a missing identity fails closed instead of silently replacing the server ID");
        var wrongHash = JsonNode.Parse(validBytes)!;
        wrongHash["serverId"] = new string('0', 64);
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(wrongHash.ToJsonString(Wire.Json)));
        Reject(() => _ = new StateStore(options));
        check(true, "A persisted server ID inconsistent with either public key is rejected");
        var wrongName = JsonNode.Parse(validBytes)!;
        wrongName["serverName"] = "Invalid/name";
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(wrongName.ToJsonString(Wire.Json)));
        Reject(() => _ = new StateStore(options));
        check(true, "An invalid persisted server display name fails validation");
        using var replacement = KeyAgreement.NewKey();
        var replacementPublic = replacement.ExportSubjectPublicKeyInfo();
        var wrongPublic = JsonNode.Parse(validBytes)!;
        wrongPublic["serverPublicKey"] = Convert.ToBase64String(replacementPublic);
        wrongPublic["serverId"] = ServerIdentityNaming.Id(replacementPublic, kemPublic);
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
        foreach (var field in new[] { "serverMlKemPublicKey", "protectedServerMlKemSeed" })
        {
            var missing = JsonNode.Parse(validBytes)!;
            missing.AsObject().Remove(field);
            var incomplete = System.Text.Encoding.UTF8.GetBytes(missing.ToJsonString(Wire.Json));
            PrivateStorage.AtomicWrite(statePath, incomplete);
            Reject(() => _ = new StateStore(options));
            check(File.ReadAllBytes(statePath).SequenceEqual(incomplete), "Missing persisted " + field + " fails closed and retains the original state");
        }
        using var replacementKem = HybridKem.Generate();
        var substituted = JsonNode.Parse(validBytes)!;
        var replacementKemPublic = replacementKem.ExportPublicKey();
        substituted["serverMlKemPublicKey"] = Convert.ToBase64String(replacementKemPublic);
        substituted["serverId"] = ServerIdentityNaming.Id(Convert.FromBase64String(current.ServerPublicKey), replacementKemPublic);
        PrivateStorage.AtomicWrite(statePath, System.Text.Encoding.UTF8.GetBytes(substituted.ToJsonString(Wire.Json)));
        Reject(() => _ = new StateStore(options));
        check(true, "A substituted ML-KEM public key and fingerprint are rejected when the DPAPI-protected seed belongs to another key");
        PrivateStorage.AtomicWrite(statePath, validBytes);
        var oldOptions = new ServerOptions { DataDirectory = Path.Combine(root, "unsupported-state") };
        PrivateStorage.SecureDirectory(oldOptions.DataDirectory);
        var oldPath = Path.Combine(oldOptions.DataDirectory, "state.json");
        foreach (var unsupported in new[] { "{}", "{\"schemaVersion\":1}", "{\"schemaVersion\":5}", "{\"schemaVersion\":9}" })
        {
            var input = System.Text.Encoding.UTF8.GetBytes(unsupported);
            PrivateStorage.AtomicWrite(oldPath, input);
            Reject(() => _ = new StateStore(oldOptions));
            check(File.ReadAllBytes(oldPath).SequenceEqual(input) && Directory.GetFiles(oldOptions.DataDirectory).Length == 1,
                "Unsupported server state is refused without altering the original file");
        }
    }
}
