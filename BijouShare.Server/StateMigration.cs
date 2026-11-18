using System.Text.Json;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed partial class StateStore
{
    public string? MigrationBackupPath
    {
        get; private set;
    }

    private ServerState LoadState(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        if (document.RootElement.TryGetProperty("schemaVersion", out var version))
        {
            if (!version.TryGetInt32(out var number) || number is not (2 or 3))
                throw new InvalidDataException("Unsupported server state schema version.");
            var decoded = Wire.Decode<ServerState>(bytes);
            if (number == 3)
                return decoded;
            var identity = CreateState();
            decoded.SchemaVersion = 3;
            decoded.ServerId = identity.ServerId;
            decoded.ServerName = identity.ServerName;
            decoded.ServerPublicKey = identity.ServerPublicKey;
            decoded.ProtectedServerPrivateKey = identity.ProtectedServerPrivateKey;
            return PersistMigration(decoded, bytes, "server-identity");
        }
        if (!document.RootElement.TryGetProperty("users", out _))
            throw new InvalidDataException("The server state has no recognized schema version.");
        var legacy = Wire.Decode<LegacyState>(bytes);
        if (legacy.Users is null || legacy.Groups is null || legacy.Devices is null || legacy.Shares is null || legacy.Rules is null ||
            legacy.Users.Any(user => user is null) || legacy.Devices.Any(device => device is null) ||
            legacy.Users.Select(user => user.Id).Distinct().Count() != legacy.Users.Count)
            throw new InvalidDataException("Invalid legacy identity configuration.");
        foreach (var user in legacy.Users)
        {
            ValidateName(user.Name);
            if (user.Id == Guid.Empty || user.GroupIds is null || user.GroupIds.Distinct().Count() != user.GroupIds.Length ||
                user.GroupIds.Any(id => legacy.Groups.All(group => group is null || group.Id != id)))
                throw new InvalidDataException("Invalid legacy user group membership.");
        }
        var migrated = CreateState();
        migrated.Admin = legacy.Admin;
        migrated.Groups = legacy.Groups;
        migrated.Shares = legacy.Shares;
        migrated.Rules = legacy.Rules;
        migrated.Devices = legacy.Devices.Select(device =>
        {
            var user = legacy.Users.SingleOrDefault(user => user.Id == device.UserId)
                ?? throw new InvalidDataException("A legacy device references an unknown user.");
            return new Device(device.Id, device.Name, user.GroupIds.ToArray(), device.ClientPublicKey,
                device.ProtectedServerPrivateKey, device.ServerPublicKey, device.Enabled && user.Enabled);
        }).ToList();
        return PersistMigration(migrated, bytes, "device-groups");
    }

    private ServerState PersistMigration(ServerState migrated, byte[] original, string purpose)
    {
        Validate(migrated, validatePrivateKeys: true);
        var backup = path + ".before-" + purpose + "-" + Guid.NewGuid().ToString("N") + ".bak";
        PrivateStorage.AtomicWrite(backup, original); // Private directory ACLs protect this exact, never-overwritten rollback copy.
        PrivateStorage.AtomicWrite(path, Wire.Encode(migrated));
        MigrationBackupPath = backup;
        return migrated;
    }

    private sealed record LegacyUser(Guid Id, string Name, bool Enabled, Guid[] GroupIds);
    private sealed record LegacyDevice(Guid Id, string Name, Guid UserId, string ClientPublicKey,
        byte[] ProtectedServerPrivateKey, string ServerPublicKey, bool Enabled);
    private sealed class LegacyState
    {
        public AdminCredential? Admin
        {
            get; set;
        }
        public List<LegacyUser> Users { get; set; } = [];
        public List<AppGroup> Groups { get; set; } = [];
        public List<ExportShare> Shares { get; set; } = [];
        public List<AccessRule> Rules { get; set; } = [];
        public List<LegacyDevice> Devices { get; set; } = [];
    }
}
