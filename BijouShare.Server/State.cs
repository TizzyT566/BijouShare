using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text.Json;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed class ServerOptions
{
    public string DataDirectory { get; set; } = PrivateStorage.DefaultDirectory("Server");
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int Port { get; set; } = 7443;
    public int MaxConnections { get; set; } = 128;
}

public sealed record AppGroup(Guid Id, string Name);
public sealed record ExportShare(Guid Id, string Name, string LocalPath, bool Enabled);
public sealed record AccessScope(string Path, Permission Allow, Permission Deny, bool Inherit);
public sealed record AccessRule(Guid Id, Guid GroupId, Guid ShareId, string Path,
    Permission Allow, Permission Deny, bool Inherit)
{
    public AccessScope[] AdditionalScopes { get; init; } = [];
    internal bool AppliesToShare(Guid id) => ShareId == id || ShareId == StateStore.AllSharesId;

    internal IEnumerable<AccessScope> Scopes()
    {
        yield return new(Path, Allow, Deny, Inherit);
        foreach (var scope in AdditionalScopes)
            yield return scope;
    }

    internal (Permission Allow, Permission Deny) MatchingPermissions(string relative)
    {
        static bool Matches(string relative, string path, bool inherit) => inherit
            ? StateStore.AtOrBelow(relative, path)
            : relative.Equals(path, StringComparison.OrdinalIgnoreCase);
        var matches = Matches(relative, Path, Inherit);
        var allow = matches ? Allow : Permission.None;
        var deny = matches ? Deny : Permission.None;
        foreach (var scope in AdditionalScopes)
        {
            if (!Matches(relative, scope.Path, scope.Inherit))
                continue;
            allow |= scope.Allow;
            deny |= scope.Deny;
        }
        return (allow, deny);
    }
}
public sealed record Device(Guid Id, string Name, Guid[] GroupIds, string ClientPublicKey,
    bool Enabled, string PublicIdentity, string ClientMlKemPublicKey)
{
    // A legacy enrollment has a stable marker across reloads. Every fresh approval gets a new one.
    public Guid EnrollmentId { get; init; } = Id;
    public bool HasSameIdentity(Device authenticated) =>
        Id == authenticated.Id && EnrollmentId == authenticated.EnrollmentId &&
        PublicIdentity == authenticated.PublicIdentity && ClientPublicKey == authenticated.ClientPublicKey &&
        ClientMlKemPublicKey == authenticated.ClientMlKemPublicKey;
}
public sealed record PendingDevice(Guid Id, string Name, string ClientPublicKey, DateTime FirstSeenUtc, DateTime LastSeenUtc,
    bool Rejected, string PublicIdentity, string ClientMlKemPublicKey);
public sealed record AdminCredential(string Name, byte[] Salt, byte[] Hash, string Algorithm = "PBKDF2-HMAC-SHA3-256");
public sealed class ServerState
{
    public int SchemaVersion { get; set; } = 7;
    public int? FilePort { get; set; }
    public int? WebPort { get; set; }
    public bool InviteOnly { get; set; }
    public string ServerId { get; set; } = "";
    public string ServerName { get; set; } = "";
    public string ServerPublicKey { get; set; } = "";
    public byte[] ProtectedServerPrivateKey { get; set; } = [];
    public string ServerMlKemPublicKey { get; set; } = "";
    public byte[] ProtectedServerMlKemSeed { get; set; } = [];
    public AdminCredential? Admin
    {
        get; set;
    }
    public List<AppGroup> Groups { get; set; } = [];
    public List<ExportShare> Shares { get; set; } = [];
    public List<AccessRule> Rules { get; set; } = [];
    public List<Device> Devices { get; set; } = [];
    public List<PendingDevice> PendingDevices { get; set; } = [];
    public List<InviteCode> Invites { get; set; } = [];
}

public sealed partial class StateStore
{
    public static readonly Guid AdministratorGroupId = new("7a336850-eff3-4a22-9bc8-a3972474f10c");
    public const string AdministratorGroupName = "Administrator";
    public static readonly Guid AllSharesId = new("d8109392-5a11-4b55-a461-001cbf206da3");
    public const string AllSharesName = "All";
    private readonly ReaderWriterLockSlim gate = new(LockRecursionPolicy.SupportsRecursion);
    private long revision;
    public long Revision => Interlocked.Read(ref revision);
    private readonly string path;
    private ServerState state;
    public string ServerId => Read(s => s.ServerId);
    public string ServerName => Read(s => s.ServerName);
    public string ServerPublicKey => Read(s => s.ServerPublicKey);
    public string ServerMlKemPublicKey => Read(s => s.ServerMlKemPublicKey);
    public bool IsInitialized => Read(s => s.Admin is not null);
    public string ServerFolderName => Read(s => ServerIdentityNaming.FolderName(s.ServerName, s.ServerId));
    public string DataDirectory
    {
        get;
    }
    public StateStore(ServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.DataDirectory) || !System.IO.Path.IsPathFullyQualified(options.DataDirectory))
            throw new ArgumentException("The server data directory must be an absolute path.");
        DataDirectory = System.IO.Path.GetFullPath(options.DataDirectory);
        PrivateStorage.SecureDirectory(DataDirectory, includeLocalService: true);
        path = System.IO.Path.Combine(DataDirectory, "state.json");
        state = File.Exists(path) ? LoadState(File.ReadAllBytes(path)) : CreateState();
        var upgraded = state.SchemaVersion == 6;
        if (upgraded)
            UpgradeShareTargets(state);
        Validate(state, validatePrivateKeys: true);
        if (upgraded)
            PrivateStorage.AtomicWrite(path, Wire.Encode(state));
        if (state.FilePort is { } filePort)
            options.Port = filePort;
    }
    private static ServerState LoadState(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("schemaVersion", out var version) ||
            version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var number) || number is not (6 or 7))
            throw new InvalidDataException("Unsupported server state format.");
        return Wire.Decode<ServerState>(bytes);
    }

    private static void UpgradeShareTargets(ServerState s)
    {
        // In v6 every rule had to reference an actual export. An orphan must never turn into a wildcard grant.
        Validate(s, legacyShares: true);
        var index = s.Shares.FindIndex(share => share.Id == AllSharesId);
        if (index >= 0)
        {
            Guid newId;
            do { newId = Guid.NewGuid(); } while (s.Shares.Any(share => share.Id == newId));
            s.Shares[index] = s.Shares[index] with { Id = newId };
            for (var i = 0; i < s.Rules.Count; i++)
                if (s.Rules[i].ShareId == AllSharesId)
                    s.Rules[i] = s.Rules[i] with { ShareId = newId };
        }
        s.SchemaVersion = 7;
    }
    public T Read<T>(Func<ServerState, T> read)
    {
        gate.EnterReadLock();
        try
        {
            return read(state);
        }
        finally { gate.ExitReadLock(); }
    }
    public T Update<T>(Func<ServerState, T> update)
    {
        gate.EnterWriteLock();
        try
        {
            // Mutate a copy: validation/disk failures cannot partially change live authorization.
            var copy = Wire.Decode<ServerState>(Wire.Encode(state));
            var result = update(copy);
            Validate(copy);
            PrivateStorage.AtomicWrite(path, Wire.Encode(copy));
            state = copy;
            Interlocked.Increment(ref revision);
            return result;
        }
        finally { gate.ExitWriteLock(); }
    }
    public void InitializeAdmin(string name, string password, string? serverName = null)
    {
        ValidateName(name);
        if (serverName is not null)
            ValidateServerName(serverName);
        if (password is null || password.Length is < 14 or > 1024)
            throw new ArgumentException("Use an administrator password of 14 to 1024 characters.");
        var salt = RandomNumberGenerator.GetBytes(32);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA3_256, 32);
        Update(s =>
        {
            s.Admin = new(name, salt, hash);
            if (serverName is not null)
                s.ServerName = serverName;
            return true;
        });
    }
    public AdminCredential? AuthenticateAdmin(string? name, string? password)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 100 || string.IsNullOrEmpty(password) || password.Length > 1024)
            return null;
        // Expensive password hashing must not hold the authorization lock and stall every file operation.
        var admin = Read(s => s.Admin);
        if (admin is null)
            return null;
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, admin.Salt, 600_000, HashAlgorithmName.SHA3_256, 32);
        try
        {
            return KeyAgreement.Equals(admin.Hash, hash) && string.Equals(admin.Name, name, StringComparison.Ordinal) ? admin : null;
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }
    public void RenameServer(string name)
    {
        ValidateServerName(name);
        Update(s => s.ServerName = name);
    }
    public void SavePorts(int? filePort, int? webPort) => Update(s =>
    {
        s.FilePort = filePort;
        s.WebPort = webPort;
        return true;
    });
    public void SetInviteOnly(bool inviteOnly) => Update(s => s.InviteOnly = inviteOnly);
    public bool VerifyAdmin(string? name, string? password) => AuthenticateAdmin(name, password) is not null;
    public void ChangeAdminPassword(string name, string currentPassword, string newPassword)
    {
        var verified = AuthenticateAdmin(name, currentPassword) ?? throw new ArgumentException("Current password is incorrect.");
        if (newPassword is null || newPassword.Length is < 14 or > 1024)
            throw new ArgumentException("Use an administrator password of 14 to 1024 characters.");
        var salt = RandomNumberGenerator.GetBytes(32);
        var hash = Rfc2898DeriveBytes.Pbkdf2(newPassword, salt, 600_000, HashAlgorithmName.SHA3_256, 32);
        Update(s =>
        {
            if (s.Admin is null || !KeyAgreement.Equals(verified.Hash, s.Admin.Hash) || s.Admin.Name != verified.Name)
                throw new ArgumentException("The administrator credential changed. Sign in again.");
            s.Admin = new(name, salt, hash);
            return true;
        });
    }
    public Device? FindRegisteredDevice(Guid deviceId) => Read(s => s.Devices.SingleOrDefault(x => x.Id == deviceId));
    public Device? FindRegisteredDevice(string fullIdentity) => Read(s => s.Devices.SingleOrDefault(x =>
        x.PublicIdentity == fullIdentity));
    public PendingDevice? FindPendingDevice(string fullIdentity) => Read(s => s.PendingDevices.SingleOrDefault(x =>
        x.PublicIdentity == fullIdentity));
    public Device Identity(Guid deviceId) => Read(s => s.Devices.SingleOrDefault(x => x.Id == deviceId && x.Enabled)
        ?? throw new UnauthorizedAccessException());

    // Call only after proving possession of both client identity keys.
    public Device UpdateAuthenticatedDeviceName(Device authenticated, string name)
    {
        ValidateName(name);
        gate.EnterWriteLock();
        try
        {
            var current = Identity(authenticated.Id);
            if (!current.HasSameIdentity(authenticated))
                throw new UnauthorizedAccessException();
            if (current.Name == name)
                return current;
            return Update(s =>
            {
                var index = s.Devices.FindIndex(device => device.Id == authenticated.Id);
                return s.Devices[index] = s.Devices[index] with
                {
                    Name = name
                };
            });
        }
        finally { gate.ExitWriteLock(); }
    }
    public static string NormalizeRelative(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (path.Length > 2048)
            throw new ArgumentException("Path is too long.");
        path = path.Replace('\\', '/');
        if (path.StartsWith("//", StringComparison.Ordinal))
            throw new ArgumentException("UNC and repeated root separators are not allowed.");
        path = path.Trim('/');
        if (path.Length == 0)
            return "";
        foreach (var segment in path.Split('/'))
        {
            if (segment.Length is 0 or > 255 || segment is "." or ".." || segment.EndsWith('.') || segment.EndsWith(' ') ||
                segment.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0 ||
                Regex.IsMatch(segment, @"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                throw new ArgumentException("Use an ordinary relative Windows path without traversal or device names.");
        }
        return path;
    }
    public static bool AtOrBelow(string path, string ancestor) => ancestor.Length == 0 ||
        path.Equals(ancestor, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(ancestor + "/", StringComparison.OrdinalIgnoreCase);
    public static string NormalizeLocalSharePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !System.IO.Path.IsPathFullyQualified(path))
            throw new ArgumentException("Shares must use an absolute local drive path.");
        var normalized = System.IO.Path.GetFullPath(path);
        if (normalized.Length < 3 || !char.IsAsciiLetter(normalized[0]) || normalized[1..3] != ":\\" || normalized.IndexOf(':', 2) >= 0)
            throw new ArgumentException("Shares must use an absolute local drive path; UNC, device paths, and alternate streams are not supported.");
        return normalized;
    }
    public static string CanonicalRulePath(ServerState state, Guid shareId, string path)
    {
        var relative = NormalizeRelative(path);
        if (relative.Length == 0)
            return "";
        if (shareId == AllSharesId)
            throw new ArgumentException("Choose an individual share to assign permissions to a named path.");
        var share = state.Shares.SingleOrDefault(x => x.Id == shareId) ?? throw new ArgumentException("Unknown share.");
        if (File.Exists(share.LocalPath))
            throw new ArgumentException("A file share has only its root permission path.");
        var root = WindowsPaths.Canonical(share.LocalPath);
        var physical = WindowsPaths.Canonical(System.IO.Path.Combine(root, relative.Replace('/', '\\')));
        var canonical = System.IO.Path.GetRelativePath(root, physical).Replace('\\', '/');
        if (canonical == ".." || canonical.StartsWith("../", StringComparison.Ordinal) || System.IO.Path.IsPathRooted(canonical))
            throw new ArgumentException("The permission path must remain inside its share.");
        return NormalizeRelative(canonical);
    }
    public Permission Permissions(Device device, Guid shareId, string relative) => Read(s =>
    {
        if (!device.Enabled || !s.Shares.Any(share => share.Id == shareId && share.Enabled))
            return Permission.None;
        var allow = device.GroupIds.Contains(AdministratorGroupId) ? Permission.FullControl : Permission.None;
        var deny = Permission.None;
        foreach (var rule in s.Rules.Where(x => x.AppliesToShare(shareId) && device.GroupIds.Contains(x.GroupId)))
        {
            var matched = rule.MatchingPermissions(relative);
            allow |= matched.Allow;
            deny |= matched.Deny;
        }
        return allow & ~deny;
    });
    public PendingDevice? FindPendingDevice(Guid deviceId) => Read(s => s.PendingDevices.SingleOrDefault(x => x.Id == deviceId));

    // The handshake proves possession of both supplied identity private keys before this call.
    public bool QueueRegistration(EnrollmentRequest request)
    {
        var binding = ValidateRegistration(request);
        gate.EnterWriteLock();
        try
        {
            EnsureIdentityAvailable(state, binding);
            if (state.Devices.Any(device => device.PublicIdentity == binding.Digest))
                return true;
            var pending = state.PendingDevices.SingleOrDefault(device => device.ClientPublicKey == binding.Ecdh);
            if (pending is { Rejected: true })
                throw new UnauthorizedAccessException("Device registration was rejected by an administrator.");
            if (state.InviteOnly)
                throw new RemoteException("InviteRequired");
            var now = DateTime.UtcNow;
            if (pending is not null && pending.Name == request.DeviceName && now - pending.LastSeenUtc < TimeSpan.FromMinutes(5))
                return false;
            if (pending is null && (state.PendingDevices.Count >= 4096 || state.PendingDevices.Count(device => !device.Rejected) >= 256))
                throw new UnauthorizedAccessException("The device approval queue is full.");
            Update(s =>
            {
                var record = new PendingDevice(binding.Id, request.DeviceName, binding.Ecdh, pending?.FirstSeenUtc ?? now,
                    now, false, binding.Digest, binding.Kem);
                s.PendingDevices.RemoveAll(device => device.ClientPublicKey == binding.Ecdh);
                s.PendingDevices.Add(record);
                return true;
            });
            return false;
        }
        finally { gate.ExitWriteLock(); }
    }

    public Device ApproveDevice(Guid id, Guid[] groupIds, string expectedFingerprint) => Update(s =>
    {
        if (s.InviteOnly)
            throw new ArgumentException("Manual approval is paused while invite-only enrollment is enabled.");
        var pending = s.PendingDevices.SingleOrDefault(device => device.Id == id)
            ?? throw new ArgumentException("No pending device request exists for this ID.");
        if (!string.Equals(pending.PublicIdentity, expectedFingerprint, StringComparison.Ordinal))
            throw new ArgumentException("The pending device identity changed. Refresh and verify its fingerprint again.");
        ValidateGroups(s, groupIds);
        var binding = new DeviceBinding(id, pending.PublicIdentity, pending.ClientPublicKey, pending.ClientMlKemPublicKey);
        return CompleteEnrollment(s, binding, pending.Name, groupIds);
    });

    public void RejectDevice(Guid id) => Update(s =>
    {
        var index = s.PendingDevices.FindIndex(device => device.Id == id);
        if (index < 0)
            throw new ArgumentException("Unknown pending device request.");
        s.PendingDevices[index] = s.PendingDevices[index] with
        {
            Rejected = true
        };
        return true;
    });

    public bool RemoveRejectedRequest(Guid id) => Update(s =>
    {
        if (s.PendingDevices.RemoveAll(d => d.Id == id && d.Rejected) == 0)
            throw new ArgumentException("Only a rejected device request can be removed. Refresh the device list.");
        return true;
    });

    public bool RemoveBlockedDevice(Guid id) => Update(s =>
    {
        if (s.Devices.RemoveAll(d => d.Id == id && !d.Enabled) == 0)
            throw new ArgumentException("Only a blocked device can be removed. Refresh the device list.");
        return true;
    });

    // Fixture construction only; production approval consumes a request through ApproveDevice.
    internal Device Enroll(EnrollmentRequest request, Guid[] groupIds) => Update(s =>
    {
        var binding = ValidateRegistration(request);
        ValidateGroups(s, groupIds);
        EnsureIdentityAvailable(s, binding);
        if (s.Devices.Any(device => device.Id == binding.Id) || s.PendingDevices.Any(device => device.Id == binding.Id))
            throw new ArgumentException("Device identity already exists.");
        return CompleteEnrollment(s, binding, request.DeviceName, groupIds);
    });

    private sealed record DeviceBinding(Guid Id, string Digest, string Ecdh, string Kem);
    private const int ClientKemBase64Length = (HybridKem.PublicKeySize + 2) / 3 * 4;

    private static Device CompleteEnrollment(ServerState state, DeviceBinding binding, string name, Guid[] groups)
    {
        EnsureIdentityAvailable(state, binding);
        var device = new Device(binding.Id, name, groups.ToArray(), binding.Ecdh, true, binding.Digest, binding.Kem)
        {
            EnrollmentId = Guid.NewGuid()
        };
        state.PendingDevices.RemoveAll(d => d.ClientPublicKey == binding.Ecdh);
        state.Devices.Add(device);
        return device;
    }

    private static DeviceBinding ValidateRegistration(EnrollmentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateName(request.DeviceName);
        if (request.ClientPublicKey is not { Length: > 0 and <= 256 } || request.ClientMlKemPublicKey is not { Length: ClientKemBase64Length })
            throw new ArgumentException("Both client public keys are required.");
        var ecdh = Convert.FromBase64String(request.ClientPublicKey);
        var kem = Convert.FromBase64String(request.ClientMlKemPublicKey);
        var digest = DeviceIdentity.Id(ecdh, kem);
        if (request.DeviceId != digest || Convert.ToBase64String(ecdh) != request.ClientPublicKey ||
            Convert.ToBase64String(kem) != request.ClientMlKemPublicKey)
            throw new ArgumentException("The device ID must match its canonical ECDH and ML-KEM public keys.");
        return new(Guid.ParseExact(digest[..32], "N"), digest, request.ClientPublicKey, request.ClientMlKemPublicKey);
    }

    private static void EnsureIdentityAvailable(ServerState s, DeviceBinding binding)
    {
        bool Conflict(Guid id, string ecdh, string kem, string digest)
        {
            if (id != binding.Id && ecdh != binding.Ecdh && kem != binding.Kem)
                return false;
            return id != binding.Id || digest != binding.Digest || ecdh != binding.Ecdh || kem != binding.Kem;
        }
        if (s.Devices.Any(d => Conflict(d.Id, d.ClientPublicKey, d.ClientMlKemPublicKey, d.PublicIdentity)) ||
            s.PendingDevices.Any(d => Conflict(d.Id, d.ClientPublicKey, d.ClientMlKemPublicKey, d.PublicIdentity)))
            throw new ArgumentException("A device ID or public key is already bound to another identity.");
    }

    private static void ValidateStoredBinding(Guid id, string ecdh, string? kem, string? digest)
    {
        if (ecdh is not { Length: > 0 and <= 256 } || kem is not { Length: ClientKemBase64Length } || digest is not { Length: 64 })
            throw new ArgumentException("Incomplete client identity.");
        var raw = Convert.FromBase64String(kem);
        var ec = Convert.FromBase64String(ecdh);
        if (Convert.ToBase64String(ec) != ecdh || Convert.ToBase64String(raw) != kem || digest != DeviceIdentity.Id(ec, raw) ||
            Guid.ParseExact(digest[..32], "N") != id)
            throw new ArgumentException("Stored device ID does not match its client public keys.");
    }

    private static void ValidateGroups(ServerState s, Guid[] groupIds)
    {
        if (groupIds is null || groupIds.Distinct().Count() != groupIds.Length || groupIds.Any(id => s.Groups.All(group => group.Id != id)))
            throw new ArgumentException("Unknown or duplicate device group.");
    }
    private static void ValidateName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 100 || value != value.Trim() || value.Any(char.IsControl))
            throw new ArgumentException("Names must contain 1 to 100 characters without leading/trailing whitespace or control characters.");
    }
    public static void ValidateServerName(string? value)
    {
        if (value is null || !Regex.IsMatch(value, @"\A[A-Za-z0-9-]{1,100}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("The server name must contain 1 to 100 ASCII letters, digits, or hyphens.");
    }
    private static ServerState CreateState()
    {
        var name = new string(Environment.MachineName.Take(100).Select(character =>
            char.IsAsciiLetterOrDigit(character) || character == '-' ? character : '-').ToArray());
        if (name.Length == 0)
            name = "Server";
        using var identity = KeyAgreement.NewKey();
        var publicKey = identity.ExportSubjectPublicKeyInfo();
        var privateKey = identity.ExportPkcs8PrivateKey();
        try
        {
            var created = new ServerState
            {
                InviteOnly = true,
                Groups = [new(AdministratorGroupId, AdministratorGroupName)],
                ServerName = name,
                ServerPublicKey = Convert.ToBase64String(publicKey),
                ProtectedServerPrivateKey = PrivateStorage.Protect(privateKey)
            };
            AddServerKem(created);
            return created;
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    private static string ComputeServerId(ServerState state) => ServerIdentityNaming.Id(
        Convert.FromBase64String(state.ServerPublicKey), Convert.FromBase64String(state.ServerMlKemPublicKey));

    private static void AddServerKem(ServerState state)
    {
        using var kem = HybridKem.Generate();
        var seed = kem.ExportPrivateSeed();
        try
        {
            state.ServerMlKemPublicKey = Convert.ToBase64String(kem.ExportPublicKey());
            state.ProtectedServerMlKemSeed = PrivateStorage.Protect(seed);
            state.ServerId = ComputeServerId(state);
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
    private static void Validate(ServerState s, bool validatePrivateKeys = false, bool legacyShares = false)
    {
        if (s.FilePort is < 1 or > 65535 || s.WebPort is < 1 or > 65535)
            throw new ArgumentException("Ports must be between 1 and 65535.");
        if (s.FilePort.HasValue && s.FilePort == s.WebPort)
            throw new ArgumentException("The file service and web UI must use different ports.");
        if (s.SchemaVersion != (legacyShares ? 6 : 7) || s.Groups is null || s.Shares is null || s.Rules is null || s.Devices is null || s.PendingDevices is null ||
            s.Groups.Any(x => x is null) || s.Shares.Any(x => x is null) ||
            s.Rules.Any(x => x is null) || s.Devices.Any(x => x is null) || s.PendingDevices.Any(x => x is null) ||
            s.PendingDevices.Count > 4096 || s.PendingDevices.Count(device => !device.Rejected) > 256)
            throw new ArgumentException("State collections cannot be null or contain null entries.");
        ValidateInvites(s);
        ValidateServerName(s.ServerName);
        if (string.IsNullOrEmpty(s.ServerPublicKey) || s.ProtectedServerPrivateKey is not { Length: > 0 and <= 4096 } ||
            string.IsNullOrEmpty(s.ServerMlKemPublicKey) || s.ProtectedServerMlKemSeed is not { Length: > 0 and <= 4096 })
            throw new ArgumentException("Missing server identity key material.");
        using (var publicKey = KeyAgreement.ImportPublic(Convert.FromBase64String(s.ServerPublicKey)))
        {
            var canonical = publicKey.ExportSubjectPublicKeyInfo();
            var kemPublic = Convert.FromBase64String(s.ServerMlKemPublicKey);
            if (s.ServerPublicKey != Convert.ToBase64String(canonical) || s.ServerMlKemPublicKey != Convert.ToBase64String(kemPublic) ||
                s.ServerId != ServerIdentityNaming.Id(canonical, kemPublic))
                throw new ArgumentException("The server ID must match its ECDH and ML-KEM public keys.");
            if (validatePrivateKeys)
            {
                var privateKey = PrivateStorage.Unprotect(s.ProtectedServerPrivateKey);
                try
                {
                    using var identity = KeyAgreement.ImportPrivate(privateKey);
                    if (!KeyAgreement.Equals(identity.ExportSubjectPublicKeyInfo(), canonical))
                        throw new ArgumentException("The server private key does not match its public identity.");
                }
                finally { CryptographicOperations.ZeroMemory(privateKey); }
                var kemSeed = PrivateStorage.Unprotect(s.ProtectedServerMlKemSeed);
                try
                {
                    using var kem = HybridKem.ImportPrivateSeed(kemSeed);
                    if (!KeyAgreement.Equals(kem.ExportPublicKey(), kemPublic))
                        throw new ArgumentException("The server ML-KEM private seed does not match its public key.");
                }
                finally { CryptographicOperations.ZeroMemory(kemSeed); }
            }
        }
        static void Unique<T>(IEnumerable<T> values, string what, IEqualityComparer<T>? comparer = null)
        {
            var seen = new HashSet<T>(comparer);
            foreach (var value in values)
                if (!seen.Add(value))
                    throw new ArgumentException($"Duplicate {what}.");
        }
        foreach (var name in s.Groups.Select(x => x.Name).Concat(s.Shares.Select(x => x.Name)))
            ValidateName(name);
        Unique(s.Groups.Select(x => x.Id), "group ID");
        Unique(s.Shares.Select(x => x.Id), "share ID");
        Unique(s.Rules.Select(x => x.Id), "rule ID");
        Unique(s.Rules.Select(x => (x.GroupId, x.ShareId)), "group/share permission assignment; edit the existing assignment to add a path");
        Unique(s.Devices.Select(x => x.Id).Concat(s.PendingDevices.Select(x => x.Id)), "device ID");
        Unique(s.Groups.Select(x => x.Name), "group name", StringComparer.OrdinalIgnoreCase);
        if (!s.Groups.Any(group => group.Id == AdministratorGroupId && group.Name == AdministratorGroupName))
            throw new ArgumentException("The built-in Administrator group cannot be removed or renamed.");
        Unique(s.Shares.Select(x => x.Name), "share name", StringComparer.OrdinalIgnoreCase);
        Unique(s.Devices.Select(x => x.ClientPublicKey).Concat(s.PendingDevices.Select(x => x.ClientPublicKey)), "device ECDH key", StringComparer.Ordinal);
        Unique(s.Devices.Select(x => x.ClientMlKemPublicKey).Concat(s.PendingDevices.Select(x => x.ClientMlKemPublicKey)), "device ML-KEM key", StringComparer.Ordinal);
        if (s.Admin is { } admin)
        {
            ValidateName(admin.Name);
            if (admin.Salt is not { Length: 32 } || admin.Hash is not { Length: 32 } ||
                admin.Algorithm != "PBKDF2-HMAC-SHA3-256")
                throw new ArgumentException("Invalid administrator credential.");
        }
        foreach (var group in s.Groups)
        {
            if (group.Id == Guid.Empty)
                throw new ArgumentException("Missing group ID.");
        }
        foreach (var share in s.Shares)
        {
            if (!legacyShares && share.Id == AllSharesId)
                throw new ArgumentException("The built-in All share cannot be replaced, renamed or disabled.");
            if (share.Id == Guid.Empty || NormalizeRelative(share.Name) != share.Name || share.Name.Contains('/'))
                throw new ArgumentException("Share names must be single Windows file names.");
            NormalizeLocalSharePath(share.LocalPath);
        }
        foreach (var rule in s.Rules)
        {
            var allShares = !legacyShares && rule.ShareId == AllSharesId;
            if (rule.GroupId == AdministratorGroupId)
                throw new ArgumentException("Administrator already has automatic full control on every share.");
            if (rule.Id == Guid.Empty || rule.AdditionalScopes is null ||
                s.Groups.All(x => x.Id != rule.GroupId) || (!allShares && s.Shares.All(x => x.Id != rule.ShareId)))
                throw new ArgumentException("Invalid group permission rule.");
            var inherited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var scope in rule.Scopes())
            {
                if (scope is null || scope.Path != NormalizeRelative(scope.Path) ||
                    ((scope.Allow | scope.Deny) & ~Permission.FullControl) != 0 || (scope.Allow & scope.Deny) != 0)
                    throw new ArgumentException("Invalid permission path or conflicting allow and deny flags.");
                if (allShares && scope.Path.Length != 0)
                    throw new ArgumentException("Choose an individual share to assign permissions to a named path.");
                if (!(scope.Inherit ? inherited : exact).Add(scope.Path))
                    throw new ArgumentException("A permission path with the same inheritance already exists in this assignment.");
            }
        }
        foreach (var device in s.Devices)
        {
            ValidateName(device.Name);
            ValidateStoredBinding(device.Id, device.ClientPublicKey, device.ClientMlKemPublicKey, device.PublicIdentity);
            if (device.Id == Guid.Empty || device.EnrollmentId == Guid.Empty)
                throw new ArgumentException("Missing device or enrollment ID.");
            ValidateGroups(s, device.GroupIds);
        }
        foreach (var pending in s.PendingDevices)
        {
            ValidateName(pending.Name);
            ValidateStoredBinding(pending.Id, pending.ClientPublicKey, pending.ClientMlKemPublicKey, pending.PublicIdentity);
            if (pending.Id == Guid.Empty || pending.FirstSeenUtc.Kind != DateTimeKind.Utc || pending.LastSeenUtc.Kind != DateTimeKind.Utc ||
                pending.LastSeenUtc < pending.FirstSeenUtc || string.IsNullOrEmpty(pending.ClientPublicKey))
                throw new ArgumentException("Invalid pending device request.");
        }
    }
}
