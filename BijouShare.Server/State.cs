using System.Security.Cryptography;
using System.Text.RegularExpressions;
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
public sealed record AccessRule(Guid Id, Guid GroupId, Guid ShareId, string Path,
    Permission Allow, Permission Deny, bool Inherit);
public sealed record Device(Guid Id, string Name, Guid[] GroupIds, string ClientPublicKey,
    byte[] ProtectedServerPrivateKey, string ServerPublicKey, bool Enabled);
public sealed record PendingDevice(Guid Id, string Name, string ClientPublicKey, DateTime FirstSeenUtc, DateTime LastSeenUtc,
    bool Rejected = false);
public sealed record AdminCredential(string Name, byte[] Salt, byte[] Hash);
public sealed class ServerState
{
    public int SchemaVersion { get; set; } = 3;
    public string ServerId { get; set; } = "";
    public string ServerName { get; set; } = "";
    public string ServerPublicKey { get; set; } = "";
    public byte[] ProtectedServerPrivateKey { get; set; } = [];
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
    private readonly ReaderWriterLockSlim gate = new(LockRecursionPolicy.SupportsRecursion);
    private long revision;
    public long Revision => Interlocked.Read(ref revision);
    private readonly string path;
    private ServerState state;
    public string ServerId => Read(s => s.ServerId);
    public string ServerName => Read(s => s.ServerName);
    public string ServerPublicKey => Read(s => s.ServerPublicKey);
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
        Validate(state, validatePrivateKeys: true);
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
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        Update(s =>
        {
            s.Admin = new(name, salt, hash);
            if (serverName is not null)
            {
                s.ServerName = serverName;
                s.ServerId = ServerIdentityNaming.Id(serverName, Convert.FromBase64String(s.ServerPublicKey));
            }
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
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, admin.Salt, 600_000, HashAlgorithmName.SHA256, 32);
        try
        {
            return KeyAgreement.Equals(admin.Hash, hash) && string.Equals(admin.Name, name, StringComparison.Ordinal) ? admin : null;
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }
    public bool VerifyAdmin(string? name, string? password) => AuthenticateAdmin(name, password) is not null;
    public void ChangeAdminPassword(string name, string currentPassword, string newPassword)
    {
        var verified = AuthenticateAdmin(name, currentPassword) ?? throw new ArgumentException("Current password is incorrect.");
        if (newPassword is null || newPassword.Length is < 14 or > 1024)
            throw new ArgumentException("Use an administrator password of 14 to 1024 characters.");
        var salt = RandomNumberGenerator.GetBytes(32);
        var hash = Rfc2898DeriveBytes.Pbkdf2(newPassword, salt, 600_000, HashAlgorithmName.SHA256, 32);
        Update(s =>
        {
            if (s.Admin is null || !KeyAgreement.Equals(verified.Hash, s.Admin.Hash) || s.Admin.Name != verified.Name)
                throw new ArgumentException("The administrator credential changed. Sign in again.");
            s.Admin = new(name, salt, hash);
            return true;
        });
    }
    public Device? FindRegisteredDevice(Guid deviceId) => Read(s => s.Devices.SingleOrDefault(x => x.Id == deviceId));
    public Device Identity(Guid deviceId) => Read(s => s.Devices.SingleOrDefault(x => x.Id == deviceId && x.Enabled)
        ?? throw new UnauthorizedAccessException());

    // Call only after proving possession of the client's private key for this identity.
    public Device UpdateAuthenticatedDeviceName(Device authenticated, string name)
    {
        ValidateName(name);
        gate.EnterWriteLock();
        try
        {
            var current = Identity(authenticated.Id);
            if (current.ClientPublicKey != authenticated.ClientPublicKey || current.ServerPublicKey != authenticated.ServerPublicKey)
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
        var allow = Permission.None;
        var deny = Permission.None;
        foreach (var rule in s.Rules.Where(x => x.ShareId == shareId && device.GroupIds.Contains(x.GroupId)))
        {
            if (rule.Path.Equals(relative, StringComparison.OrdinalIgnoreCase) || rule.Inherit && AtOrBelow(relative, rule.Path))
            {
                allow |= rule.Allow;
                deny |= rule.Deny;
            }
        }
        return allow & ~deny;
    });
    public PendingDevice? FindPendingDevice(Guid deviceId) => Read(s => s.PendingDevices.SingleOrDefault(x => x.Id == deviceId));

    // The network caller proves possession of the supplied static private key before calling this method.
    public bool QueueRegistration(EnrollmentRequest request)
    {
        var (id, key) = ValidateRegistration(request);
        gate.EnterWriteLock();
        try
        {
            EnsureIdentityAvailable(state, id, key);
            if (state.Devices.Any(device => device.Id == id))
                return true;
            var pending = state.PendingDevices.SingleOrDefault(device => device.Id == id);
            if (pending?.Rejected == true)
                throw new UnauthorizedAccessException("Device registration was rejected by an administrator.");
            var now = DateTime.UtcNow;
            if (pending is not null && pending.Name == request.DeviceName && now - pending.LastSeenUtc < TimeSpan.FromMinutes(5))
                return false;
            if (pending is null && (state.PendingDevices.Count >= 4096 || state.PendingDevices.Count(device => !device.Rejected) >= 256))
                throw new UnauthorizedAccessException("The device approval queue is full.");
            Update(s =>
            {
                if (pending is null)
                    s.PendingDevices.Add(new(id, request.DeviceName, key, now, now));
                else
                    s.PendingDevices[s.PendingDevices.FindIndex(device => device.Id == id)] = pending with
                    {
                        Name = request.DeviceName,
                        LastSeenUtc = now
                    };
                return true;
            });
            return false;
        }
        finally { gate.ExitWriteLock(); }
    }

    public Device ApproveDevice(Guid id, Guid[] groupIds, string expectedFingerprint) => Update(s =>
    {
        var pending = s.PendingDevices.SingleOrDefault(device => device.Id == id)
            ?? throw new ArgumentException("No pending device request exists for this ID.");
        if (!string.Equals(KeyAgreement.Fingerprint(pending.ClientPublicKey), expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The pending device identity changed. Refresh and verify its fingerprint again.");
        ValidateGroups(s, groupIds);
        EnsureIdentityAvailable(s, id, pending.ClientPublicKey);
        var device = CreateDevice(id, pending.Name, pending.ClientPublicKey, groupIds);
        s.PendingDevices.Remove(pending);
        s.Devices.Add(device);
        return device;
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

    // Fixture construction only; production approval consumes a request through ApproveDevice.
    internal Device Enroll(EnrollmentRequest request, Guid[] groupIds) => Update(s =>
    {
        var (id, key) = ValidateRegistration(request);
        ValidateGroups(s, groupIds);
        EnsureIdentityAvailable(s, id, key);
        if (s.Devices.Any(device => device.Id == id) || s.PendingDevices.Any(device => device.Id == id))
            throw new ArgumentException("Device identity already exists.");
        var device = CreateDevice(id, request.DeviceName, key, groupIds);
        s.Devices.Add(device);
        return device;
    });

    private static Device CreateDevice(Guid id, string name, string canonicalPublicKey, Guid[] groupIds)
    {
        using var server = KeyAgreement.NewKey();
        var privateKey = server.ExportPkcs8PrivateKey();
        try
        {
            return new Device(id, name, groupIds.ToArray(), canonicalPublicKey,
                PrivateStorage.Protect(privateKey), Convert.ToBase64String(server.ExportSubjectPublicKeyInfo()), true);
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    private static (Guid Id, string Key) ValidateRegistration(EnrollmentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!Guid.TryParse(request.DeviceId, out var id) || id == Guid.Empty)
            throw new ArgumentException("Invalid device ID.");
        ValidateName(request.DeviceName);
        if (string.IsNullOrEmpty(request.ClientPublicKey) || request.ClientPublicKey.Length > 512)
            throw new ArgumentException("Invalid client public key.");
        using var client = KeyAgreement.ImportPublic(Convert.FromBase64String(request.ClientPublicKey));
        return (id, Convert.ToBase64String(client.ExportSubjectPublicKeyInfo()));
    }

    private static void EnsureIdentityAvailable(ServerState s, Guid id, string key)
    {
        if (s.Devices.Any(device => device.Id == id && device.ClientPublicKey != key || device.Id != id && device.ClientPublicKey == key) ||
            s.PendingDevices.Any(device => device.Id == id && device.ClientPublicKey != key || device.Id != id && device.ClientPublicKey == key))
            throw new ArgumentException("The device ID or public key is already bound to another identity.");
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
            return new()
            {
                ServerId = ServerIdentityNaming.Id(name, publicKey),
                ServerName = name,
                ServerPublicKey = Convert.ToBase64String(publicKey),
                ProtectedServerPrivateKey = PrivateStorage.Protect(privateKey)
            };
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }
    private static void Validate(ServerState s, bool validatePrivateKeys = false)
    {
        if (s.SchemaVersion != 3 || s.Groups is null || s.Shares is null || s.Rules is null || s.Devices is null || s.PendingDevices is null ||
            s.Groups.Any(x => x is null) || s.Shares.Any(x => x is null) ||
            s.Rules.Any(x => x is null) || s.Devices.Any(x => x is null) || s.PendingDevices.Any(x => x is null) ||
            s.PendingDevices.Count > 4096 || s.PendingDevices.Count(device => !device.Rejected) > 256)
            throw new ArgumentException("State collections cannot be null or contain null entries.");
        ValidateInvites(s);
        ValidateServerName(s.ServerName);
        if (string.IsNullOrEmpty(s.ServerPublicKey) || s.ProtectedServerPrivateKey is not { Length: > 0 and <= 4096 })
            throw new ArgumentException("Missing server identity key material.");
        using (var publicKey = KeyAgreement.ImportPublic(Convert.FromBase64String(s.ServerPublicKey)))
        {
            var canonical = publicKey.ExportSubjectPublicKeyInfo();
            if (s.ServerPublicKey != Convert.ToBase64String(canonical) ||
                s.ServerId != ServerIdentityNaming.Id(s.ServerName, canonical))
                throw new ArgumentException("The server ID must be the lowercase SHA-256 hash of its UTF-8 name followed by its canonical public key.");
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
        Unique(s.Devices.Select(x => x.Id).Concat(s.PendingDevices.Select(x => x.Id)), "device ID");
        Unique(s.Groups.Select(x => x.Name), "group name", StringComparer.OrdinalIgnoreCase);
        Unique(s.Shares.Select(x => x.Name), "share name", StringComparer.OrdinalIgnoreCase);
        Unique(s.Devices.Select(x => x.ClientPublicKey).Concat(s.PendingDevices.Select(x => x.ClientPublicKey)), "device public key", StringComparer.Ordinal);
        if (s.Admin is { } admin)
        {
            ValidateName(admin.Name);
            if (admin.Salt is not { Length: 32 } || admin.Hash is not { Length: 32 })
                throw new ArgumentException("Invalid administrator credential.");
        }
        foreach (var group in s.Groups)
        {
            if (group.Id == Guid.Empty)
                throw new ArgumentException("Missing group ID.");
        }
        foreach (var share in s.Shares)
        {
            if (share.Id == Guid.Empty || NormalizeRelative(share.Name) != share.Name || share.Name.Contains('/'))
                throw new ArgumentException("Share names must be single Windows file names.");
            NormalizeLocalSharePath(share.LocalPath);
        }
        foreach (var rule in s.Rules)
        {
            if (rule.Id == Guid.Empty || rule.Path != NormalizeRelative(rule.Path) ||
                s.Groups.All(x => x.Id != rule.GroupId) || s.Shares.All(x => x.Id != rule.ShareId) ||
                ((rule.Allow | rule.Deny) & ~Permission.FullControl) != 0)
                throw new ArgumentException("Invalid group permission rule.");
        }
        foreach (var device in s.Devices)
        {
            ValidateName(device.Name);
            if (device.Id == Guid.Empty)
                throw new ArgumentException("Missing device ID.");
            ValidateGroups(s, device.GroupIds);
            if (device.ProtectedServerPrivateKey is not { Length: > 0 and <= 4096 } ||
                string.IsNullOrEmpty(device.ClientPublicKey) || string.IsNullOrEmpty(device.ServerPublicKey))
                throw new ArgumentException("Missing device key material.");
            using var client = KeyAgreement.ImportPublic(Convert.FromBase64String(device.ClientPublicKey));
            using var server = KeyAgreement.ImportPublic(Convert.FromBase64String(device.ServerPublicKey));
            if (device.ClientPublicKey != Convert.ToBase64String(client.ExportSubjectPublicKeyInfo()) ||
                device.ServerPublicKey != Convert.ToBase64String(server.ExportSubjectPublicKeyInfo()))
                throw new ArgumentException("Device public keys must use canonical encoding.");
            if (validatePrivateKeys)
            {
                var privateKey = PrivateStorage.Unprotect(device.ProtectedServerPrivateKey);
                try
                {
                    using var key = KeyAgreement.ImportPrivate(privateKey);
                    if (!KeyAgreement.Equals(key.ExportSubjectPublicKeyInfo(), server.ExportSubjectPublicKeyInfo()))
                        throw new ArgumentException("An enrolled server private key does not match its public key.");
                }
                finally { CryptographicOperations.ZeroMemory(privateKey); }
            }
        }
        foreach (var pending in s.PendingDevices)
        {
            ValidateName(pending.Name);
            if (pending.Id == Guid.Empty || pending.FirstSeenUtc.Kind != DateTimeKind.Utc || pending.LastSeenUtc.Kind != DateTimeKind.Utc ||
                pending.LastSeenUtc < pending.FirstSeenUtc || string.IsNullOrEmpty(pending.ClientPublicKey))
                throw new ArgumentException("Invalid pending device request.");
            using var client = KeyAgreement.ImportPublic(Convert.FromBase64String(pending.ClientPublicKey));
            if (pending.ClientPublicKey != Convert.ToBase64String(client.ExportSubjectPublicKeyInfo()))
                throw new ArgumentException("Pending device public keys must use canonical encoding.");
        }
    }
}
