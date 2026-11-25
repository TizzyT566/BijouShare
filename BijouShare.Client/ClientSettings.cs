using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed class ServerEndpoint
{
    private readonly object metadataGate = new();
    private string? cachedName, cachedId, cachedFolder;
    private CancellationTokenSource verificationLifetime = new();
    public string Name { get; set; } = "Server";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 7443;
    // Null follows the primary drive. Before the first drive is added, the server waits.
    public string? MountPoint { get; set; }
    public string? TrustedServerId { get; set; }
    internal CancellationToken VerificationToken => verificationLifetime.Token;
    [JsonIgnore] public string? PresentedServerId
    {
        get { lock (metadataGate) return ServerId; }
    }
    [JsonIgnore] public string? PresentedServerName
    {
        get { lock (metadataGate) return ServerName; }
    }
    public string? ServerMlKemPublicKey { get; set; }
    public byte[]? ProtectedInviteCode
    {
        get; set;
    }
    public string? ServerId
    {
        get; set;
    }
    public string? ServerName
    {
        get; set;
    }
    public string? ServerIdentityPublicKey
    {
        get; set;
    }
    [System.Text.Json.Serialization.JsonIgnore]
    public string? FolderName
    {
        get
        {
            lock (metadataGate)
            {
                if (ServerId is null || ServerId != TrustedServerId || ServerName is null || ServerMlKemPublicKey is null)
                    return null;
                if (cachedName != ServerName || cachedId != ServerId)
                {
                    cachedFolder = ServerIdentityNaming.FolderName(ServerName, ServerId);
                    cachedName = ServerName;
                    cachedId = ServerId;
                }
                return cachedFolder;
            }
        }
    }
    internal void SetIdentity(string? id, string? name, string? publicKey, string? kemKey = null)
    {
        lock (metadataGate)
        {
            ServerId = id;
            ServerName = name;
            ServerIdentityPublicKey = publicKey;
            ServerMlKemPublicKey = kemKey;
            cachedName = cachedId = cachedFolder = null;
        }
    }

    internal readonly record struct IdentityState(string? Anchor, string? Id, string? Name, string? GlobalKey, string? KemKey);
    internal IdentityState SavedIdentity => new(TrustedServerId, ServerId, ServerName, ServerIdentityPublicKey, ServerMlKemPublicKey);
    internal void SetSavedIdentity(IdentityState state)
    {
        TrustedServerId = state.Anchor;
        SetIdentity(state.Id, state.Name, state.GlobalKey, state.KemKey);
    }

    internal void InvalidateSessions()
    {
        var previous = verificationLifetime;
        verificationLifetime = new();
        previous.Cancel();
        previous.Dispose();
    }
}

public sealed partial class ClientSettings
{
    private const int CurrentFormat = 6;
    private const int MaximumSettingsBytes = 1024 * 1024;
    private readonly object persistenceGate = new();
    private ClientSettings? parent;
    private ServerEndpoint? endpoint;
    internal CancellationToken VerificationToken { get; private set; }
    internal bool IsVerificationCurrent => !VerificationToken.IsCancellationRequested;
    public string DeviceId { get; set; } = "";
    public string DeviceName { get; set; } = Environment.MachineName;
    public bool SetupComplete { get; set; } = true;
    public int ManagementPort { get; set; }
    public byte[] ProtectedPrivateKey { get; set; } = [];
    public string PublicKey { get; set; } = "";
    internal string? TrustedServerId => endpoint?.TrustedServerId;
    public string MlKemPublicKey { get; set; } = "";
    public byte[] ProtectedMlKemPrivateSeed { get; set; } = [];
    internal string Host => endpoint?.Host ?? "";
    internal int Port => endpoint?.Port ?? 0;
    public List<ServerEndpoint> Servers { get; set; } = [];
    public int IdentityFormat { get; set; }
    public string MountPoint { get; set; } = "";
    public List<string> AdditionalMountPoints { get; set; } = [];
    public Dictionary<string, string> DriveNames { get; set; } = [];
    // Identifies separately authorized Windows grants. The profile alone cannot authorize elevation.
    [JsonInclude] private Dictionary<string, Guid> ElevatedDriveGrants { get; set; } = [];
    public const string DefaultDriveName = "BijouShare";
    public int RequestTimeoutSeconds { get; set; } = 30;
    internal bool IsConfigured => endpoint is not null || Servers.Count > 0;
    [System.Text.Json.Serialization.JsonIgnore]
    internal string? SettingsPath
    {
        get; private set;
    }

    public static ClientSettings Create(string name)
    {
        using var key = KeyAgreement.NewKey();
        var privateKey = key.ExportPkcs8PrivateKey();
        try
        {
            var settings = new ClientSettings
            {
                IdentityFormat = CurrentFormat,
                DeviceName = name,
                ProtectedPrivateKey = UserSecrets.Protect(privateKey),
                PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())
            };
            settings.GenerateIdentityKem();
            return settings;
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    private void GenerateIdentityKem()
    {
        using var kem = HybridKem.Generate();
        var seed = kem.ExportPrivateSeed();
        try
        {
            var publicKem = kem.ExportPublicKey();
            var id = DeviceIdentity.Id(DecodePublicKey(PublicKey), publicKem);
            ProtectedMlKemPrivateSeed = UserSecrets.Protect(seed);
            MlKemPublicKey = Convert.ToBase64String(publicKem);
            DeviceId = id;
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    internal HybridKem OpenIdentityKem()
    {
        var seed = UserSecrets.Unprotect(ProtectedMlKemPrivateSeed);
        try { return HybridKem.ImportPrivateSeed(seed); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    internal void AttachPath(string path) => SettingsPath = Path.GetFullPath(path);

    public string[] DriveSnapshot()
    {
        lock (persistenceGate)
            return MountPoint.Length == 0 ? [] : [MountPoint, .. AdditionalMountPoints];
    }

    public ServerEndpoint[] ServerSnapshot(string? mountPoint = null)
    {
        lock (persistenceGate)
            return mountPoint is null ? Servers.ToArray() :
                Servers.Where(server => (server.MountPoint ?? MountPoint) == mountPoint).ToArray();
    }

    public string GetDriveName(string mountPoint)
    {
        lock (persistenceGate)
            return DriveNames.GetValueOrDefault(NormalizeMountPoint(mountPoint), DefaultDriveName);
    }

    internal Guid? ElevatedGrant(string mountPoint)
    {
        lock (persistenceGate)
            return ElevatedDriveGrants.TryGetValue(NormalizeMountPoint(mountPoint), out var grant) ? grant : null;
    }

    internal void SetElevatedGrant(string mountPoint, Guid? grant) => UpdateElevatedGrant(mountPoint, grant, null);

    internal bool ClearElevatedGrant(string mountPoint, Guid expected) => UpdateElevatedGrant(mountPoint, null, expected);

    private bool UpdateElevatedGrant(string mountPoint, Guid? grant, Guid? expected)
    {
        if (parent is not null)
            throw new InvalidOperationException("Configure drive access on the root client settings.");
        mountPoint = NormalizeMountPoint(mountPoint);
        if (grant == Guid.Empty || expected == Guid.Empty)
            throw new ArgumentException("A drive access grant requires a nonempty ID.");
        lock (persistenceGate)
        {
            var previous = ElevatedGrant(mountPoint);
            if (expected.HasValue && previous != expected) return false;
            if (!DriveSnapshot().Contains(mountPoint))
                throw new ArgumentException("Unknown drive.");
            if (previous == grant) return false;
            if (grant.HasValue) ElevatedDriveGrants[mountPoint] = grant.Value;
            else ElevatedDriveGrants.Remove(mountPoint);
            try { PersistChange(); }
            catch
            {
                if (previous.HasValue) ElevatedDriveGrants[mountPoint] = previous.Value;
                else ElevatedDriveGrants.Remove(mountPoint);
                throw;
            }
            return true;
        }
    }

    public void RenameDrive(string mountPoint, string name)
    {
        if (!TryRenameDrive(mountPoint, null, name))
            throw new ArgumentException("Unknown drive.");
    }

    internal bool TryRenameDrive(string mountPoint, string? expectedName, string newName)
    {
        mountPoint = NormalizeMountPoint(mountPoint);
        ValidateDriveName(newName);
        lock (persistenceGate)
        {
            if (!DriveSnapshot().Contains(mountPoint))
                return false;
            var previous = DriveNames.GetValueOrDefault(mountPoint);
            var current = previous ?? DefaultDriveName;
            if (expectedName is not null && current != expectedName)
                return false;
            if (current == newName)
                return true;
            DriveNames[mountPoint] = newName;
            try { PersistChange(); }
            catch
            {
                if (previous is null) DriveNames.Remove(mountPoint);
                else DriveNames[mountPoint] = previous;
                throw;
            }
        }
        return true;
    }

    public void AddDrive(string mountPoint, string name = DefaultDriveName)
    {
        mountPoint = NormalizeMountPoint(mountPoint);
        ValidateDriveName(name);
        lock (persistenceGate)
        {
            if (!SetupComplete)
                throw new ArgumentException("Complete device setup before adding a drive.");
            if (DriveSnapshot().Contains(mountPoint))
                throw new ArgumentException("That drive is already configured.");
            var first = MountPoint.Length == 0;
            if (first)
                MountPoint = mountPoint;
            else
                AdditionalMountPoints.Add(mountPoint);
            DriveNames.Add(mountPoint, name);
            try { PersistChange(); }
            catch
            {
                DriveNames.Remove(mountPoint);
                if (first)
                    MountPoint = "";
                else
                    AdditionalMountPoints.Remove(mountPoint);
                throw;
            }
        }
    }

    public void RemoveDrive(string mountPoint)
    {
        mountPoint = NormalizeMountPoint(mountPoint);
        lock (persistenceGate)
        {
            if (!DriveSnapshot().Contains(mountPoint))
                throw new ArgumentException("Unknown drive.");
            if (ServerSnapshot(mountPoint).Length != 0)
                throw new ArgumentException("Disconnect this drive's servers before removing it.");
            var hadName = DriveNames.Remove(mountPoint, out var name);
            var hadGrant = ElevatedDriveGrants.Remove(mountPoint, out var grant);
            if (AdditionalMountPoints.Count == 0)
            {
                MountPoint = "";
                try { PersistChange(); }
                catch
                {
                    MountPoint = mountPoint;
                    if (hadName) DriveNames[mountPoint] = name!;
                    if (hadGrant) ElevatedDriveGrants[mountPoint] = grant;
                    throw;
                }
                return;
            }
            var oldPrimary = MountPoint;
            var removedLetter = mountPoint == MountPoint ? AdditionalMountPoints[0] : mountPoint;
            var index = AdditionalMountPoints.IndexOf(removedLetter);
            var promoted = mountPoint == MountPoint ? ServerSnapshot(removedLetter) : [];
            if (mountPoint == MountPoint)
            {
                MountPoint = removedLetter;
                foreach (var server in promoted)
                    server.MountPoint = null;
            }
            AdditionalMountPoints.RemoveAt(index);
            try { PersistChange(); }
            catch
            {
                MountPoint = oldPrimary;
                if (hadName) DriveNames[mountPoint] = name!;
                if (hadGrant) ElevatedDriveGrants[mountPoint] = grant;
                AdditionalMountPoints.Insert(index, removedLetter);
                foreach (var server in promoted)
                    server.MountPoint = removedLetter;
                throw;
            }
        }
    }

    private void PersistChange()
    {
        if (SettingsPath is not null)
            Save(SettingsPath);
        else
            Validate();
    }

    public ServerEndpoint AddServer(string host, int port, string? inviteCode, string? mountPoint = null, string? trustedServerId = null, bool preserveInvite = false)
    {
        if (parent is not null)
            throw new InvalidOperationException("Configure servers on the root settings.");
        WadUri.ValidateInviteCode(inviteCode);
        lock (persistenceGate)
        {
            var previous = Servers.ToArray();
            var server = UpsertServer(host, port, mountPoint: mountPoint);
            var oldInvite = server.ProtectedInviteCode;
            var oldPin = server.TrustedServerId;
            try
            {
                SetTrustedServerId(server, trustedServerId ?? server.TrustedServerId ?? throw new ArgumentException("A full server fingerprint is required. Open the server's connection link."));
                if (inviteCode is not null)
                {
                    var bytes = Encoding.UTF8.GetBytes(inviteCode);
                    try
                    {
                        server.ProtectedInviteCode = UserSecrets.Protect(bytes);
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
                else if (!preserveInvite)
                    server.ProtectedInviteCode = null;
                if (SettingsPath is not null)
                    Save(SettingsPath);
                else
                    Validate();
                return server;
            }
            catch
            {
                server.ProtectedInviteCode = oldInvite;
                server.TrustedServerId = oldPin;
                Servers.Clear();
                Servers.AddRange(previous);
                throw;
            }
        }
    }

    private static bool SameAddress(ServerEndpoint endpoint, string host, int port) => endpoint.Port == port &&
        NormalizeHost(endpoint.Host).Equals(NormalizeHost(host), StringComparison.OrdinalIgnoreCase);

    private void SetTrustedServerId(ServerEndpoint server, string fingerprint)
    {
        ServerIdentityNaming.ValidateId(fingerprint);
        if (Servers.Any(peer => SameAddress(peer, server.Host, server.Port) &&
            peer.TrustedServerId is { } expected && expected != fingerprint))
            throw new ArgumentException("The fingerprint differs from the saved trust for this server.");
        server.TrustedServerId = fingerprint;
    }

    public bool RemoveServer(string host, int port, string? mountPoint = null)
    {
        lock (persistenceGate)
        {
            var drive = mountPoint is null ? MountPoint : NormalizeMountPoint(mountPoint);
            var index = Servers.FindIndex(server => (server.MountPoint ?? MountPoint) == drive &&
                server.Port == port && NormalizeHost(server.Host).Equals(NormalizeHost(host), StringComparison.OrdinalIgnoreCase));
            if (index < 0)
                return false;
            var removed = Servers[index];
            Servers.RemoveAt(index);
            try
            {
                if (SettingsPath is not null)
                    Save(SettingsPath);
                removed.InvalidateSessions();
                return true;
            }
            catch
            {
                Servers.Insert(index, removed);
                throw;
            }
        }
    }

    public void UpdateDevice(string name)
    {
        ValidateName(name, "device name");
        lock (persistenceGate)
        {
            var previous = (DeviceName, SetupComplete);
            DeviceName = name;
            SetupComplete = true;
            try
            {
                if (SettingsPath is not null)
                    Save(SettingsPath);
                else
                    Validate();
            }
            catch
            {
                (DeviceName, SetupComplete) = previous;
                throw;
            }
        }
    }

    public string? GetInviteCode()
    {
        var owner = parent ?? this;
        lock (owner.persistenceGate)
        {
            if (endpoint is null || !owner.Servers.Contains(endpoint) || endpoint.ProtectedInviteCode is null)
                return null;
            var bytes = UserSecrets.Unprotect(endpoint.ProtectedInviteCode);
            try
            {
                return Encoding.UTF8.GetString(bytes);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    public void ClearInviteCode(string? expected)
    {
        if (expected is null)
            return;
        var owner = parent ?? this;
        lock (owner.persistenceGate)
        {
            if (endpoint is null || !owner.Servers.Contains(endpoint) || GetInviteCode() != expected)
                return;
            var previous = endpoint.ProtectedInviteCode;
            endpoint.ProtectedInviteCode = null;
            try
            {
                if (owner.SettingsPath is not null)
                    owner.Save(owner.SettingsPath);
            }
            catch { endpoint.ProtectedInviteCode = previous; throw; }
        }
    }
    public static ClientSettings Load(string path)
    {
        using var file = File.OpenRead(path);
        RequireCurrentFormat(file);
        file.Position = 0;
        var settings = JsonSerializer.Deserialize<ClientSettings>(file, Wire.Json) ?? throw new InvalidDataException("Empty client profile.");
        settings.Validate();
        settings.SettingsPath = Path.GetFullPath(path);
        return settings;
    }
    internal static void RequireCurrentFormat(Stream file)
    {
        if (file.Length > MaximumSettingsBytes)
            throw new InvalidDataException("The client settings file exceeds 1 MiB.");
        using var document = JsonDocument.Parse(file);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("identityFormat", out var format) || format.ValueKind != JsonValueKind.Number ||
            !format.TryGetInt32(out var version) || version != CurrentFormat)
            throw new InvalidDataException("Unsupported client profile format. Keep a backup and configure a new v6 profile.");
    }

    public void Save(string path)
    {
        if (parent is not null)
            throw new InvalidOperationException("Save the root client configuration, not a per-server view.");
        lock (persistenceGate)
        {
            Validate();
            var bytes = Wire.Encode(this);
            if (bytes.Length > MaximumSettingsBytes)
                throw new InvalidDataException("The client settings exceed 1 MiB.");
            PrivateStorage.AtomicWrite(path, bytes);
            SettingsPath = Path.GetFullPath(path);
        }
    }

    public void Validate(bool requireEnrollment = false)
    {
        ValidateNetworkListeners();
        if (Servers is null || Servers.Count > 64 || Servers.Any(server => server is null))
            throw new InvalidDataException("Configure at most 64 non-null servers.");
        if (IdentityFormat != CurrentFormat)
            throw new InvalidDataException("Unsupported client identity format.");
        ValidateName(DeviceName, "device name");
        if (ProtectedPrivateKey is not { Length: > 0 and <= 4096 })
            throw new InvalidDataException("Missing or invalid protected client identity.");
        var publicKey = DecodePublicKey(PublicKey);
        byte[] privateKey;
        try
        {
            privateKey = UserSecrets.Unprotect(ProtectedPrivateKey);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException("The client identity cannot be decrypted. Open this profile as the Windows user who created it, or create and enroll a new identity.", ex);
        }
        try
        {
            using var key = KeyAgreement.ImportPrivate(privateKey);
            if (!KeyAgreement.Equals(key.ExportSubjectPublicKeyInfo(), publicKey))
                throw new InvalidDataException("The client public and private keys do not match.");
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }

        if (ProtectedMlKemPrivateSeed is not { Length: > 0 and <= 4096 } ||
            MlKemPublicKey is null || MlKemPublicKey.Length != ((HybridKem.PublicKeySize + 2) / 3) * 4)
            throw new InvalidDataException("Incomplete protected ML-KEM device identity.");
        try
        {
            var publicKem = Convert.FromBase64String(MlKemPublicKey);
            using var kem = OpenIdentityKem();
            if (!KeyAgreement.Equals(kem.ExportPublicKey(), publicKem) ||
                !string.Equals(DeviceId, DeviceIdentity.Id(publicKey, publicKem), StringComparison.Ordinal))
                throw new InvalidDataException("The stored device ID and its identity key pairs do not match.");
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new InvalidDataException("Cannot open the protected ML-KEM identity for this Windows user.", ex);
        }

        if (MountPoint is null || AdditionalMountPoints is null || AdditionalMountPoints.Count > 25 ||
            MountPoint.Length == 0 && AdditionalMountPoints.Count > 0 ||
            !SetupComplete && MountPoint.Length != 0)
            throw new InvalidDataException("Invalid drive list.");
        var drives = new HashSet<string>(StringComparer.Ordinal);
        if (MountPoint.Length != 0)
        {
            MountPoint = NormalizeMountPoint(MountPoint);
            drives.Add(MountPoint);
        }
        for (var index = 0; index < AdditionalMountPoints.Count; index++)
        {
            var point = NormalizeMountPoint(AdditionalMountPoints[index]);
            if (!drives.Add(point))
                throw new InvalidDataException("Drive letters must be unique.");
            AdditionalMountPoints[index] = point;
        }
        if (DriveNames is null || DriveNames.Keys.Any(letter => !drives.Contains(letter)))
            throw new InvalidDataException("A drive name references an unknown drive.");
        if (ElevatedDriveGrants is null || ElevatedDriveGrants.Any(item => !drives.Contains(item.Key) || item.Value == Guid.Empty) ||
            ElevatedDriveGrants.Values.Distinct().Count() != ElevatedDriveGrants.Count)
            throw new InvalidDataException("Invalid or duplicated drive access grant.");
        foreach (var label in DriveNames.Values)
            ValidateDriveName(label);
        if (RequestTimeoutSeconds is < 5 or > 45)
            throw new InvalidDataException("RequestTimeoutSeconds must be between 5 and 45.");
        if (ManagementPort != 0 && ManagementPort is < 1024 or > 65535)
            throw new InvalidDataException("ManagementPort must be 0 or between 1024 and 65535.");
        if (requireEnrollment && !IsConfigured)
            throw new InvalidDataException("Add a server using its connection link before connecting.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pins = new Dictionary<(string, int), string>();
        foreach (var server in Servers)
        {
            if (server is null)
                throw new InvalidDataException("Invalid server entry.");
            MultiServerConnection.ValidateName(server.Name);
            ValidateHost(server.Host);
            if (server.Port is < 1 or > 65535)
                throw new InvalidDataException("Server ports must be between 1 and 65535.");
            if (server.ProtectedInviteCode is { Length: 0 or > 4096 })
                throw new InvalidDataException("Invalid protected invitation.");
            if (server.TrustedServerId is null)
                throw new InvalidDataException("Each server entry must contain its expected v6 fingerprint.");
            var letter = server.MountPoint is null ? MountPoint : NormalizeMountPoint(server.MountPoint);
            if (letter.Length != 0 && !drives.Contains(letter))
                throw new InvalidDataException("A server references an unknown drive.");
            server.MountPoint = letter == MountPoint ? null : letter;
            if (!names.Add(letter + server.Name) || !addresses.Add(letter + NormalizeHost(server.Host) + "\n" + server.Port))
                throw new InvalidDataException("Server folder names and host/port endpoints must be unique within a drive.");
            if (server.TrustedServerId is { } trusted)
            {
                ServerIdentityNaming.ValidateId(trusted);
                var address = (NormalizeHost(server.Host).ToUpperInvariant(), server.Port);
                if (pins.TryGetValue(address, out var known) && known != trusted)
                    throw new InvalidDataException("Conflicting trusted fingerprints for the same endpoint.");
                pins[address] = trusted;
            }
            if (server.ServerIdentityPublicKey is not null)
                DecodePublicKey(server.ServerIdentityPublicKey);
            if (server.ServerId is { } serverId)
            {
                try
                {
                    ServerIdentityNaming.FolderName(server.ServerName!, serverId);
                    if (server.ServerId != server.TrustedServerId || server.ServerIdentityPublicKey is null || server.ServerMlKemPublicKey is null ||
                        ServerIdentityNaming.Id(DecodePublicKey(server.ServerIdentityPublicKey),
                            Convert.FromBase64String(server.ServerMlKemPublicKey)) != serverId)
                        throw new InvalidDataException("The saved server identity does not match the trusted composite fingerprint.");
                }
                catch (ArgumentException ex) { throw new InvalidDataException("Invalid saved server identity metadata.", ex); }
            }
            else if (server.ServerName is not null || server.ServerIdentityPublicKey is not null || server.ServerMlKemPublicKey is not null)
                throw new InvalidDataException("Server name metadata requires a persistent server ID.");
        }
    }

    private ServerEndpoint UpsertServer(string host, int port, string? mountPoint)
    {
        if (parent is not null)
            throw new InvalidOperationException("Configure servers on the root settings.");
        ValidateHost(host);
        if (port is < 1 or > 65535)
            throw new ArgumentException("The server port must be between 1 and 65535.");
        host = NormalizeHost(host);
        var letter = mountPoint is null ? MountPoint : NormalizeMountPoint(mountPoint);
        if (letter.Length != 0 && !DriveSnapshot().Contains(letter))
            throw new ArgumentException("Select a configured drive.");
        var driveServers = ServerSnapshot(letter);
        var existing = driveServers.SingleOrDefault(item => item.Port == port && NormalizeHost(item.Host).Equals(host, StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
            return existing;
        var baseName = DefaultServerName(host);
        var chosen = baseName;
        for (var suffix = 2; driveServers.Any(item => item.Name.Equals(chosen, StringComparison.OrdinalIgnoreCase)); suffix++)
            chosen = baseName + "-" + suffix;
        var added = new ServerEndpoint { Name = chosen, Host = host, Port = port };
        added.MountPoint = letter == MountPoint ? null : letter;
        var known = Servers.Where(item => SameAddress(item, host, port))
            .OrderByDescending(item => item.TrustedServerId is not null).ThenByDescending(item => item.ServerId is not null)
            .FirstOrDefault();
        if (known is not null)
        {
            added.TrustedServerId = known.TrustedServerId;
            added.SetIdentity(known.ServerId, known.ServerName, known.ServerIdentityPublicKey, known.ServerMlKemPublicKey);
        }
        Servers.Add(added);
        return added;
    }

    public ClientSettings ForServer(ServerEndpoint server)
    {
        lock (persistenceGate)
        {
            if (parent is not null || !Servers.Contains(server))
                throw new ArgumentException("The server must belong to this client configuration.");
            return new()
            {
                parent = this,
                IdentityFormat = IdentityFormat,
                endpoint = server,
                VerificationToken = server.VerificationToken,
                DeviceId = DeviceId,
                DeviceName = DeviceName,
                PublicKey = PublicKey,
                ProtectedPrivateKey = ProtectedPrivateKey,
                MlKemPublicKey = MlKemPublicKey,
                ProtectedMlKemPrivateSeed = ProtectedMlKemPrivateSeed,
                MountPoint = server.MountPoint ?? MountPoint,
                RequestTimeoutSeconds = RequestTimeoutSeconds,
                SetupComplete = SetupComplete,
                ManagementPort = ManagementPort,
                SettingsPath = SettingsPath
            };
        }
    }

    private static string NormalizeHost(string host) => IPAddress.TryParse(host, out var address) ? address.ToString() : host;
    private static string DefaultServerName(string host)
    {
        var name = new string(host.Select(character => Path.GetInvalidFileNameChars().Contains(character) ? '-' : character).ToArray()).TrimEnd('.', ' ');
        try
        {
            return MultiServerConnection.ValidateName(name);
        }
        catch (ArgumentException) { return "Server"; }
    }
    public static string NormalizeMountPoint(string mount)
    {
        if (string.IsNullOrWhiteSpace(mount))
            throw new ArgumentException("Specify a drive letter, such as N:\\.");
        if (mount.Length == 2)
            mount += "\\";
        if (mount.Length != 3 || !char.IsAsciiLetter(mount[0]) || mount[1..] != ":\\")
            throw new ArgumentException("MountPoint must be a drive letter, such as N:\\.");
        return char.ToUpperInvariant(mount[0]) + mount[1..];
    }

    public static void ValidateDriveName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 32 || name != name.Trim() ||
            name.Any(char.IsControl) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("Use a drive name of 1–32 characters without surrounding spaces, control characters, or Windows filename separators and reserved characters.");
    }

    private static void ValidateName(string name, string label)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 100 || name != name.Trim() || name.Any(char.IsControl))
            throw new InvalidDataException($"Invalid {label}; use 1–100 characters without leading/trailing whitespace or control characters.");
    }

    private static byte[] DecodePublicKey(string key)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(key) || key.Length > 256)
                throw new FormatException();
            var bytes = Convert.FromBase64String(key);
            using var imported = KeyAgreement.ImportPublic(bytes);
            return imported.ExportSubjectPublicKeyInfo();
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            throw new InvalidDataException("The enrollment must contain a valid P-256 public key.", ex);
        }
    }

    private static void ValidateHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 ||
            (!IPAddress.TryParse(host, out _) && Uri.CheckHostName(host) != UriHostNameType.Dns))
            throw new InvalidDataException("The server address must be a LAN hostname or IP address without a URL scheme, path, or port.");
    }
    internal void RememberServerIdentity(string? serverId, string? name, byte[]? publicEc, byte[]? publicKem)
    {
        if (serverId is null || name is null || publicEc is null || publicKem is null ||
            ServerIdentityNaming.Id(publicEc, publicKem) != serverId || serverId != TrustedServerId)
            throw new ServerIdentityMismatchException();
        ServerIdentityNaming.ValidateName(name);
        var ec = Convert.ToBase64String(publicEc);
        var kem = Convert.ToBase64String(publicKem);
        var owner = parent ?? this;
        lock (owner.persistenceGate)
        {
            var target = endpoint;
            if (target is null || !owner.Servers.Contains(target))
                throw new RemoteException("Disconnected");
            if (!IsVerificationCurrent)
                throw new RemoteException("Disconnected");
            var peers = owner.Servers.Where(peer => SameAddress(peer, target.Host, target.Port) ||
                peer.ServerId == serverId && peer.TrustedServerId == serverId &&
                peer.ServerIdentityPublicKey == ec && peer.ServerMlKemPublicKey == kem).ToArray();
            if (target.TrustedServerId != serverId || peers.Any(peer => peer.TrustedServerId != serverId ||
                peer.ServerIdentityPublicKey is not null && peer.ServerIdentityPublicKey != ec ||
                peer.ServerMlKemPublicKey is not null && peer.ServerMlKemPublicKey != kem))
                throw new ServerIdentityMismatchException();

            var next = new ServerEndpoint.IdentityState(serverId, serverId, name, ec, kem);
            var changed = peers.Where(peer => peer.SavedIdentity != next).Select(peer => (Peer: peer, Previous: peer.SavedIdentity)).ToArray();
            if (changed.Length == 0)
                return;
            foreach (var item in changed)
                item.Peer.SetSavedIdentity(next);
            try { owner.PersistChange(); }
            catch
            {
                foreach (var item in changed)
                    item.Peer.SetSavedIdentity(item.Previous);
                throw;
            }
        }
    }
}
