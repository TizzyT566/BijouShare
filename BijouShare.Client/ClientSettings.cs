using System.Net;
using System.Security.Cryptography;
using System.Text;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed class ServerEndpoint
{
    private readonly object metadataGate = new();
    private string? cachedName, cachedId, cachedFolder, cachedPublicKey, cachedFingerprint;
    public string Name { get; set; } = "Server";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 7443;
    public string ServerPublicKey { get; set; } = "";
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
                if (ServerId is null || ServerName is null)
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
    [System.Text.Json.Serialization.JsonIgnore]
    public string? ServerKeyFingerprint
    {
        get
        {
            lock (metadataGate)
            {
                if (ServerIdentityPublicKey is null)
                    return null;
                if (cachedPublicKey != ServerIdentityPublicKey)
                {
                    cachedFingerprint = ServerIdentityNaming.KeyFingerprint(Convert.FromBase64String(ServerIdentityPublicKey));
                    cachedPublicKey = ServerIdentityPublicKey;
                }
                return cachedFingerprint;
            }
        }
    }
    internal void SetIdentity(string? id, string? name, string? publicKey)
    {
        lock (metadataGate)
        {
            ServerId = id;
            ServerName = name;
            ServerIdentityPublicKey = publicKey;
            cachedName = cachedId = cachedFolder = cachedPublicKey = cachedFingerprint = null;
        }
    }
}

public sealed class ClientSettings
{
    private readonly object persistenceGate = new();
    private ClientSettings? parent;
    private ServerEndpoint? endpoint;
    public string DeviceId { get; set; } = Guid.NewGuid().ToString();
    public string DeviceName { get; set; } = Environment.MachineName;
    public bool SetupComplete { get; set; } = true;
    public int ManagementPort { get; set; } = 5081;
    public byte[] ProtectedPrivateKey { get; set; } = [];
    public string PublicKey { get; set; } = "";
    public string ServerPublicKey { get; set; } = "";
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
    public string Host { get; set; } = "";
    public int Port { get; set; } = 7443;
    public List<ServerEndpoint> Servers { get; set; } = [];
    public string MountPoint { get; set; } = "N:\\";
    public int RequestTimeoutSeconds { get; set; } = 30;
    public bool IsEnrolled => !string.IsNullOrWhiteSpace(ServerPublicKey) && !string.IsNullOrWhiteSpace(Host);
    public bool IsConfigured => Servers is { Count: > 0 } || !string.IsNullOrWhiteSpace(Host);
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
            return new()
            {
                DeviceName = name,
                ProtectedPrivateKey = PrivateStorage.Protect(privateKey),
                PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())
            };
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    internal void AttachPath(string path) => SettingsPath = Path.GetFullPath(path);

    public ServerEndpoint[] ServerSnapshot()
    {
        lock (persistenceGate)
            return Servers.ToArray();
    }

    public ServerEndpoint AddServer(string host, int port, string? inviteCode)
    {
        if (parent is not null)
            throw new InvalidOperationException("Configure servers on the root settings.");
        WadUri.ValidateInviteCode(inviteCode);
        lock (persistenceGate)
        {
            var previous = Servers.ToArray();
            var server = UpsertServer(host, port);
            var oldInvite = server.ProtectedInviteCode;
            try
            {
                if (inviteCode is not null)
                {
                    var bytes = Encoding.UTF8.GetBytes(inviteCode);
                    try
                    {
                        server.ProtectedInviteCode = PrivateStorage.Protect(bytes);
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
                else
                    server.ProtectedInviteCode = null;
                if (SetupComplete && SettingsPath is not null)
                    Save(SettingsPath);
                else
                    Validate();
                return server;
            }
            catch
            {
                server.ProtectedInviteCode = oldInvite;
                Servers.Clear();
                Servers.AddRange(previous);
                SynchronizeLegacyEndpoint();
                throw;
            }
        }
    }

    public bool RemoveServer(string host, int port)
    {
        lock (persistenceGate)
        {
            var index = Servers.FindIndex(server => server.Port == port && NormalizeHost(server.Host).Equals(NormalizeHost(host), StringComparison.OrdinalIgnoreCase));
            if (index < 0)
                return false;
            var removed = Servers[index];
            Servers.RemoveAt(index);
            SynchronizeLegacyEndpoint();
            try
            {
                if (SetupComplete && SettingsPath is not null)
                    Save(SettingsPath);
                return true;
            }
            catch
            {
                Servers.Insert(index, removed);
                SynchronizeLegacyEndpoint();
                throw;
            }
        }
    }

    public void UpdateDevice(string name, string mount)
    {
        ValidateName(name, "device name");
        mount = NormalizeMountPoint(mount);
        lock (persistenceGate)
        {
            var previous = (DeviceName, MountPoint, SetupComplete);
            DeviceName = name;
            MountPoint = mount;
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
                (DeviceName, MountPoint, SetupComplete) = previous;
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
            var bytes = PrivateStorage.Unprotect(endpoint.ProtectedInviteCode);
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
        var file = new FileInfo(path);
        if (file.Length > 64 * 1024)
            throw new InvalidDataException("The client settings file is too large.");
        var settings = Wire.Decode<ClientSettings>(File.ReadAllBytes(path));
        var migrate = settings.Servers is { Count: 0 } && !string.IsNullOrEmpty(settings.Host);
        settings.Validate();
        settings.SettingsPath = Path.GetFullPath(path);
        if (migrate)
            settings.Save(path);
        return settings;
    }
    public void Save(string path)
    {
        if (parent is not null)
            throw new InvalidOperationException("Save the root client configuration, not a per-server view.");
        lock (persistenceGate)
        {
            Validate();
            SynchronizeLegacyEndpoint();
            var bytes = Wire.Encode(this);
            if (bytes.Length > 64 * 1024)
                throw new InvalidDataException("The client settings exceed 64 KB. Reduce server entries or folder-name lengths.");
            PrivateStorage.AtomicWrite(path, bytes);
            SettingsPath = Path.GetFullPath(path);
        }
    }

    public void Validate(bool requireEnrollment = false)
    {
        if (Servers is null || Servers.Count > 64 || Servers.Any(server => server is null))
            throw new InvalidDataException("Configure at most 64 non-null servers.");
        if (parent is null && Servers.Count == 0 && !string.IsNullOrEmpty(Host))
            Servers.Add(new()
            {
                Name = DefaultServerName(Host),
                Host = Host,
                Port = Port,
                ServerPublicKey = ServerPublicKey
            });
        if (parent is null)
            SynchronizeLegacyEndpoint();
        if (!Guid.TryParse(DeviceId, out var id) || id == Guid.Empty)
            throw new InvalidDataException("Invalid client device ID.");
        ValidateName(DeviceName, "device name");
        if (ProtectedPrivateKey is not { Length: > 0 and <= 4096 })
            throw new InvalidDataException("Missing or invalid protected client identity.");
        var publicKey = DecodePublicKey(PublicKey);
        byte[] privateKey;
        try
        {
            privateKey = PrivateStorage.Unprotect(ProtectedPrivateKey);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException("The client identity cannot be decrypted. Keep its data on the Windows machine where it was created, or create and enroll a new identity.", ex);
        }
        try
        {
            using var key = KeyAgreement.ImportPrivate(privateKey);
            if (!KeyAgreement.Equals(key.ExportSubjectPublicKeyInfo(), publicKey))
                throw new InvalidDataException("The client public and private keys do not match.");
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }

        MountPoint = NormalizeMountPoint(MountPoint);
        if (RequestTimeoutSeconds is < 5 or > 45)
            throw new InvalidDataException("RequestTimeoutSeconds must be between 5 and 45.");
        if (ManagementPort is < 1024 or > 65535)
            throw new InvalidDataException("ManagementPort must be between 1024 and 65535.");
        if (Port is < 1 or > 65535)
            throw new InvalidDataException("The server port must be between 1 and 65535.");
        if (requireEnrollment || !string.IsNullOrEmpty(ServerPublicKey) || !string.IsNullOrEmpty(Host))
        {
            if (!IsConfigured)
                throw new InvalidDataException("Configure the server address with --server before connecting.");
            ValidateHost(Host);
            if (!string.IsNullOrEmpty(ServerPublicKey))
                DecodePublicKey(ServerPublicKey);
        }
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
            if (!names.Add(server.Name) || !addresses.Add(NormalizeHost(server.Host) + "\n" + server.Port))
                throw new InvalidDataException("Server folder names and host/port endpoints must be unique.");
            if (!string.IsNullOrEmpty(server.ServerPublicKey))
                DecodePublicKey(server.ServerPublicKey);
            if (server.ServerId is { } serverId)
            {
                if (string.IsNullOrEmpty(server.ServerPublicKey))
                    throw new InvalidDataException("Server identity metadata requires an approved pinned server key.");
                try
                {
                    ServerIdentityNaming.FolderName(server.ServerName!, serverId);
                    if (server.ServerIdentityPublicKey is null || ServerIdentityNaming.Id(server.ServerName!, DecodePublicKey(server.ServerIdentityPublicKey)) != serverId)
                        throw new InvalidDataException("The saved server ID does not match its name and global public key.");
                }
                catch (ArgumentException ex) { throw new InvalidDataException("Invalid saved server identity metadata.", ex); }
            }
            else if (server.ServerName is not null || server.ServerIdentityPublicKey is not null)
                throw new InvalidDataException("Server name metadata requires a persistent server ID.");
        }
    }

    public ServerEndpoint UpsertServer(string host, int port, string? name = null)
    {
        if (parent is not null)
            throw new InvalidOperationException("Configure servers on the root settings.");
        ValidateHost(host);
        if (port is < 1 or > 65535)
            throw new ArgumentException("The server port must be between 1 and 65535.");
        host = NormalizeHost(host);
        var existing = Servers.SingleOrDefault(item => item.Port == port && NormalizeHost(item.Host).Equals(host, StringComparison.OrdinalIgnoreCase));
        if (name is not null)
            MultiServerConnection.ValidateName(name);
        if (name is null && existing is not null)
            return existing;
        var chosen = name ?? DefaultServerName(host);
        if (name is null)
        {
            var suffix = 2;
            while (Servers.Any(item => item != existing && item.Name.Equals(chosen, StringComparison.OrdinalIgnoreCase)))
                chosen = DefaultServerName(host) + "-" + suffix++;
        }
        else if (Servers.Any(item => item != existing && item.Name.Equals(chosen, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("That server folder name is already used. Choose a different --server-name.");
        if (existing is not null)
        {
            existing.Name = chosen;
            return existing;
        }
        var added = new ServerEndpoint { Name = chosen, Host = host, Port = port };
        Servers.Add(added);
        SynchronizeLegacyEndpoint();
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
                endpoint = server,
                DeviceId = DeviceId,
                DeviceName = DeviceName,
                PublicKey = PublicKey,
                ProtectedPrivateKey = ProtectedPrivateKey,
                Host = server.Host,
                Port = server.Port,
                ServerPublicKey = server.ServerPublicKey,
                ServerId = server.ServerId,
                ServerName = server.ServerName,
                ServerIdentityPublicKey = server.ServerIdentityPublicKey,
                MountPoint = MountPoint,
                RequestTimeoutSeconds = RequestTimeoutSeconds,
                SetupComplete = SetupComplete,
                ManagementPort = ManagementPort,
                SettingsPath = SettingsPath
            };
        }
    }

    public void ResetServerTrust(ServerEndpoint server)
    {
        lock (persistenceGate)
        {
            if (!Servers.Contains(server))
                throw new ArgumentException("Unknown server.");
            server.ServerPublicKey = "";
            server.SetIdentity(null, null, null);
            SynchronizeLegacyEndpoint();
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
    private void SynchronizeLegacyEndpoint()
    {
        if (Servers.Count == 0)
        {
            Host = "";
            Port = 7443;
            ServerPublicKey = "";
            ServerId = ServerName = ServerIdentityPublicKey = null;
            return;
        }
        Host = Servers[0].Host;
        Port = Servers[0].Port;
        ServerPublicKey = Servers[0].ServerPublicKey;
        ServerId = Servers[0].ServerId;
        ServerName = Servers[0].ServerName;
        ServerIdentityPublicKey = Servers[0].ServerIdentityPublicKey;
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
    public void Enroll(EnrollmentBundle bundle)
    {
        if (!Guid.TryParse(bundle.DeviceId, out var id) || !Guid.TryParse(DeviceId, out var ownId) || id != ownId)
            throw new ArgumentException("Enrollment belongs to another device.");
        if (bundle.Port is < 1 or > 65535)
            throw new ArgumentException("The server port must be between 1 and 65535.");
        ValidateHost(bundle.Host);
        DecodePublicKey(bundle.ServerPublicKey);
        var server = UpsertServer(bundle.Host, bundle.Port);
        server.ServerPublicKey = bundle.ServerPublicKey;
        SynchronizeLegacyEndpoint();
    }
    public bool TrustApprovedServer(byte[] publicKey, string? serverId = null, string? serverName = null, byte[]? serverIdentityPublicKey = null)
    {
        using var imported = KeyAgreement.ImportPublic(publicKey);
        var canonical = imported.ExportSubjectPublicKeyInfo();
        var owner = parent ?? this;
        lock (owner.persistenceGate)
        {
            if (endpoint is not null && !owner.Servers.Contains(endpoint))
                throw new RemoteException("Disconnected");
            var target = endpoint ?? (Servers.Count == 1 && Servers[0].Port == Port &&
                Servers[0].Host.Equals(Host, StringComparison.OrdinalIgnoreCase) ? Servers[0] : null);
            var current = target?.ServerPublicKey ?? ServerPublicKey;
            var currentId = target?.ServerId ?? ServerId;
            var currentGlobalKey = target?.ServerIdentityPublicKey ?? ServerIdentityPublicKey;
            string? globalKey = null;
            if (serverId is { } offeredId)
            {
                ServerIdentityNaming.ValidateId(offeredId);
                ServerIdentityNaming.ValidateName(serverName);
                if (serverIdentityPublicKey is null || ServerIdentityNaming.Id(serverName!, serverIdentityPublicKey) != offeredId)
                    throw new CryptographicException("The server ID does not match its name and global public key.");
                var canonicalGlobal = DecodePublicKey(Convert.ToBase64String(serverIdentityPublicKey));
                globalKey = Convert.ToBase64String(canonicalGlobal);
                if (currentGlobalKey is not null && !KeyAgreement.Equals(DecodePublicKey(currentGlobalKey), canonicalGlobal))
                    throw new ServerIdentityMismatchException();
            }
            else if (serverName is not null || serverIdentityPublicKey is not null)
                throw new CryptographicException("Incomplete server identity metadata.");
            if (!string.IsNullOrEmpty(current))
            {
                if (!KeyAgreement.Equals(DecodePublicKey(current), canonical))
                    throw new ServerIdentityMismatchException();
            }
            var encoded = Convert.ToBase64String(canonical);
            var oldName = target?.ServerName ?? ServerName;
            var changed = string.IsNullOrEmpty(current) || serverId is not null && (currentId != serverId || oldName != serverName || currentGlobalKey != globalKey);
            if (!changed)
            {
                ServerPublicKey = current;
                ServerId = currentId;
                ServerName = oldName;
                ServerIdentityPublicKey = currentGlobalKey;
                return false;
            }
            ServerPublicKey = encoded;
            if (serverId is not null)
            {
                ServerId = serverId;
                ServerName = serverName;
                ServerIdentityPublicKey = globalKey;
            }
            if (target is not null)
            {
                target.ServerPublicKey = encoded;
                if (serverId is not null)
                    target.SetIdentity(serverId, serverName, globalKey);
            }
            try
            {
                if (owner.SettingsPath is not null)
                    owner.Save(owner.SettingsPath);
            }
            catch
            {
                ServerPublicKey = current;
                ServerId = currentId;
                ServerName = oldName;
                ServerIdentityPublicKey = currentGlobalKey;
                if (target is not null)
                {
                    target.ServerPublicKey = current;
                    target.SetIdentity(currentId, oldName, currentGlobalKey);
                }
                owner.SynchronizeLegacyEndpoint();
                throw;
            }
            return true;
        }
    }
}
