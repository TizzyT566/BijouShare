using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace BijouShare.Shared;

public static class PrivateStorage
{
    public static string DefaultDirectory(string role) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BijouShare", role);

    public static void SecureDirectory(string directory, bool includeLocalService = false)
    {
        directory = Path.GetFullPath(directory);
        if (string.Equals(directory.TrimEnd(Path.DirectorySeparatorChar), Path.GetPathRoot(directory)?.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Private storage needs a dedicated directory, not a drive or share root.");
        var defaultRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BijouShare");
        if (string.Equals(Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar)), defaultRoot, StringComparison.OrdinalIgnoreCase))
            SecureOneDirectory(defaultRoot, includeLocalService: true);
        SecureOneDirectory(directory, includeLocalService);
    }

    private static void SecureOneDirectory(string directory, bool includeLocalService)
    {
        RejectReparseAncestors(directory);
        Directory.CreateDirectory(directory);
        RejectReparseAncestors(directory);
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User ?? throw new UnauthorizedAccessException("The current Windows identity has no user SID.");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var localService = new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null);
        var existingOwner = new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier));
        var elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        if (existingOwner is null || !existingOwner.Equals(currentUser) && !existingOwner.Equals(administrators) && !existingOwner.Equals(system) &&
            !(includeLocalService && existingOwner.Equals(localService)))
            throw new UnauthorizedAccessException("The data directory has an untrusted owner. Initialize it from an elevated PowerShell first.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] {
            system,
            administrators,
            currentUser }.Distinct())
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }
        if (includeLocalService)
            security.AddAccessRule(new FileSystemAccessRule(localService,
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        if (elevated)
            security.SetOwner(administrators);
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private static void RejectReparseAncestors(string directory)
    {
        for (var path = directory; !string.IsNullOrEmpty(path); path = Path.GetDirectoryName(path))
        {
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException("Private storage cannot use a reparse point, symbolic link, or junction.");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    public static byte[] Protect(byte[] bytes) => ProtectedData.Protect(bytes, null, DataProtectionScope.LocalMachine);
    public static byte[] Unprotect(byte[] bytes) => ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine);
    public static void AtomicWrite(string path, byte[] data)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                stream.Write(data);
                stream.Flush(true);
            }
            File.Move(temp, path, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}

public static class KeyAgreement
{
    public static ECDiffieHellman NewKey() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    public static ECDiffieHellman ImportPrivate(byte[] key)
    {
        var result = ECDiffieHellman.Create();
        try
        {
            result.ImportPkcs8PrivateKey(key, out var read);
            if (read != key.Length || result.KeySize != 256 ||
                result.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new CryptographicException("Expected a P-256 key.");
            return result;
        }
        catch { result.Dispose(); throw; }
    }
    public static ECDiffieHellman ImportPublic(byte[] key)
    {
        if (key.Length is < 64 or > 160)
            throw new CryptographicException("Invalid public key.");
        var result = ECDiffieHellman.Create();
        try
        {
            result.ImportSubjectPublicKeyInfo(key, out var read);
            if (read != key.Length || result.KeySize != 256 ||
                result.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new CryptographicException("Expected a P-256 public key.");
            return result;
        }
        catch { result.Dispose(); throw; }
    }
    public static byte[] Agree(ECDiffieHellman local, byte[] remote)
    {
        using var other = ImportPublic(remote);
        return local.DeriveKeyFromHash(other.PublicKey, HashAlgorithmName.SHA256);
    }
    public static byte[] Transcript(ClientHello client, ServerHello server, byte[] serverIdentity) =>
        SHA256.HashData(Wire.Encode(new
        {
            protocol = Wire.ProtocolName,
            client,
            server.Version,
            server.CryptoSuite,
            server.Nonce,
            server.EphemeralPublicKey,
            server.MlKemCiphertext,
            serverIdentity,
            server.IdentityPublicKey,
            server.PendingApproval,
            server.ServerId,
            server.ServerName,
            server.GlobalIdentityPublicKey,
            server.InviteEnrollment
        }));
    public static byte[] Proof(byte[] secret, byte[] transcript, string role) =>
        HMACSHA256.HashData(secret, (byte[])[.. transcript, .. System.Text.Encoding.UTF8.GetBytes(role)]);
    public static byte[] HybridProof(byte[] identitySecret, byte[] ephemeralSecret, byte[] kemSecret, byte[] transcript, string role)
    {
        if (role is not ("server" or "client" or "server-identity"))
            throw new ArgumentException("Unknown handshake proof role.", nameof(role));
        var key = HybridMaterial(identitySecret, ephemeralSecret, kemSecret, transcript, 32, "authentication " + role);
        try
        {
            return Proof(key, transcript, role);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    public static byte[] SessionMaterial(byte[] identitySecret, byte[] ephemeralSecret, byte[] kemSecret, byte[] transcript) =>
        HybridMaterial(identitySecret, ephemeralSecret, kemSecret, transcript, 72, "transport");

    private static byte[] HybridMaterial(byte[] identitySecret, byte[] ephemeralSecret, byte[] kemSecret, byte[] transcript,
        int outputLength, string purpose)
    {
        if (identitySecret is not { Length: 32 } || ephemeralSecret is not { Length: 32 } || kemSecret is not { Length: 32 } || transcript is not { Length: 32 })
            throw new ArgumentException("Hybrid key derivation requires three 32-byte secrets and a 32-byte transcript hash.");
        byte[] input = [.. identitySecret, .. ephemeralSecret, .. kemSecret];
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, input, outputLength,
                transcript, System.Text.Encoding.UTF8.GetBytes(Wire.ProtocolName + " " + Wire.CryptoSuite + " " + purpose));
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    public static bool Equals(byte[] expected, byte[]? actual) =>
        actual is not null && CryptographicOperations.FixedTimeEquals(expected, actual);
    public static string Fingerprint(string publicKey) => Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(publicKey)));
}
