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
        return local.DeriveRawSecretAgreement(other.PublicKey);
    }

    public static byte[] Transcript(ClientHello client, ServerHello server, ClientKeyExchange exchange) =>
        SHA3_256.HashData(Wire.Encode(new { protocol = Wire.ProtocolName, client, server, exchange }));

    public static byte[] SessionSecret(byte[] staticEc, byte[] ephemeralEc, byte[] clientKem, byte[] serverKem, byte[] ephemeralKem)
    {
        // Mix the independently generated KEM secrets in their fixed protocol order.
        // Both sides must know both static private keys on their side and the fresh session keys.
        Span<byte> hybridInputs = stackalloc byte[64];
        Span<byte> ecInputs = stackalloc byte[64];
        Span<byte> kemInputs = stackalloc byte[96];
        try
        {
            CopySecret(staticEc, ecInputs[..32]);
            CopySecret(ephemeralEc, ecInputs[32..]);
            CopySecret(clientKem, kemInputs[..32]);
            CopySecret(serverKem, kemInputs[32..64]);
            CopySecret(ephemeralKem, kemInputs[64..]);
            SHA3_256.HashData(ecInputs, hybridInputs[..32]);
            SHA3_256.HashData(kemInputs, hybridInputs[32..]);
            return SHA3_256.HashData(hybridInputs);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridInputs);
            CryptographicOperations.ZeroMemory(ecInputs);
            CryptographicOperations.ZeroMemory(kemInputs);
        }
    }

    private static void CopySecret(byte[] secret, Span<byte> destination)
    {
        if (secret is not { Length: 32 })
            throw new CryptographicException("Expected a 32-byte key agreement result.");
        secret.CopyTo(destination);
    }

    public static byte[] Proof(byte[] secret, byte[] transcript, string role) =>
        role switch
        {
            "server" => Derive(secret, transcript, "server proof"u8),
            "client" => Derive(secret, transcript, "client proof"u8),
            _ => throw new ArgumentException("Unknown key confirmation role.", nameof(role))
        };

    public static byte[] SessionMaterial(byte[] secret, byte[] transcript)
    {
        var result = new byte[72];
        Span<byte> nonces = stackalloc byte[32];
        Derive(secret, transcript, "client traffic key"u8, result.AsSpan(0, 32));
        Derive(secret, transcript, "server traffic key"u8, result.AsSpan(32, 32));
        Derive(secret, transcript, "nonce prefixes"u8, nonces);
        nonces[..8].CopyTo(result.AsSpan(64));
        CryptographicOperations.ZeroMemory(nonces);
        return result;
    }

    private static byte[] Derive(byte[] secret, byte[] transcript, ReadOnlySpan<byte> purpose)
    {
        var output = new byte[32];
        Derive(secret, transcript, purpose, output);
        return output;
    }

    private static void Derive(byte[] secret, byte[] transcript, ReadOnlySpan<byte> purpose, Span<byte> output)
    {
        if (secret is not { Length: 32 } || transcript is not { Length: 32 })
            throw new CryptographicException("Invalid v6 hybrid secret or transcript.");
        // SP 800-56C Rev. 2 one-step KDF, hash option, one 256-bit output block.
        ReadOnlySpan<byte> domain = "BijouShare-v6/key-schedule/"u8;
        Span<byte> input = stackalloc byte[4 + 32 + domain.Length + purpose.Length + 32];
        try
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(input, 1);
            secret.CopyTo(input[4..]);
            domain.CopyTo(input[36..]);
            purpose.CopyTo(input[(36 + domain.Length)..]);
            transcript.CopyTo(input[^32..]);
            SHA3_256.HashData(input, output);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }
    public static bool Equals(byte[] expected, byte[]? actual) =>
        actual is not null && CryptographicOperations.FixedTimeEquals(expected, actual);
}

// Own every managed copy of a handshake secret until authentication succeeds or aborts.
internal sealed class HandshakeSecrets : IDisposable
{
    private readonly List<byte[]> secrets = [];
    public byte[] Keep(byte[] secret)
    {
        secrets.Add(secret);
        return secret;
    }
    public void Dispose()
    {
        foreach (var secret in secrets)
            CryptographicOperations.ZeroMemory(secret);
        secrets.Clear();
    }
}
