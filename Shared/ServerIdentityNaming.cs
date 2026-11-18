using System.Security.Cryptography;

namespace BijouShare.Shared;

public static class ServerIdentityNaming
{
    public const int MaxNameLength = 100;
    public static string ValidateName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxNameLength ||
            name.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))
            throw new ArgumentException("Server names must contain 1 to 100 ASCII letters, digits, or hyphens.");
        return name;
    }

    public static string ValidateId(string? serverId)
    {
        if (serverId is not { Length: 64 } || serverId.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new ArgumentException("The server ID must be a lowercase SHA-256 public-key hash.");
        return serverId;
    }
    public static string Id(string name, byte[] publicKey)
    {
        using var imported = KeyAgreement.ImportPublic(publicKey);
        var prefix = System.Text.Encoding.UTF8.GetBytes(ValidateName(name));
        return Convert.ToHexStringLower(SHA256.HashData([.. prefix, .. imported.ExportSubjectPublicKeyInfo()]));
    }
    public static string KeyFingerprint(byte[] publicKey)
    {
        using var imported = KeyAgreement.ImportPublic(publicKey);
        return Convert.ToHexStringLower(SHA256.HashData(imported.ExportSubjectPublicKeyInfo()));
    }
    public static string FolderName(string name, string serverId) => ValidateName(name) + "_" + ValidateId(serverId)[..16];
}
