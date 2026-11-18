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
            throw new ArgumentException("Enter the full 64-character lowercase hexadecimal server fingerprint.");
        return serverId;
    }
    public static string Id(byte[] ecdhSpki, byte[] mlKemPublic) => DeviceIdentity.Id(ecdhSpki, mlKemPublic);

    public static string FolderName(string name, string serverId) => ValidateName(name) + "_" + ValidateId(serverId)[..16];
}
