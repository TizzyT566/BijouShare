using System.Security.Cryptography;

namespace BijouShare.Client;

internal static class UserSecrets
{
    // Distinguish profile secrets from the old machine-wide DPAPI format.
    private static readonly byte[] Entropy = "BijouShare.Client.UserProfile.v1"u8.ToArray();

    public static byte[] Protect(byte[] bytes) => ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser);
    public static byte[] Unprotect(byte[] bytes) => ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser);
}
