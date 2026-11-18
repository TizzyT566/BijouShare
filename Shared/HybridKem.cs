using System.Security.Cryptography;

namespace BijouShare.Shared;

/// <summary>ML-KEM-768 key generation, encapsulation and decapsulation through Windows CNG.</summary>
public sealed class HybridKem : IDisposable
{
    public const int PublicKeySize = 1184;
    public const int CiphertextSize = 1088;
    public const int SharedSecretSize = 32;
    public const string AlgorithmName = "ML-KEM-768";
    public static string ProviderName => "Windows CNG";
    public static bool IsSupported => OperatingSystem.IsWindows() && MLKem.IsSupported;

    private readonly MLKem key;
    private HybridKem(MLKem key) => this.key = key;

    public static HybridKem Generate()
    {
        EnsureSupported();
        return new(MLKem.GenerateKey(MLKemAlgorithm.MLKem768));
    }

    public byte[] ExportPrivateSeed() => key.ExportPrivateSeed();

    public static HybridKem ImportPrivateSeed(byte[] seed)
    {
        EnsureSupported();
        if (seed is not { Length: 64 })
            throw new CryptographicException("Expected a 64-byte ML-KEM-768 private seed.");
        return new(MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seed));
    }

    public byte[] ExportPublicKey()
    {
        var publicKey = key.ExportEncapsulationKey();
        if (publicKey.Length != PublicKeySize)
            throw new CryptographicException("The native provider returned an invalid ML-KEM-768 public key.");
        return publicKey;
    }

    public static (byte[] Ciphertext, byte[] Secret) Encapsulate(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (publicKey.Length != PublicKeySize)
            throw new CryptographicException("Invalid ML-KEM-768 public key length.");
        EnsureSupported();
        // Import and encapsulation enforce the native provider's ML-KEM modulus/canonical-key checks.
        using var recipient = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, publicKey);
        var ciphertext = new byte[CiphertextSize];
        var secret = new byte[SharedSecretSize];
        try
        {
            recipient.Encapsulate(ciphertext, secret);
            return (ciphertext, secret);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            throw;
        }
    }

    public byte[] Decapsulate(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length != CiphertextSize)
            throw new CryptographicException("Invalid ML-KEM-768 ciphertext length.");
        var secret = new byte[SharedSecretSize];
        try
        {
            // ML-KEM deliberately maps invalid ciphertexts to an unrelated secret (implicit rejection).
            // The authenticated handshake's proof/AEAD confirmation must reject the resulting mismatch.
            key.Decapsulate(ciphertext, secret);
            return secret;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            throw;
        }
    }

    public static void EnsureSupported()
    {
        if (!IsSupported)
            throw new PlatformNotSupportedException("Native Windows ML-KEM support is required for the ECDH + ML-KEM-768 handshake. Install a Windows version that supports ML-KEM through CNG; no classical-only fallback is permitted.");
    }

    public void Dispose() => key.Dispose();
}
