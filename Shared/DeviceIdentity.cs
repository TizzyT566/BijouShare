using System.Security.Cryptography;

namespace BijouShare.Shared;

/// <summary>Canonical fingerprint for a BijouShare client identity, independent of its display name.</summary>
public static class DeviceIdentity
{
    public static string Id(byte[] ecdhSpki, byte[] mlKemPublic)
    {
        using var ec = KeyAgreement.ImportPublic(ecdhSpki);
        var canonicalEc = ec.ExportSubjectPublicKeyInfo();
        if (!ecdhSpki.AsSpan().SequenceEqual(canonicalEc))
            throw new CryptographicException("Expected canonical P-256 SubjectPublicKeyInfo.");
        if (mlKemPublic is not { Length: HybridKem.PublicKeySize })
            throw new CryptographicException("Expected an ML-KEM-768 encapsulation key.");
        using var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, mlKemPublic);
        // P-256 canonical SPKI and ML-KEM-768 encapsulation keys have fixed encodings and sizes.
        return Convert.ToHexStringLower(SHA3_256.HashData([.. canonicalEc, .. mlKemPublic]));
    }
}
