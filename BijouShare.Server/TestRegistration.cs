using BijouShare.Shared;

namespace BijouShare.Server;

internal static class TestRegistration
{
    public static Guid RecordId(string digest) => Guid.ParseExact(digest[..32], "N");

    public static EnrollmentRequest Create(string name, string ecdhPublicKey, HybridKem? identityKem = null)
    {
        using var temporary = identityKem is null ? HybridKem.Generate() : null;
        var kemPublic = (identityKem ?? temporary!).ExportPublicKey();
        var digest = DeviceIdentity.Id(Convert.FromBase64String(ecdhPublicKey), kemPublic);
        return new EnrollmentRequest(digest, name, ecdhPublicKey, Convert.ToBase64String(kemPublic));
    }
}
