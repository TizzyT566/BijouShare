using System.Security.AccessControl;
using System.Security.Principal;
using DokanNet.Native;

namespace BijouShare.Client;

internal static class UserDriveSecurity
{
    internal static SecurityIdentifier Owner { get; } = GetOwner();

    private static SecurityIdentifier GetOwner()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User ?? throw new UnauthorizedAccessException("The mount requires a Windows user SID.");
    }

    public static void Configure(DOKAN_OPTIONS options)
    {
        var descriptor = new RawSecurityDescriptor($"O:{Owner}G:{Owner}D:P(A;;GA;;;SY)(A;;GA;;;{Owner})");
        // Dokan marshals this field as an inline array of exactly 16 KiB.
        var buffer = new byte[16384];
        descriptor.GetBinaryForm(buffer, 0);
        options.VolumeSecurityDescriptor = buffer;
        options.VolumeSecurityDescriptorLength = descriptor.BinaryLength;
    }
}
