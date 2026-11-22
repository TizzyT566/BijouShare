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

internal sealed class MountLogonAccess
{
    private readonly SecurityIdentifier owner;
    private readonly long ownerLogon;
    private readonly long? administratorLogon;
    private bool elevatedAllowed;

    public MountLogonAccess()
    {
        using var identity = WindowsIdentity.GetCurrent();
        owner = identity.User ?? throw new UnauthorizedAccessException("The mount requires a Windows user SID.");
        ownerLogon = ElevatedDriveAlias.AuthenticationId(identity.AccessToken);
        administratorLogon = ElevatedDriveAlias.LinkedAdministratorLogon(identity);
    }

    public bool Allows(WindowsIdentity? caller)
    {
        if (caller?.User != owner) return false;
        return AllowsLogon(ElevatedDriveAlias.AuthenticationId(caller.AccessToken));
    }

    internal bool AllowsLogon(long logon) =>
        logon == ownerLogon || (Volatile.Read(ref elevatedAllowed) && administratorLogon == logon);

    public void SetElevatedAllowed(bool allowed)
    {
        if (allowed && !administratorLogon.HasValue)
            throw new UnauthorizedAccessException("This Windows sign-in has no linked administrator logon for the drive.");
        Volatile.Write(ref elevatedAllowed, allowed);
    }
}
