using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

// Preferences in client.json alone cannot authorize a privileged drive mapping.
// The limited token may delete its own marker, including while the service is offline.
internal static class ElevatedDriveConsent
{
    private const string Store = @"SOFTWARE\BijouShare.Client.ElevatedDriveAccess";
    private const string Active = "ActiveGrant";
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.AuthenticatedUserSid, null);

    internal static void Approve(SecurityIdentifier owner, char letter, Guid grant)
    {
        var scopeName = ScopeName(owner, letter, grant);
        using var impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
        using var identity = WindowsIdentity.GetCurrent();
        if (impersonation is not null || (!identity.IsSystem &&
            (identity.User != owner || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))))
            throw new UnauthorizedAccessException("Approve elevated access with the Windows account that owns this drive.");

        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var store = CreateProtected(machine, Store, Users, RegistryRights.ReadPermissions);
        using var scope = CreateProtected(store, scopeName, owner, RegistryRights.ReadKey);
        var previous = scope.GetValue(Active) as string;
        var name = grant.ToString("N");
        using var marker = CreateProtected(scope, name, owner, RegistryRights.ReadKey | RegistryRights.Delete);
        scope.SetValue(Active, name, RegistryValueKind.String);
        if (Guid.TryParseExact(previous, "N", out var old) && old != grant)
            Revoke(owner, letter, old);
    }

    internal static bool IsApproved(SecurityIdentifier owner, char letter, Guid grant)
    {
        var scopeName = ScopeName(owner, letter, grant);
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var store = OpenRead(machine, Store, RegistryRights.ReadPermissions);
        if (store is null) return false;
        VerifySecurity(store, Users, RegistryRights.ReadPermissions);
        // Opening the full path lets the owner check their grant without enumerating other users.
        using var scope = OpenRead(machine, Store + "\\" + scopeName, RegistryRights.ReadKey);
        if (scope is null) return false;
        VerifySecurity(scope, owner, RegistryRights.ReadKey);
        var name = grant.ToString("N");
        if (!string.Equals(scope.GetValue(Active) as string, name, StringComparison.Ordinal)) return false;
        using var marker = OpenRead(scope, name, RegistryRights.ReadPermissions);
        if (marker is null) return false;
        VerifySecurity(marker, owner, RegistryRights.ReadKey | RegistryRights.Delete);
        return true;
    }

    internal static void Revoke(SecurityIdentifier owner, char letter, Guid grant)
    {
        var scopeName = ScopeName(owner, letter, grant);
        // RegDeleteKeyEx checks DELETE on the leaf. The medium token never needs
        // KEY_WRITE on the parent and cannot recreate the marker it has removed.
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var scope = OpenRead(machine, Store + "\\" + scopeName, RegistryRights.ReadKey);
        if (scope is null) return;
        VerifySecurity(scope, owner, RegistryRights.ReadKey);
        var status = RegDeleteKeyExW(scope.Handle, grant.ToString("N"), 0x100, 0);
        if (status is not (0 or 2 or 3 or 1018)) // not found or already marked for deletion
            throw new IOException("Windows could not remove the drive's saved approval.", new Win32Exception(status));
    }

    private static string ScopeName(SecurityIdentifier owner, char letter, Guid grant)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (letter is < 'A' or > 'Z' || grant == Guid.Empty)
            throw new ArgumentException("An elevated-drive approval requires a drive letter and a grant ID.");
        return owner.Value + "." + letter;
    }

    private static RegistryKey? OpenRead(RegistryKey parent, string path, RegistryRights rights) =>
        parent.OpenSubKey(path, RegistryKeyPermissionCheck.ReadSubTree, rights);

    private static RegistryKey CreateProtected(RegistryKey parent, string name, SecurityIdentifier reader, RegistryRights rights)
    {
        var security = new RegistrySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(true, false);
        foreach (var trustee in new[] { Administrators, SystemSid })
            security.AddAccessRule(new RegistryAccessRule(trustee, RegistryRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(reader, rights, AccessControlType.Allow));
        var key = parent.CreateSubKey(name, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.None, security);
        try { VerifySecurity(key, reader, rights); return key; }
        catch { key.Dispose(); throw; }
    }

    private static void VerifySecurity(RegistryKey key, SecurityIdentifier reader, RegistryRights rights)
    {
        var security = key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>().ToArray();
        bool Grants(SecurityIdentifier sid, RegistryRights expected) => rules.Any(rule =>
            rule.IdentityReference.Equals(sid) && rule.AccessControlType == AccessControlType.Allow &&
            rule.RegistryRights == expected && rule.InheritanceFlags == InheritanceFlags.None &&
            rule.PropagationFlags == PropagationFlags.None && !rule.IsInherited);
        if ((owner != Administrators && owner != SystemSid) || !security.AreAccessRulesProtected ||
            rules.Length != 3 || !Grants(Administrators, RegistryRights.FullControl) ||
            !Grants(SystemSid, RegistryRights.FullControl) || !Grants(reader, rights))
            throw new UnauthorizedAccessException("Windows could not verify the saved drive approval's permissions.");
    }

    [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int RegDeleteKeyExW(SafeRegistryHandle key, string name, int view, int reserved);
}
