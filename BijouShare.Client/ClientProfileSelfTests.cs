using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace BijouShare.Client;

internal static class ClientProfileSelfTests
{
    public static void Run(Action<bool, string> check)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BijouShare", "profile-tests-" + Guid.NewGuid().ToString("N"));
        var profile = Path.Combine(root, ".bijoushare");
        var settingsFile = new FileInfo(Path.Combine(profile, "client.json"));
        var keyDirectory = new DirectoryInfo(Path.Combine(profile, "web-keys"));
        var keyFile = new FileInfo(Path.Combine(keyDirectory.FullName, "test.xml"));
        check(UserProfileStorage.ProfileDirectory == Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".bijoushare"),
            "Runtime client data lives directly under the owner's home in .bijoushare");
        try
        {
            UserProfileStorage.RequireHomeDirectory(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BijouShare", "Client", owner.Value));
            throw new InvalidOperationException("A client profile in ProgramData was accepted.");
        }
        catch (ArgumentException) { check(true, "Client state accepts the personal profile and rejects ProgramData"); }

        bool IsPrivate(FileSystemSecurity security)
        {
            var allowed = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Where(rule => rule.AccessControlType == AccessControlType.Allow).ToArray();
            return allowed.Any(rule => rule.IdentityReference.Equals(owner) && rule.FileSystemRights.HasFlag(FileSystemRights.FullControl)) &&
                allowed.All(rule => rule.IdentityReference.Equals(owner) || rule.IdentityReference.Equals(system));
        }

        try
        {
            using (UserProfileStorage.Acquire(profile))
            {
                keyDirectory.Create();
                File.WriteAllBytes(settingsFile.FullName, BijouShare.Shared.Wire.Encode(ClientSettings.Create("Profile test")));
                File.WriteAllText(keyFile.FullName, "<fixture/>");
            }
            check(IsPrivate(new DirectoryInfo(profile).GetAccessControl()) &&
                IsPrivate(settingsFile.GetAccessControl()) && IsPrivate(keyFile.GetAccessControl()),
                "New profile files inherit access only for the Windows account and system");

            foreach (var file in new[] { settingsFile, keyFile })
            {
                var acl = file.GetAccessControl();
                acl.SetAccessRuleProtection(true, true);
                acl.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Read, AccessControlType.Allow));
                file.SetAccessControl(acl);
            }
            using (UserProfileStorage.Acquire(profile))
            {
                check(IsPrivate(settingsFile.GetAccessControl()) && IsPrivate(keyFile.GetAccessControl()),
                    "Startup removes explicit read grants from existing settings and nested web keys");
            }

            var outside = new FileInfo(Path.Combine(root, "outside.txt"));
            File.WriteAllText(outside.FullName, "fixture");
            var before = outside.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            var link = Path.Combine(profile, "outside-link.txt");
            if (!CreateHardLink(link, outside.FullName, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            try
            {
                var refused = false;
                try { using var unexpected = UserProfileStorage.Acquire(profile); }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidDataException)
                { refused = true; }
                check(refused && outside.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access) == before,
                    "Profile startup rejects a hard-linked file without changing the external file's permissions");
            }
            finally { File.Delete(link); }
            var old = "{}"u8.ToArray();
            File.WriteAllBytes(settingsFile.FullName, old);
            var broader = settingsFile.GetAccessControl();
            broader.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Read, AccessControlType.Allow));
            settingsFile.SetAccessControl(broader);
            var oldAcl = settingsFile.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            try
            {
                using var rejected = UserProfileStorage.Acquire(profile);
                throw new InvalidOperationException("Opened an obsolete profile.");
            }
            catch (InvalidDataException)
            {
                check(File.ReadAllBytes(settingsFile.FullName).SequenceEqual(old) && File.ReadAllText(keyFile.FullName) == "<fixture/>" &&
                    settingsFile.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access) == oldAcl,
                    "Startup refuses an obsolete schema before changing its settings, web keys or permissions");
            }
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string newName, string existingName, IntPtr securityAttributes);
}
