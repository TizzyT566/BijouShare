using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

internal sealed class PrivateMountDirectory : IDisposable
{
    internal const string ContainerName = "mounts";

    private readonly SafeFileHandle profile, container, slot;
    private readonly SecurityIdentifier user;
    public string MountPath { get; }

    private PrivateMountDirectory(string path, SafeFileHandle profile, SafeFileHandle container, SafeFileHandle slot,
        SecurityIdentifier user)
    {
        MountPath = path;
        this.profile = profile;
        this.container = container;
        this.slot = slot;
        this.user = user;
    }

    internal static PrivateMountDirectory Create(string profileDirectory, char driveLetter)
    {
        driveLetter = char.ToUpperInvariant(driveLetter);
        if (!char.IsAsciiLetterUpper(driveLetter) || !Path.IsPathFullyQualified(profileDirectory))
            throw new ArgumentException("A private profile path and a drive letter are required.");
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new UnauthorizedAccessException("The Windows user SID is unavailable.");
        var profilePath = Path.GetFullPath(profileDirectory);
        var containerPath = Path.Combine(profilePath, ContainerName);
        var prefix = driveLetter + "-";
        var path = Path.Combine(containerPath, prefix + Guid.NewGuid().ToString("N"));
        if (path.Length >= 260 || profilePath.StartsWith(@"\\", StringComparison.Ordinal) ||
            !new DriveInfo(Path.GetPathRoot(profilePath)!).DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("A Windows volume mount requires a local NTFS directory within the Dokan path limit.");

        var profile = UserProfileStorage.OpenPrivateDirectory(profilePath, user);
        SafeFileHandle? container = null;
        try
        {
            var acl = UserProfileStorage.PrivateDirectorySecurity(user);
            new DirectoryInfo(containerPath).Create(acl);
            container = UserProfileStorage.OpenPrivateDirectory(containerPath, user);
            // A crash may leave an empty physical slot. Ignore live mounts, unexpected
            // contents and unrecognized names. The kernel checks emptiness on deletion.
            foreach (var previous in Directory.EnumerateDirectories(containerPath, prefix + "*"))
            {
                var name = Path.GetFileName(previous);
                if (name.Length == prefix.Length + 32 && Guid.TryParseExact(name.AsSpan(prefix.Length), "N", out _))
                    TryRemoveEmptySlot(previous, user);
            }
            new DirectoryInfo(path).Create(acl);
            var slot = UserProfileStorage.OpenPrivateDirectory(path, user);
            return new(path, profile, container, slot, user);
        }
        catch
        {
            container?.Dispose();
            profile.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (profile.IsClosed)
            return;
        slot.Dispose();
        try { TryRemoveEmptySlot(MountPath, user); }
        finally
        {
            container.Dispose();
            profile.Dispose();
        }
    }

    private static void TryRemoveEmptySlot(string path, SecurityIdentifier user)
    {
        try
        {
            using var handle = UserProfileStorage.OpenPrivateDirectory(path, user, forDeletion: true);
            byte delete = 1;
            _ = SetFileInformationByHandle(handle, FileDispositionInfo, ref delete, sizeof(byte));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private const int FileDispositionInfo = 4;

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass,
        ref byte information, uint informationSize);
}
