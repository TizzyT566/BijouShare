using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace BijouShare.Client;

internal sealed class MountedDriveLabel : IDisposable
{
    private readonly SafeFileHandle root;
    internal SafeFileHandle RootHandle => root;
    private readonly string mountPoint;
    private string synchronized;
    private string? lastError;

    public MountedDriveLabel(string mountPoint, string initialName, DriveOperations operations, string? mountedRoot = null)
    {
        this.mountPoint = mountPoint;
        synchronized = initialName;
        // Keep the directory handle tied to this mount, even if Windows later reuses its letter.
        const uint writeData = 2, readAttributes = 0x80, openExisting = 3, backupSemantics = 0x02000000, randomAccess = 0x10000000;
        operations.ExpectLabelRootOpen();
        bool observed;
        try { root = CreateFileW(mountedRoot ?? mountPoint, writeData | readAttributes, FileShare.ReadWrite | FileShare.Delete, 0, openExisting, backupSemantics | randomAccess, 0); }
        finally { observed = operations.FinishLabelRootOpen(); }
        try
        {
            if (root.IsInvalid) throw new Win32Exception(Marshal.GetLastPInvokeError());
            if (!observed) throw new IOException($"Drive {mountPoint} no longer points to this BijouShare mount.");
        }
        catch { root.Dispose(); throw; }
    }

    public void Synchronize(ClientSettings settings, ILogger logger)
    {
        try
        {
            var configured = settings.GetDriveName(mountPoint);
            var mounted = Read();
            // Dokan processes Explorer's rename inside the driver and overrides GetVolumeInformation.
            // Prefer a newer configuration edit if both sides changed since the previous observation.
            if (mounted != configured && configured == synchronized)
            {
                try
                {
                    if (!settings.TryRenameDrive(mountPoint, configured, mounted)) return;
                    configured = mounted;
                }
                catch (ArgumentException) { /* Restore the required valid label if Explorer cleared it. */ }
            }
            if (configured != mounted)
                Write(configured);
            if (synchronized != configured || mounted != configured)
                SHChangeNotify(0x2000 /* SHCNE_UPDATEITEM */, 5 /* SHCNF_PATHW */, mountPoint, 0);
            synchronized = configured;
            lastError = null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception)
        {
            // The existing volume-health monitor owns remount decisions, particularly after sleep.
            if (error.Message != lastError)
                logger.LogWarning("Could not synchronize the name of {Mount}: {Reason}", mountPoint, error.Message);
            lastError = error.Message;
        }
    }

    private string Read()
    {
        var name = new StringBuilder(261);
        if (!GetVolumeInformationByHandleW(root, name, name.Capacity, out _, out _, out _, null, 0))
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        return name.ToString();
    }

    private void Write(string value)
    {
        // FILE_FS_LABEL_INFORMATION begins with a byte count followed by UTF-16 text.
        var length = Encoding.Unicode.GetByteCount(value);
        var buffer = new byte[Math.Max(8, sizeof(int) + length)];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, length);
        Encoding.Unicode.GetBytes(value, buffer.AsSpan(sizeof(int)));
        int status = NtSetVolumeInformationFile(root, out _, buffer, buffer.Length, 2 /* FileFsLabelInformation */);
        if (status < 0) throw new Win32Exception((int)RtlNtStatusToDosError(status));
    }

    public void Dispose() => root.Dispose();

    internal static void NotifyDriveLetter(string path, bool added) =>
        SHChangeNotify(added ? 0x100 /* SHCNE_DRIVEADD */ : 0x80 /* SHCNE_DRIVEREMOVED */, 5 /* SHCNF_PATHW */, path, 0);

    [StructLayout(LayoutKind.Sequential)] private struct IoStatusBlock { public nint Status; public nuint Information; }
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share, nint security, uint disposition, uint flags, nint template);
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder name, int length,
        out uint serial, out uint maximumComponent, out uint features, StringBuilder? fileSystem, int fileSystemLength);
    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetVolumeInformationFile(SafeFileHandle handle, out IoStatusBlock status, byte[] data, int length, int informationClass);
    [DllImport("ntdll.dll", ExactSpelling = true)] private static extern uint RtlNtStatusToDosError(int status);
    [DllImport("shell32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern void SHChangeNotify(int change, uint flags, string path, nint reserved);
}
