using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace BijouShare.Shared;

public static class WindowsPaths
{
    // Expand 8.3 aliases before confinement/protected-directory comparisons, including for new files.
    public static string Canonical(string path)
    {
        var full = Path.GetFullPath(path);
        var missing = new Stack<string>();
        var existing = full;
        while (!TryGetAttributes(existing, out _))
        {
            var parent = Path.GetDirectoryName(existing);
            if (string.IsNullOrEmpty(parent))
                throw new DirectoryNotFoundException();
            missing.Push(Path.GetFileName(existing));
            existing = parent;
        }
        if ((File.GetAttributes(existing) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse points are not exported.");
        var buffer = new StringBuilder(260);
        var native = existing.StartsWith(@"\\?\", StringComparison.Ordinal) ? existing : @"\\?\" + existing;
        var size = GetLongPathName(native, buffer, (uint)buffer.Capacity);
        if (size >= buffer.Capacity)
        {
            buffer.EnsureCapacity(checked((int)size + 1));
            size = GetLongPathName(native, buffer, (uint)buffer.Capacity);
        }
        if (size == 0 || size >= buffer.Capacity)
            throw new IOException("Cannot canonicalize the Windows path.", new Win32Exception(Marshal.GetLastPInvokeError()));
        var result = buffer.ToString();
        if (result.StartsWith(@"\\?\", StringComparison.Ordinal))
            result = result[4..];
        while (missing.TryPop(out var part))
            result = Path.Combine(result, part);
        return result;
    }

    public static bool TryGetAttributes(string path, out FileAttributes attributes)
    {
        try
        {
            // File.Exists follows links and hides access errors. GetAttributes also identifies dangling links.
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            attributes = default;
            return false;
        }
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetLongPathNameW")]
    private static extern uint GetLongPathName(string shortPath, StringBuilder longPath, uint size);
}
