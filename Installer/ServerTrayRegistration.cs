using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Installer
{
    internal static class ServerTrayRegistration
    {
        internal static bool IsRegistered(string executable)
        {
            if (String.IsNullOrEmpty(executable)) return false;
            IntPtr window = IntPtr.Zero;
            while ((window = FindWindowExW(IntPtr.Zero, window, "STATIC", "BijouShare Server")) != IntPtr.Zero)
            {
                uint pid;
                if (GetWindowThreadProcessId(window, out pid) == 0) continue;
                using (var process = OpenProcess(0x1000, false, pid)) // PROCESS_QUERY_LIMITED_INFORMATION
                {
                    if (process.IsInvalid) continue;
                    var path = new StringBuilder(32768);
                    int length = path.Capacity;
                    if (!QueryFullProcessImageNameW(process, 0, path, ref length) ||
                        !String.Equals(executable, path.ToString(), StringComparison.OrdinalIgnoreCase)) continue;

                    // The server registers notification ID 1 against this hidden top-level window.
                    var icon = new IconIdentifier { Size = (uint)Marshal.SizeOf(typeof(IconIdentifier)), Window = window, Id = 1 };
                    Bounds bounds;
                    if (Shell_NotifyIconGetRect(ref icon, out bounds) == 0 &&
                        bounds.Right > bounds.Left && bounds.Bottom > bounds.Top) return true;
                }
            }
            return false;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IconIdentifier { public uint Size; public IntPtr Window; public uint Id; public Guid Guid; }
        [StructLayout(LayoutKind.Sequential)]
        private struct Bounds { public int Left, Top, Right, Bottom; }
        [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string className, string title);
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
        [DllImport("kernel32.dll")]
        private static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern bool QueryFullProcessImageNameW(SafeFileHandle process, uint flags, StringBuilder buffer, ref int size);
        [DllImport("shell32.dll", ExactSpelling = true)]
        private static extern int Shell_NotifyIconGetRect(ref IconIdentifier identifier, out Bounds bounds);
    }
}
