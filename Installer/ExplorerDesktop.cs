#if SERVER
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;

namespace BijouShare.Installer
{
    internal static class ExplorerDesktop
    {
        private static readonly Guid ShellWindows = new Guid("9BA05972-F6A8-11CF-A442-00A0C90A8F39");

        // The signed-in user's desktop executes the command, including when someone
        // supplied another account's administrator credentials at the UAC prompt.
        internal static bool Start(string executable, string arguments)
        {
            IntPtr shell = GetShellWindow();
            if (shell == IntPtr.Zero || !File.Exists(executable)) return false;
            object windows = null, desktop = null, view = null, application = null;
            try
            {
                windows = Activator.CreateInstance(Type.GetTypeFromCLSID(ShellWindows, true));
                // IShellWindows::FindWindowSW takes two input VARIANTs by reference,
                // SWC_DESKTOP, an output HWND, and SWFO_NEEDDISPATCH.
                var byRef = new ParameterModifier(5);
                byRef[0] = byRef[1] = byRef[3] = true;
                var find = new object[] { 0, 0, 8, 0, 1 };
                desktop = windows.GetType().InvokeMember("FindWindowSW", BindingFlags.InvokeMethod, null, windows, find,
                    new[] { byRef }, null, null);
                uint shellProcess, desktopProcess;
                if (desktop == null || GetWindowThreadProcessId(shell, out shellProcess) == 0 ||
                    GetWindowThreadProcessId(new IntPtr((int)find[3]), out desktopProcess) == 0 ||
                    desktopProcess != shellProcess) return false;

                view = desktop.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, desktop, null);
                if (view == null) return false;
                application = view.GetType().InvokeMember("Application", BindingFlags.GetProperty, null, view, null);
                if (application == null) return false;
                application.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, application,
                    new object[] { executable, arguments, Path.GetDirectoryName(executable), "open", 0 });
                return true;
            }
            catch (COMException) { return false; }
            catch (TargetInvocationException) { return false; }
            catch (MissingMethodException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (SecurityException) { return false; }
            finally
            {
                foreach (object instance in new[] { application, view, desktop, windows })
                    if (instance != null && Marshal.IsComObject(instance)) Marshal.ReleaseComObject(instance);
            }
        }

        [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    }
}
#endif
