using System;
using System.Diagnostics;
#if SERVER
using System.Diagnostics.Eventing.Reader;
#endif
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Installer
{
    internal static class Setup
    {
#if CLIENT && SERVER
#error Define exactly one installer role.
#elif CLIENT
        private const string Role = "Client";
#elif SERVER
        private const string Role = "Server";
#else
#error Define CLIENT or SERVER.
#endif
        private const string Product = "BijouShare " + Role;
        private const string Caption = Product + " Setup";

        [STAThread]
        private static int Main(string[] args)
        {
            bool quiet = false, passive = false, help = false, invalid = false;
            string operation = null;
            foreach (string argument in args)
            {
                switch (argument.ToLowerInvariant())
                {
                    case "/quiet": case "/qn": quiet = true; break;
                    case "/passive": passive = true; break;
                    case "/norestart": break; // All installations already pass /norestart to Windows Installer.
                    case "/?": case "/help": case "--help": help = true; break;
#if SERVER
                    case "/serviceaccount":
#endif
                    case "/repair": case "/uninstall":
                        if (operation != null) invalid = true;
                        operation = argument.ToLowerInvariant();
                        break;
                    default: invalid = true; break;
                }
            }
            bool unattended = quiet || passive;
#if SERVER
            if (operation == "/serviceaccount" && unattended) invalid = true;
#endif
            if (invalid || help)
            {
                if (!unattended) Show("Run setup to install " + Product +
                    ". Use /repair to repair it or /uninstall to remove it. Use /quiet (or /qn) for silent setup, or /passive for unattended setup with progress. " +
#if SERVER
                    "Use /serviceaccount to change the installed server's Windows account and restart its service. " +
#endif
                    "Setup always uses /norestart. Run unattended commands from an elevated terminal.", MessageBoxIcon.Information);
                return invalid ? 1639 : 0;
            }
#if SERVER
            FileStream serverOperation = null;
#endif
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    if (!Environment.Is64BitProcess || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    {
                        if (!unattended) Show("Run the 64-bit setup as a Windows administrator.", MessageBoxIcon.Error);
                        return 1603;
                    }
                }
#if SERVER
                // Serialize credential validation, its temporary logon right, and service
                // changes across sessions, including the interval before MSI takes its lock.
                try
                {
                    serverOperation = new FileStream(Path.Combine(ProtectedProgramFiles(), ".BijouShare-ServerSetup.lock"),
                        FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
                }
                catch (IOException error)
                {
                    int reason = error.HResult & 0xffff;
                    if (reason != 32 && reason != 33) throw;
                    if (!unattended) Show("Another BijouShare Server setup is running. Wait for it to finish, then try again.", MessageBoxIcon.Information);
                    return 1618;
                }
                if (operation == "/serviceaccount") return ServerAccountMaintenance.Run();
#endif
#if CLIENT
                if (operation != "/uninstall")
                {
                    int prerequisite = DokanPrerequisite.Ensure(unattended, DokanPrerequisite.Problem,
                        DokanPrerequisite.OpenWebsite, DokanPrerequisite.Prompt);
                    if (prerequisite != 0) return prerequisite;
                }
#endif
                if (!unattended
#if SERVER
                    && operation != null // The account dialog confirms an interactive install.
#endif
                    )
                {
                    string action = operation == "/uninstall" ? "Remove" : operation == "/repair" ? "Repair" : "Install";
                    if (MessageBox.Show(action + " " + Product + " for this computer?", Caption, MessageBoxButtons.OKCancel,
                            MessageBoxIcon.Question) != DialogResult.OK) return 1602;
                }
#if SERVER
                DateTime installStart = DateTime.UtcNow;
                ServerInstallAccount account = null;
                if (!unattended && operation == null && !ServerInstallAccount.Prompt(out account)) return 1602;
                bool maintenance = false;
                int code;
                using (account)
                {
                    Func<string, int> installWithAccount = null;
                    if (account != null)
                        installWithAccount = package => InstallWithAccount(package, account, out maintenance);
                    code = RunPackage(operation, quiet, passive, installWithAccount);
                    if (maintenance) return code; // Maintenance reports its own service result.
                    if (account != null && (code == 0 || code == 3010 || code == 1641))
                        account.KeepLogonRight();
                }
#else
                int code = RunPackage(operation, quiet, passive, null);
#endif
#if SERVER
                Func<bool> ensureTray = ServerTrayStartup.EnsureInstalled;
#else
                Func<bool> ensureTray = null;
#endif
                string instructions = AfterInstall(operation, quiet, passive, code, ensureTray);
                if (instructions != null) Show(instructions, MessageBoxIcon.Information);
                else if (!unattended && code != 1602)
                {
                    string result = operation == "/uninstall" ? "removed" : operation == "/repair" ? "repaired" : "installed";
                    if (code == 0 || code == 3010 || code == 1641)
                        Show(Product + " was " + result + "." + (code == 0 ? "" : "\r\nRestart Windows to finish setup."), MessageBoxIcon.Information);
                    else
                    {
                        string reason = new System.ComponentModel.Win32Exception(code).Message;
#if SERVER
                        reason = StorageFailure.Describe(operation, code, installStart, DateTime.UtcNow, StorageFailure.ReadEvent) ?? reason;
                        if (account != null && operation == null)
                            reason += "\r\nIf setup rolled back an upgrade and Windows reports a service logon failure, run this setup with /serviceaccount to re-enter the service password.";
#endif
                        Show("Windows Installer could not complete setup.\r\n\r\n" + reason +
                            " (" + code.ToString(CultureInfo.InvariantCulture) + ")", MessageBoxIcon.Error);
                    }
                }
                return code;
            }
            catch (Exception error)
            {
                if (!unattended) Show("Setup could not continue.\r\n\r\n" + error.Message, MessageBoxIcon.Error);
                return 1603;
            }
#if SERVER
            finally { if (serverOperation != null) serverOperation.Dispose(); }
#endif
        }

        private static void Show(string message, MessageBoxIcon icon)
        {
            MessageBox.Show(message, Caption, MessageBoxButtons.OK, icon);
        }

#if SERVER
        private static int InstallWithAccount(string package, ServerInstallAccount account, out bool maintenance)
        {
            maintenance = false;
            Application.OleRequired(); // MSI requires COM on the thread that opens the package.
            const int basicProgress = 3, rebootAtEnd = 6;
            int previousUi = MsiSetInternalUI(basicProgress, IntPtr.Zero);
            uint session = 0;
            try
            {
                int code = MsiOpenPackageExW(package, 0, out session);
                if (code != 0) return code;
                if (MsiEvaluateConditionW(session, "Installed") == 1)
                {
                    maintenance = true;
                    return ServerAccountMaintenance.Apply(account);
                }

                // The password is set as a hidden session property, never serialized as
                // command-line syntax. Quotes, whitespace and MSI-looking text stay literal.
                code = MsiSetPropertyW(session, "REBOOT", "ReallySuppress");
                if (code != 0) return code;
                code = MsiSetPropertyW(session, "BIJOUSERVICEACCOUNT", account.AccountName);
                if (code != 0) return code;
                IntPtr password = Marshal.SecureStringToGlobalAllocUnicode(account.Password);
                try { code = MsiSetPasswordProperty(session, "BIJOUSERVICEPASSWORD", password); }
                finally { Marshal.ZeroFreeGlobalAllocUnicode(password); }
                if (code != 0) return code;
                code = MsiDoActionW(session, "INSTALL");
                return code == 0 && MsiGetMode(session, rebootAtEnd) ? 3010 : code;
            }
            finally
            {
                if (session != 0) MsiCloseHandle(session);
                MsiSetInternalUI(previousUi, IntPtr.Zero);
            }
        }

        [DllImport("msi.dll", ExactSpelling = true)] private static extern int MsiSetInternalUI(int level, IntPtr window);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int MsiOpenPackageExW(string path, uint options, out uint session);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int MsiEvaluateConditionW(uint session, string condition);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int MsiSetPropertyW(uint session, string property, string value);
        [DllImport("msi.dll", EntryPoint = "MsiSetPropertyW", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int MsiSetPasswordProperty(uint session, string property, IntPtr value);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int MsiDoActionW(uint session, string action);
        [DllImport("msi.dll", ExactSpelling = true)] private static extern bool MsiGetMode(uint session, int mode);
        [DllImport("msi.dll", ExactSpelling = true)] private static extern int MsiCloseHandle(uint session);
#endif

        internal static string AfterInstall(string operation, bool quiet, bool passive, int exitCode, Func<bool> ensureTray)
        {
            if (operation != null || quiet || passive || (exitCode != 0 && exitCode != 3010 && exitCode != 1641)) return null;
            string shortcut = "Start > BijouShare > " + Product;
            string recovery = "If the icon is missing, open " + shortcut + ".";
#if SERVER
            if (exitCode == 0 && !ensureTray())
                return Product + " was installed.\r\n\r\nSetup could not confirm a tray icon in this Windows session. " +
                    "Open " + shortcut + " to show the icon. It may appear under Show hidden icons (^) beside the clock.";
#endif
            return Product + " was installed." + (exitCode == 0 ? "" : " Restart Windows to finish setup.") +
                "\r\n\r\nClick the " + Product + " tray icon beside the clock to open the web UI. " +
                "Select Show hidden icons (^) if you don't see it.\r\n\r\n" + recovery;
        }

        private static string ProtectedProgramFiles()
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (String.IsNullOrEmpty(root) || !Path.IsPathRooted(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The protected Program Files directory is unavailable.");
            return root;
        }

        private static int RunPackage(string operation, bool quiet, bool passive, Func<string, int> installWithAccount)
        {
            // A split-token administrator's normal desktop processes can change entries in
            // the user's TEMP directory. Stage installer input in the machine's protected
            // Program Files directory with an explicit administrator/SYSTEM-only DACL.
            string directory = Path.Combine(ProtectedProgramFiles(), ".BijouShare-Setup-" + Guid.NewGuid().ToString("N"));
            string msi = Path.Combine(directory, "BijouShare.msi");
            var acl = new DirectorySecurity();
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(admins);
            foreach (var identity in new[] { admins, system })
                acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(directory, acl);
            try
            {
                using (Stream embedded = Assembly.GetExecutingAssembly().GetManifestResourceStream("BijouShare.Package.msi"))
                {
                    if (embedded == null) throw new InvalidDataException("The installer package is missing. Obtain a fresh copy of setup.");
                    using (var file = new FileStream(msi, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        embedded.CopyTo(file);
                }
                if (installWithAccount != null) return installWithAccount(msi);
                // Repair from the embedded package even if the original staging path has gone away.
                string action = operation == "/uninstall" ? "/x" : operation == "/repair" ? "/fvomus" : "/i";
                string display = quiet ? "/qn" : passive ? "/passive" : "/qb";
                var launch = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
                    action + " \"" + msi + "\" " + display + " /norestart");
                launch.UseShellExecute = false;
                launch.WorkingDirectory = Environment.SystemDirectory;
                using (var installer = Process.Start(launch))
                {
                    installer.WaitForExit();
                    return installer.ExitCode;
                }
            }
            finally
            {
                // Never recurse into an installation or user-data directory during cleanup.
                try { File.Delete(msi); Directory.Delete(directory); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

#if SERVER
    internal static class ServerTrayStartup
    {
        internal static bool EnsureInstalled()
        {
            string directory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (String.IsNullOrEmpty(directory) || !Path.IsPathRooted(directory)) return false;
            string executable = Path.Combine(directory, "BijouShare", "Server", "BijouShare.Server.Tray.exe");
            return Ensure(() => ServerTrayRegistration.IsRegistered(executable),
                () => ExplorerDesktop.Start(executable, "--tray-only"), () => System.Threading.Thread.Sleep(200));
        }

        internal static bool Ensure(Func<bool> isRegistered, Func<bool> start, Action wait)
        {
            if (isRegistered()) return true;
            // Explorer can register the icon asynchronously, including during another launch at sign-in.
            try { start(); }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
            catch (COMException) { }
            for (int attempt = 0; attempt < 25; attempt++)
            {
                if (isRegistered()) return true;
                wait();
            }
            return isRegistered();
        }
    }

    internal static class StorageFailure
    {
        internal static int? ReadEvent(DateTime startUtc, DateTime endUtc)
        {
            string filter = String.Format(CultureInfo.InvariantCulture,
                "*[System[Provider[@Name='BijouShare.Server'] and (EventID=4201 or EventID=4202 or EventID=4203 or EventID=4204)" +
                " and TimeCreated[@SystemTime >= '{0:O}' and @SystemTime <= '{1:O}']]]", startUtc, endUtc);
            var query = new EventLogQuery("Application", PathType.LogName, filter) { ReverseDirection = true };
            using (var reader = new EventLogReader(query))
            using (var entry = reader.ReadEvent())
                return entry == null ? (int?)null : entry.Id;
        }

        internal static string Describe(string operation, int exitCode, DateTime startUtc, DateTime endUtc,
            Func<DateTime, DateTime, int?> readEvent)
        {
            if (exitCode != 1603 || operation == "/uninstall") return null;
            int? eventId;
            try { eventId = readEvent(startUtc, endUtc); }
            catch (EventLogException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (System.Security.SecurityException) { return null; }
            string reason;
            switch (eventId)
            {
                case 4201: reason = @"Windows denied access to the server data folder. Have an administrator check the owner and write permissions on %ProgramData%\BijouShare and its Server folder."; break;
                case 4202: reason = @"The server data path contains an unsafe directory. Check %ProgramData%\BijouShare\Server and its parent directories for symbolic links or junctions."; break;
                case 4203: reason = @"A folder in the server data path is in use. Close any BijouShare Server instance or other program holding the folder, then run setup again."; break;
                case 4204: reason = @"Windows could not prepare the server data folder under %ProgramData%\BijouShare. Check the drive and the Windows error recorded below before retrying."; break;
                default: return null;
            }
            return reason + "\r\n\r\nFor details, open Event Viewer → Windows Logs → Application and find BijouShare.Server event " +
                eventId.Value.ToString(CultureInfo.InvariantCulture) + ".";
        }
    }
#endif

#if CLIENT
    internal static class DokanPrerequisite
    {
        internal const string Website = "https://github.com/dokan-dev/dokany";

        internal static bool Prompt(string issue)
        {
            return MessageBox.Show(issue + "\r\n\r\nInstall Dokany 2.3 or a later 2.x release for 64-bit Windows from\r\n" +
                Website + "\r\n\r\nAfter installing Dokany, choose Retry to continue setup.",
                "BijouShare Client Setup", MessageBoxButtons.RetryCancel, MessageBoxIcon.Warning) == DialogResult.Retry;
        }

        internal static int Ensure(bool unattended, Func<string> check, Action openPage, Func<string, bool> retry)
        {
            string problem = check();
            if (problem == null) return 0;
            if (unattended) return 1603;
            // The prompt includes the URL even on desktops with no registered browser.
            try { openPage(); }
            catch (System.ComponentModel.Win32Exception) { }
            catch (InvalidOperationException) { }
            while (problem != null)
            {
                if (!retry(problem)) return 1602;
                problem = check();
            }
            return 0;
        }

        internal static string Problem()
        {
            try
            {
                string runtime = Path.Combine(Environment.SystemDirectory, "dokan2.dll");
                if (!VersionMatches(runtime) || !MatchesMachine(runtime, 0x8664))
                    return "The 64-bit Dokany runtime is missing or incompatible.";
                using (RegistryKey service = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Dokan2"))
                {
                    int start = service == null ? -1 : service.GetValue("Start") as int? ?? -1;
                    if (service == null || !Object.Equals(service.GetValue("Type"), 2) || start < 0 || start > 3)
                        return "The Dokany filesystem driver is missing or disabled.";
                    string driver = ResolveDriverPath(service.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
                    if (driver == null || !VersionMatches(driver) || !MatchesMachine(driver, NativeDriverMachine()))
                        return "The registered Dokany driver is missing or incompatible.";
                }
                return null;
            }
            catch (Exception error)
            {
                if (!(error is IOException || error is UnauthorizedAccessException || error is System.ComponentModel.Win32Exception ||
                      error is System.Security.SecurityException || error is ArgumentException || error is NotSupportedException)) throw;
                return "Setup could not verify the installed Dokany runtime and driver.";
            }
        }

        internal static string ResolveDriverPath(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return null;
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string path = value.Trim().Trim('"').Replace('/', '\\');
            if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path.Substring(4);
            foreach (string prefix in new[] { @"\SystemRoot\", @"%SystemRoot%\", @"%windir%\" })
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return Path.Combine(windows, path.Substring(prefix.Length));
            if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) return Path.Combine(windows, path);
            if (path.Length >= 3 && Char.IsLetter(path[0]) && path[1] == ':' && path[2] == '\\') return path;
            return null;
        }

        private static bool VersionMatches(string path)
        {
            if (!File.Exists(path)) return false;
            var version = FileVersionInfo.GetVersionInfo(path);
            return version.FileMajorPart == 2 && version.FileMinorPart >= 3;
        }

        private static ushort NativeDriverMachine()
        {
            ushort process, native;
            // A win-x64 application on Windows on Arm still needs an Arm64 kernel driver.
            try { if (IsWow64Process2(new IntPtr(-1), out process, out native)) return native; }
            catch (EntryPointNotFoundException) { } // Older x64 Windows did not support x64-on-Arm emulation.
            return 0x8664;
        }

        private static bool MatchesMachine(string path, ushort machine)
        {
            using (var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            using (var image = new BinaryReader(file))
            {
                if (file.Length < 64 || image.ReadUInt16() != 0x5a4d) return false;
                file.Position = 60;
                int header = image.ReadInt32();
                if (header < 64 || header > file.Length - 6) return false;
                file.Position = header;
                return image.ReadUInt32() == 0x4550 && image.ReadUInt16() == machine;
            }
        }

        internal static void OpenWebsite()
        {
            string handler = Path.Combine(Environment.SystemDirectory, "url.dll");
            if (DesktopLaunch.Start(Path.Combine(Environment.SystemDirectory, "rundll32.exe"),
                "\"" + handler + "\",FileProtocolHandler " + Website)) return;
            // Ask the desktop shell to dispatch the URL if its token cannot be opened.
            string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            using (Process.Start(new ProcessStartInfo(explorer, Website) { UseShellExecute = false })) { }
        }

        [DllImport("kernel32.dll")] private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    }

    internal static class DesktopLaunch
    {
        internal static bool Start(string executable, string arguments)
        {
            // Use Explorer's desktop token to open the prerequisite page for the signed-in user.
            IntPtr desktop = GetShellWindow();
            uint processId;
            if (desktop == IntPtr.Zero || GetWindowThreadProcessId(desktop, out processId) == 0) return false;
            using (var shell = OpenProcess(0x1000, false, processId))
            {
                SafeFileHandle token;
                if (shell.IsInvalid || !OpenProcessToken(shell, 0x0001 | 0x0002 | 0x0008, out token)) return false;
                using (token)
                {
                    IntPtr environment;
                    if (!CreateEnvironmentBlock(out environment, token, false)) return false;
                    ProcessInfo child;
                    try
                    {
                        var command = new StringBuilder("\"" + executable + "\" " + arguments);
                        var startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfo)), Desktop = @"winsta0\default" };
                        const uint unicodeEnvironment = 0x400, noWindow = 0x08000000;
                        if (!CreateProcessWithTokenW(token, 0, executable, command, unicodeEnvironment | noWindow,
                            environment, Path.GetDirectoryName(executable), ref startup, out child)) return false;
                    }
                    finally { DestroyEnvironmentBlock(environment); }
                    CloseHandle(child.Thread);
                    CloseHandle(child.Process);
                    return true;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int Size;
            public string Reserved, Desktop, Title;
            public int X, Y, Width, Height, Columns, Rows, Attributes, Flags;
            public ushort Show, ReservedSize;
            public IntPtr Reserved2, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
        [DllImport("kernel32.dll")] private static extern SafeFileHandle OpenProcess(uint rights, bool inherit, uint pid);
        [DllImport("advapi32.dll")] private static extern bool OpenProcessToken(SafeFileHandle process, uint rights, out SafeFileHandle token);
        [DllImport("userenv.dll")] private static extern bool CreateEnvironmentBlock(out IntPtr environment, SafeFileHandle token, bool inherit);
        [DllImport("userenv.dll")] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern bool CreateProcessWithTokenW(SafeFileHandle token, uint logonFlags, string application, StringBuilder command,
            uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo result);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    }
#endif
}
