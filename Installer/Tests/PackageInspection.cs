using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

public static class PackageInspection
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll")] private static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] private static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] private static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr module);

    public static void CheckUnattendedArguments(Assembly setup)
    {
        // Include help to exercise the real command parser without starting an MSI transaction.
        foreach (string mode in new[] { "/quiet", "/qn", "/passive" })
        foreach (string action in new[] { "", "/repair", "/uninstall" })
        {
            string[] args = action.Length == 0 ? new[] { mode, "/norestart", "/?" } : new[] { mode, action, "/norestart", "/?" };
            if (!Equals(setup.EntryPoint.Invoke(null, new object[] { args }), 0))
                throw new InvalidOperationException("Unattended setup rejected " + String.Join(" ", args));
        }
        if (!Equals(setup.EntryPoint.Invoke(null, new object[] { new[] { "/quiet", "/norestart", "/unknown" } }), 1639))
            throw new InvalidOperationException("Unattended setup accepted an unknown switch.");
    }

    public static string ReadManifest(string file)
    {
        var module = LoadLibraryEx(file, IntPtr.Zero, 0x02 | 0x20); // LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE
        if (module == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var resource = FindResourceW(module, (IntPtr)1, (IntPtr)24); // RT_MANIFEST, application manifest
            if (resource == IntPtr.Zero) throw new Win32Exception();
            var bytes = new byte[SizeofResource(module, resource)];
            var data = LockResource(LoadResource(module, resource));
            if (data == IntPtr.Zero || bytes.Length == 0) throw new Win32Exception();
            Marshal.Copy(data, bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(bytes).Trim('\uFEFF', '\0');
        }
        finally { FreeLibrary(module); }
    }

    public static void CheckDokanFlow(Assembly setup)
    {
        var type = setup.GetType("BijouShare.Installer.DokanPrerequisite", true);
        var ensure = type.GetMethod("Ensure", BindingFlags.NonPublic | BindingFlags.Static);
        var website = type.GetField("Website", BindingFlags.NonPublic | BindingFlags.Static);
        if (!Equals(website.GetRawConstantValue(), "https://github.com/dokan-dev/dokany"))
            throw new InvalidOperationException("Incorrect Dokany website.");
        CheckFlow(ensure, false, 0, false, 0, 1, 0, 0);       // Installed
        CheckFlow(ensure, false, 2, true, 0, 3, 1, 2);        // Missing through two checks, installed before the third
        CheckFlow(ensure, false, 1, false, 1602, 1, 1, 1);    // Cancel
        CheckFlow(ensure, true, 1, false, 1603, 1, 0, 0);     // Unattended missing dependency
    }

    public static void CheckPostInstall(Assembly setup, string role)
    {
        var type = setup.GetType("BijouShare.Installer.Setup", true);
        var complete = type.GetMethod("AfterInstall", BindingFlags.Static | BindingFlags.NonPublic);
        if (complete == null) throw new InvalidOperationException("Missing post-install tray instructions.");

        foreach (var operation in new string[] { null, "/repair", "/uninstall" })
        foreach (var mode in new[] { "interactive", "/quiet", "/passive" })
        foreach (var exitCode in new[] { 0, 1602, 1603, 1618, 1641, 3010 })
        {
            int attempts = 0;
            Func<bool> ensureTray = () => { attempts++; return true; };
            string instructions = (string)complete.Invoke(null, new object[] { operation, mode == "/quiet", mode == "/passive", exitCode, ensureTray });
            bool interactiveInstall = operation == null && mode == "interactive";
            bool showInstructions = interactiveInstall && (exitCode == 0 || exitCode == 1641 || exitCode == 3010);
            bool verifyServerTray = role == "Server" && interactiveInstall && exitCode == 0;
            if (attempts != (verifyServerTray ? 1 : 0) || (instructions != null) != showInstructions)
                throw new InvalidOperationException(String.Format("{0} tray startup count {1} for {2}, {3}, exit {4}.",
                    role, attempts, operation ?? "install", mode, exitCode));
            if (showInstructions && (!instructions.Contains("Click the BijouShare " + role + " tray icon") ||
                !instructions.Contains("web UI") || !instructions.Contains("Show hidden icons") ||
                (exitCode != 0 && !instructions.Contains("Restart Windows"))))
                throw new InvalidOperationException("Missing setup completion guidance for " + role + ".");
        }

        var startup = setup.GetType("BijouShare.Installer.ServerTrayStartup");
        if (role == "Client")
        {
            if (startup != null) throw new InvalidOperationException("Client setup contains the server tray startup helper.");
            return;
        }
        int unavailableChecks = 0;
        Func<bool> unavailable = () => { unavailableChecks++; return false; };
        string recovery = (string)complete.Invoke(null, new object[] { null, false, false, 0, unavailable });
        if (unavailableChecks != 1 || recovery == null ||
            !recovery.Contains("Setup could not confirm a tray icon in this Windows session.") ||
            !recovery.Contains("Start > BijouShare > BijouShare Server") ||
            recovery.IndexOf("Click the BijouShare Server tray icon", StringComparison.OrdinalIgnoreCase) >= 0)
            throw new InvalidOperationException("Server setup omitted Start menu recovery for an unconfirmed icon.");
        var method = startup == null ? null : startup.GetMethod("Ensure", BindingFlags.Static | BindingFlags.NonPublic);
        if (method == null) throw new InvalidOperationException("Missing server tray registration check.");
        var ensure = (Func<Func<bool>, Func<bool>, Action, bool>)Delegate.CreateDelegate(
            typeof(Func<Func<bool>, Func<bool>, Action, bool>), method);
        int initialChecks = 0, activeStarts = 0, activeWaits = 0;
        if (!ensure(() => { initialChecks++; return true; },
                () => { activeStarts++; return true; }, () => { activeWaits++; }) ||
            initialChecks != 1 || activeStarts != 0 || activeWaits != 0)
            throw new InvalidOperationException("Setup did not recognize an already active server tray icon.");

        foreach (string launchResult in new[] { "started", "failed", "denied" })
        foreach (bool appears in new[] { true, false })
            CheckTrayRegistration(ensure, launchResult, appears);
    }

    private static void CheckTrayRegistration(Func<Func<bool>, Func<bool>, Action, bool> ensure, string launchResult, bool appears)
    {
        int queries = 0, launches = 0, waits = 0;
        Func<bool> registered = () =>
        {
            if (++queries > 128) throw new InvalidOperationException("Server tray registration polling exceeded its bound.");
            // A tray can register asynchronously, even when a second launch failed during a restart.
            return appears && waits >= 2;
        };
        Func<bool> launch = () =>
        {
            if (queries == 0 || ++launches != 1)
                throw new InvalidOperationException("Setup must check registration before its single desktop launch.");
            if (launchResult == "denied") throw new UnauthorizedAccessException("Test desktop access denial.");
            return launchResult == "started";
        };
        bool result = ensure(registered, launch, () =>
        {
            if (++waits > 128) throw new InvalidOperationException("Setup kept waiting for a missing icon.");
        });
        if (result != appears || launches != 1 || queries < 2 || waits < 2 || (appears && waits != 2))
            throw new InvalidOperationException("Server tray readiness did not match observed registration after desktop launch " + launchResult + ".");
    }

    private static void CheckFlow(MethodInfo ensure, bool quiet, int failures, bool retry, int expectedCode,
        int expectedChecks, int expectedLaunches, int expectedPrompts)
    {
        int checks = 0, launches = 0, prompts = 0;
        Func<string> check = () => checks++ < failures ? "Missing Dokany." : null;
        Action open = () => launches++;
        Func<string, bool> prompt = issue =>
        {
            if (++prompts > expectedPrompts || issue != "Missing Dokany.")
                throw new InvalidOperationException("Unexpected prerequisite prompt.");
            return retry;
        };
        int code = (int)ensure.Invoke(null, new object[] { quiet, check, open, prompt });
        if (code != expectedCode || checks != expectedChecks || launches != expectedLaunches || prompts != expectedPrompts)
            throw new InvalidOperationException("Unexpected prerequisite detection, website launch, retry or cancel behavior.");
    }

    public static void CheckStorageDiagnostics(Assembly setup, string role)
    {
        var type = setup.GetType("BijouShare.Installer.StorageFailure");
        if (role == "Client")
        {
            if (type != null) throw new InvalidOperationException("Client setup contains server storage diagnostics.");
            return;
        }
        var describe = type.GetMethod("Describe", BindingFlags.Static | BindingFlags.NonPublic);
        var start = DateTime.UtcNow.AddMinutes(-1);
        var end = DateTime.UtcNow;
        foreach (var operation in new string[] { null, "/repair" })
        foreach (var eventId in new int?[] { null, 4201, 4202, 4203, 4204, 8192 })
        {
            int reads = 0;
            Func<DateTime, DateTime, int?> lookup = (from, until) =>
            {
                if (from != start || until != end) throw new InvalidOperationException("Incorrect MSI event interval.");
                reads++;
                return eventId;
            };
            var detail = (string)describe.Invoke(null, new object[] { operation, 1603, start, end, lookup });
            var known = eventId >= 4201 && eventId <= 4204;
            if (reads != 1 || (known ? detail == null || !detail.Contains("BijouShare.Server event " + eventId) : detail != null))
                throw new InvalidOperationException("Unexpected server storage failure explanation for " + eventId);
        }
        Func<DateTime, DateTime, int?> unexpected = (from, until) => { throw new InvalidOperationException("Unrelated failure queried the Application log."); };
        foreach (var code in new[] { 0, 1602, 1618, 3010 })
            if (describe.Invoke(null, new object[] { null, code, start, end, unexpected }) != null)
                throw new InvalidOperationException("Storage diagnostics must apply only to failed installation or repair.");
        if (describe.Invoke(null, new object[] { "/uninstall", 1603, start, end, unexpected }) != null)
            throw new InvalidOperationException("Uninstall should retain its MSI details.");
        Func<DateTime, DateTime, int?> denied = (from, until) => { throw new UnauthorizedAccessException(); };
        if (describe.Invoke(null, new object[] { null, 1603, start, end, denied }) != null)
            throw new InvalidOperationException("An unavailable Application log must retain the ordinary MSI details.");
    }
}
