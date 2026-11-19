using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BijouShare.Client;

// Session zero has no user drive namespace. Only the signed-in user process handles keys and file I/O.
internal sealed class UserSessionLauncher(ILogger<UserSessionLauncher> logger, bool headless) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var children = new Dictionary<int, SafeProcessHandle>();
        var retryAfter = new Dictionary<int, DateTime>();
        // Using the installed apphost also makes the child independent of the service working directory.
        var binary = Path.Combine(AppContext.BaseDirectory, "BijouShare.Client.exe");
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var sessions = GetActiveSessions();
                    foreach (var (session, process) in children.ToArray())
                    {
                        if (WaitForSingleObject(process, 0) != 0)
                            continue;
                        children.Remove(session);
                        using var exited = process;
                        if (!sessions.Contains(session))
                            continue;
                        if (GetExitCodeProcess(exited, out var exitCode))
                        {
                            // An attached worker exits normally when the profile owner stops.
                            if (exitCode == 0)
                                continue;
                            logger.LogWarning("The client worker in Windows session {Session} exited with code {ExitCode}. Retrying in 30 seconds.", session, exitCode);
                        }
                        else
                            logger.LogWarning("Could not read the client worker exit code in Windows session {Session} (Windows error {Error}). Retrying in 30 seconds.", session, Marshal.GetLastWin32Error());
                        retryAfter[session] = DateTime.UtcNow.AddSeconds(30);
                    }
                    foreach (var session in sessions)
                    {
                        if (children.ContainsKey(session) || retryAfter.GetValueOrDefault(session) > DateTime.UtcNow)
                            continue;
                        try { children.Add(session, StartWorker(binary, session, headless)); }
                        catch (Win32Exception ex)
                        {
                            logger.LogWarning("Could not start the client in Windows session {Session} (Windows error {Error}).", session, ex.NativeErrorCode);
                            retryAfter[session] = DateTime.UtcNow.AddSeconds(30);
                        }
                    }
                    foreach (var session in retryAfter.Keys.Except(sessions).ToArray())
                        retryAfter.Remove(session);
                }
                catch (Win32Exception ex)
                {
                    logger.LogWarning("Could not enumerate signed-in sessions (Windows error {Error}).", ex.NativeErrorCode);
                }
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
        finally
        {
            foreach (var process in children.Values)
            {
                using (process)
                {
                    if (WaitForSingleObject(process, 0) == 258 && !TerminateProcess(process, 0))
                        logger.LogDebug("The session worker was already closing.");
                }
            }
        }
    }

    private static HashSet<int> GetActiveSessions()
    {
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var entries, out var count))
            throw new Win32Exception();
        try
        {
            var result = new HashSet<int>();
            var size = Marshal.SizeOf<SessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<SessionInfo>(entries + i * size);
                if (entry.SessionId != 0 && entry.State == 0) // WTSActive
                    result.Add(entry.SessionId);
            }
            return result;
        }
        finally { WTSFreeMemory(entries); }
    }

    private static SafeProcessHandle StartWorker(string executable, int session, bool headless)
    {
        if (!WTSQueryUserToken(session, out var token))
            throw new Win32Exception();
        using (token)
        {
            if (!CreateEnvironmentBlock(out var environment, token, false))
                throw new Win32Exception();
            try
            {
                var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>(), Desktop = @"winsta0\default" };
                // Specify the application path explicitly and use only the user's environment.
                var arguments = headless ? "--session-worker --no-browser" : "--session-worker";
                if (!CreateProcessAsUser(token, executable, new System.Text.StringBuilder($"\"{executable}\" {arguments}"),
                    0, 0, false, 0x08000400 /* CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT */, environment,
                    AppContext.BaseDirectory, ref startup, out var result))
                    throw new Win32Exception();
                CloseHandle(result.Thread);
                return new SafeProcessHandle(result.Process, ownsHandle: true);
            }
            finally { DestroyEnvironmentBlock(environment); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionInfo { public int SessionId; public nint Station; public int State; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved, Desktop, Title;
        public uint X, Y, Width, Height, Columns, Rows, Attributes, Flags;
        public ushort ShowWindow, ReservedSize;
        public nint ReservedPointer, StandardInput, StandardOutput, StandardError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo { public nint Process, Thread; public int ProcessId, ThreadId; }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(nint server, int reserved, int version, out nint entries, out int count);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(nint entries);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int session, out SafeAccessTokenHandle token);
    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out nint environment, SafeAccessTokenHandle token, bool inherit);
    [DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(nint environment);
    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string executable,
        System.Text.StringBuilder commandLine, nint processAttributes, nint threadAttributes, bool inheritHandles,
        int flags, nint environment, string directory, ref StartupInfo startup, out ProcessInfo result);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(nint handle);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
}
