using System.Diagnostics;
using BijouShare.Server;

if (args is not ([] or ["--tray-only"]))
    return 87; // ERROR_INVALID_PARAMETER

using (var process = Process.GetCurrentProcess())
{
    if (!Environment.UserInteractive || process.SessionId == 0)
        return 1;
}

return ServerTray.RunCompanion();
