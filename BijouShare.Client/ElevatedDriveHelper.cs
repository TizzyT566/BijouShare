using System.ComponentModel;
using System.Globalization;

namespace BijouShare.Client;

internal enum MountAliasReply : byte { Ready = 1, DifferentLogon = 2, LetterInUse = 3, VerificationFailed = 4 }

internal static class ElevatedDriveHelper
{
    internal static bool TryParse(string[] args, out char letter, out int workerPid, out Guid nonce)
    {
        letter = default;
        workerPid = default;
        nonce = default;
        if (args.Length != 4 || args[0] != "--elevated-drive" || args[1].Length != 2 ||
            args[1][0] is < 'A' or > 'Z' || args[1][1] != ':' ||
            !int.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out workerPid) || workerPid <= 0 ||
            !Guid.TryParseExact(args[3], "N", out nonce) || nonce == Guid.Empty)
            return false;
        letter = args[1][0];
        return true;
    }

    internal static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsWindows() || !TryParse(args, out var letter, out var workerPid, out var nonce))
            return 1;
        using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            using var session = await MountAliasPipe.ConnectAsync(letter, workerPid, nonce, startup.Token);
            IDisposable alias;
            try
            {
                alias = ElevatedDriveAlias.Create(letter + ":", workerPid, session.RootHandle);
            }
            catch (Exception ex) when (ex is IOException or Win32Exception or UnauthorizedAccessException or InvalidDataException)
            {
                var reason = ex switch
                {
                    ElevatedDriveAlias.DriveLetterInUseException => MountAliasReply.LetterInUse,
                    UnauthorizedAccessException => MountAliasReply.DifferentLogon,
                    _ => MountAliasReply.VerificationFailed
                };
                await session.Pipe.WriteAsync(new byte[] { (byte)reason }, startup.Token);
                return 1;
            }
            using (alias)
            {
                var signal = new byte[] { (byte)MountAliasReply.Ready };
                // This UAC-approved helper can authorize only the verified mount above.
                // An abandoned or canceled request must never become a lasting approval.
                var owner = UserDriveSecurity.Owner;
                ElevatedDriveConsent.Approve(owner, letter, nonce);
                bool acknowledged = false;
                try
                {
                    await session.Pipe.WriteAsync(signal, startup.Token);
                    acknowledged = await session.Pipe.ReadAsync(signal, startup.Token) == 1 && signal[0] == (byte)MountAliasReply.Ready;
                }
                finally { if (!acknowledged) ElevatedDriveConsent.Revoke(owner, letter, nonce); }
                if (!acknowledged) return 1;
                // The worker keeps its end open for this mount. EOF also covers worker exit.
                return await session.Pipe.ReadAsync(signal) == 0 ? 0 : 1;
            }
        }
        catch (Exception ex) when (ex is IOException or Win32Exception or UnauthorizedAccessException or InvalidDataException or
            OperationCanceledException or ArgumentException or InvalidOperationException or System.Security.SecurityException or DllNotFoundException or EntryPointNotFoundException)
        {
            return 1;
        }
    }
}
