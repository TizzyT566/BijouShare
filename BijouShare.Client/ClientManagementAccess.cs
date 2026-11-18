using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace BijouShare.Client;

internal static partial class UserProfileStorage
{
    private static string HomeDirectory => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static string ProfileDirectory => Path.Combine(HomeDirectory, ".bijoushare");
    private static bool IsInsideHome(string path)
    {
        var home = HomeDirectory;
        return Path.IsPathFullyQualified(home) && Path.IsPathFullyQualified(path) &&
            Path.GetFullPath(path).StartsWith(Path.TrimEndingDirectorySeparator(home) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    internal static void RequireHomeDirectory(string path)
    {
        if (!IsInsideHome(path) || Path.GetFullPath(path).Split(Path.DirectorySeparatorChar)
            .Skip(1).Any(component => component.EndsWith('.') || component.EndsWith(' ') ||
                component.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
            throw new ArgumentException("Choose a client data directory inside your Windows user profile.");
    }

    public static string Resolve(string? requestedDirectory)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.IsSystem || !Environment.UserInteractive)
            throw new InvalidOperationException("Start the client in your Windows sign-in session.");
        if (requestedDirectory is not null)
        {
            if (!Path.IsPathFullyQualified(requestedDirectory))
                throw new ArgumentException("--data-dir must be an absolute path.");
            var requested = Path.TrimEndingDirectorySeparator(Path.GetFullPath(requestedDirectory));
            if (!requested.Equals(ProfileDirectory, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Client data belongs in %USERPROFILE%\\.bijoushare. Start the client without --data-dir.");
        }
        RequireHomeDirectory(ProfileDirectory);
        return ProfileDirectory;
    }

}

public sealed class ClientManagementAccess
{
    private readonly string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private readonly TaskCompletionSource<string> launch = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal void Listen(string address) => launch.SetResult(address.TrimEnd('/') + "/#access=" + secret);
    internal Task<string> LaunchUrl(CancellationToken cancellation) => launch.Task.WaitAsync(cancellation);

    internal void RequireOwner(WebApplication app)
    {
        var expected = Encoding.ASCII.GetBytes("Bearer " + secret);
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                var authorization = context.Request.Headers.Authorization.ToString();
                if (authorization.Length != expected.Length ||
                    !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(authorization), expected))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.Headers.CacheControl = "no-store";
                    await context.Response.WriteAsJsonAsync(new { error = "Click the BijouShare Client tray icon in your Windows session to manage your drives." });
                    return;
                }
            }
            await next();
        });
    }
}
