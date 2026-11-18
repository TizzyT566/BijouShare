using System.Net;
using System.Security.Cryptography;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed partial class StateStore
{
    public bool TryCompleteSetup(string? serverName, string? adminName, string? password, string? confirmPassword)
    {
        if (IsInitialized)
            return false;
        ValidateServerName(serverName);
        ValidateName(adminName);
        if (string.IsNullOrWhiteSpace(password) || password.Length is < 14 or > 1024)
            throw new ArgumentException("Use an administrator password of 14 to 1024 characters.");
        if (string.IsNullOrWhiteSpace(confirmPassword) || password != confirmPassword)
            throw new ArgumentException("Enter the same password in both password fields.");
        var salt = RandomNumberGenerator.GetBytes(32);
        // Hashing must not block file authorization or another setup request's state inspection.
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        var committed = false;
        try
        {
            Update(s =>
            {
                if (s.Admin is not null)
                    throw new SetupAlreadyCompletedException();
                s.Admin = new(adminName!, salt, hash);
                s.ServerName = serverName!;
                s.ServerId = ServerIdentityNaming.Id(serverName!, Convert.FromBase64String(s.ServerPublicKey));
                return true;
            });
            committed = true;
            return true;
        }
        catch (SetupAlreadyCompletedException) { return false; }
        finally { if (!committed) CryptographicOperations.ZeroMemory(hash); }
    }

    private sealed class SetupAlreadyCompletedException : Exception
    {
    }
}

public static class ServerSetupSecurity
{
    public static bool IsLocalRequest(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress;
        if (remote?.IsIPv4MappedToIPv6 == true)
            remote = remote.MapToIPv4();
        var host = context.Request.Host.Host;
        var localHost = host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            IPAddress.TryParse(host.Trim('[', ']'), out var hostAddress) && IPAddress.IsLoopback(hostAddress);
        var origin = context.Request.Headers.Origin.ToString();
        var ownOrigin = context.Request.Scheme + "://" + context.Request.Host;
        return remote is not null && IPAddress.IsLoopback(remote) && localHost &&
            (origin.Length == 0 || origin.Equals(ownOrigin, StringComparison.OrdinalIgnoreCase)) &&
            context.Request.Headers["Sec-Fetch-Site"] != "cross-site";
    }
}
