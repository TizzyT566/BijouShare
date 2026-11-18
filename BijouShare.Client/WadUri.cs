using System.Text.RegularExpressions;
using BijouShare.Shared;

namespace BijouShare.Client;

public sealed record WadUri(string Host, int Port, string TrustedServerId, string? InviteCode = null)
{
    public static WadUri Parse(string value)
    {
        if (value is null || value.Length > 2048 ||
            !Regex.IsMatch(value, @"\A(?i:wad)://(?:\[[0-9a-fA-F:.%]+\]|[^:/?#@\\\s]+):[0-9]{1,5}/[0-9a-f]{64}(?:#[A-Za-z0-9_-]{32})?\z", RegexOptions.CultureInvariant) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "wad" || uri.Port is < 1 or > 65535 ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.HostNameType == UriHostNameType.Unknown)
            throw new ArgumentException("Use wad://host:port/full-fingerprint with an optional #invite-code.");
        return new(uri.IdnHost.Trim('[', ']'), uri.Port, ServerIdentityNaming.ValidateId(uri.AbsolutePath[1..]),
            uri.Fragment.Length == 0 ? null : uri.Fragment[1..]);
    }

    public static void ValidateInviteCode(string? value)
    {
        if (value is not null && !Regex.IsMatch(value, @"\A[A-Za-z0-9_-]{32}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("The invitation code must contain exactly 32 letters, digits, underscores, or hyphens.");
    }

    // Invitations are bearer credentials; diagnostic string conversion must not expose them.
    public override string ToString() => $"wad://{(Host.Contains(':') ? "[" + Host + "]" : Host)}:{Port}/{TrustedServerId}";
    internal string ToStringWithInvite() => ToString() + (InviteCode is null ? "" : "#" + InviteCode);
}
