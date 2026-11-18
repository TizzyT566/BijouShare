using System.Text.RegularExpressions;

namespace BijouShare.Client;

public sealed record WadUri(string Host, int Port, string? InviteCode)
{
    public static WadUri Parse(string value)
    {
        if (value is null || value.Length > 2048 ||
            !Regex.IsMatch(value, @"\Awad://(?:\[[0-9a-fA-F:.%]+\]|[^:/?#@\\\s]+):[0-9]{1,5}(?:/[A-Za-z0-9_-]{1,128}|/)?\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "wad" || uri.Port is < 1 or > 65535 ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.HostNameType == UriHostNameType.Unknown)
            throw new ArgumentException("Use a link in the form wad://host:port or wad://host:port/invite-code.");
        var code = uri.AbsolutePath.Trim('/');
        ValidateInviteCode(code.Length == 0 ? null : code);
        return new(uri.IdnHost.Trim('[', ']'), uri.Port, code.Length == 0 ? null : code);
    }

    public static void ValidateInviteCode(string? value)
    {
        if (value is not null && !Regex.IsMatch(value, @"\A[A-Za-z0-9_-]{32}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("The invitation code must contain exactly 32 letters, digits, underscores, or hyphens.");
    }

    // Invitations are bearer credentials; diagnostic string conversion must not expose them.
    public override string ToString() => $"wad://{(Host.Contains(':') ? "[" + Host + "]" : Host)}:{Port}";
    internal string ToStringWithInvite() => ToString() + (InviteCode is null ? "" : "/" + InviteCode);
}
