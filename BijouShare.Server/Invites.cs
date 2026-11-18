using System.Security.Cryptography;
using System.Text;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed record InviteCode(Guid Id, string Name, Guid[] GroupIds, string CodeHash, int? MaxUses,
    long Uses, DateTime CreatedUtc, DateTime? ExpiresUtc, bool Revoked = false);
public sealed record CreatedInvite(InviteCode Invite, string Code);

public sealed partial class StateStore
{
    public CreatedInvite CreateInvite(string name, Guid[] groupIds, int? maxUses, DateTime? expiresUtc)
    {
        ValidateName(name);
        ArgumentNullException.ThrowIfNull(groupIds);
        if (maxUses is <= 0 or > 1_000_000)
            throw new ArgumentException("Invite use limits must be between 1 and 1000000, or unlimited.");
        if (expiresUtc is { } expiry && (expiry.Kind != DateTimeKind.Utc || expiry <= DateTime.UtcNow))
            throw new ArgumentException("The invite expiration must be a future UTC date, or never.");
        var code = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_');
        var created = DateTime.UtcNow;
        var invite = new InviteCode(Guid.NewGuid(), name, groupIds.ToArray(), HashInvite(code), maxUses, 0, created, expiresUtc);
        return Update(s =>
        {
            ValidateInviteGroups(s, invite.GroupIds);
            if (s.Invites.Count >= 1024 || s.Invites.Count(item => IsUsable(item, created)) >= 256)
                throw new ArgumentException("The invite limit has been reached (256 active, 1024 total).");
            s.Invites.Add(invite);
            return new CreatedInvite(invite, code);
        });
    }

    public void RevokeInvite(Guid id) => Update(s =>
    {
        var index = s.Invites.FindIndex(invite => invite.Id == id);
        if (index < 0)
            throw new ArgumentException("Unknown invite.");
        s.Invites[index] = s.Invites[index] with
        {
            Revoked = true
        };
        return true;
    });

    // The handshake proves both private identity keys before an invite can be redeemed.
    public Device RedeemInvite(EnrollmentRequest request, string? code)
    {
        var binding = ValidateRegistration(request);
        gate.EnterWriteLock();
        try
        {
            EnsureIdentityAvailable(state, binding);
            if (state.Devices.SingleOrDefault(device => device.PublicIdentity == binding.Digest) is { } registered)
                return registered.Enabled ? registered : throw new RemoteException("DeviceBlocked");
            var pending = state.PendingDevices.SingleOrDefault(d => d.ClientPublicKey == binding.Ecdh);
            if (pending?.Rejected == true)
                throw new RemoteException("DeviceRejected");
            if (!IsCode(code))
                throw new RemoteException("InvalidInvite");
            var hash = HashInvite(code!);
            var invite = state.Invites.SingleOrDefault(item => item.CodeHash == hash);
            if (invite is null || !IsUsable(invite, DateTime.UtcNow))
                throw new RemoteException("InvalidInvite");
            return Update(s =>
            {
                var device = CompleteEnrollment(s, binding, request.DeviceName, invite.GroupIds);
                var index = s.Invites.FindIndex(item => item.Id == invite.Id);
                s.Invites[index] = s.Invites[index] with
                {
                    Uses = checked(invite.Uses + 1)
                };
                return device;
            });
        }
        finally { gate.ExitWriteLock(); }
    }

    private static bool IsUsable(InviteCode invite, DateTime now) => !invite.Revoked &&
        !invite.GroupIds.Contains(AdministratorGroupId) &&
        (invite.ExpiresUtc is null || invite.ExpiresUtc > now) && (invite.MaxUses is null || invite.Uses < invite.MaxUses);
    private static bool IsCode(string? code) => code is { Length: 32 } &&
        code.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    private static string HashInvite(string code) => Convert.ToHexStringLower(SHA3_256.HashData(Encoding.ASCII.GetBytes(code)));

    private static void ValidateInviteGroups(ServerState state, Guid[] groupIds)
    {
        ValidateGroups(state, groupIds);
        if (groupIds.Contains(AdministratorGroupId))
            throw new ArgumentException("Invites cannot grant membership in the Administrator group. Assign it directly to an approved device.");
    }

    private static void ValidateInvites(ServerState state)
    {
        if (state.Invites is null || state.Invites.Count > 1024 || state.Invites.Any(invite => invite is null) ||
            state.Invites.Select(invite => invite.Id).Distinct().Count() != state.Invites.Count ||
            state.Invites.Select(invite => invite.CodeHash).Distinct(StringComparer.Ordinal).Count() != state.Invites.Count)
            throw new ArgumentException("Invalid invite collection.");
        foreach (var invite in state.Invites)
        {
            ValidateName(invite.Name);
            ValidateInviteGroups(state, invite.GroupIds);
            if (invite.Id == Guid.Empty || invite.CodeHash is not { Length: 64 } || invite.CodeHash.Any(character => !char.IsAsciiHexDigitLower(character)) ||
                invite.Uses < 0 || invite.MaxUses is <= 0 or > 1_000_000 || invite.MaxUses is { } limit && invite.Uses > limit ||
                invite.CreatedUtc.Kind != DateTimeKind.Utc || invite.ExpiresUtc is { Kind: not DateTimeKind.Utc })
                throw new ArgumentException("Invalid invite metadata.");
        }
    }
}
