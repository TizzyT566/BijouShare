using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.RateLimiting;
using BijouShare.Shared;

namespace BijouShare.Server;

public static class AdminApi
{
    public sealed record ServerNameUpdate(string Name);
    public sealed record Login(string Name, string Password);
    public sealed record PasswordChange(string CurrentPassword, string NewPassword);
    public sealed record DeviceApproval(Guid[] GroupIds, string Fingerprint);
    public sealed record DeviceUpdate(bool Enabled, Guid[] GroupIds);
    public sealed record InviteCreation(string Name, Guid[] GroupIds, int? MaxUses, DateTimeOffset? ExpiresUtc);
    public sealed record PermissionRuleUpdate(Guid Id, Guid GroupId, Guid ShareId, string Path,
        Permission Allow, Permission Deny, bool Inherit, AccessScope[]? AdditionalScopes = null);
    public sealed record Setup(string ServerName, string AdminName, string Password, string ConfirmPassword);
    public static string CredentialVersion(AdminCredential admin) => Convert.ToHexString(System.Security.Cryptography.SHA3_256.HashData(admin.Hash));
    public static void MapAdminApi(this WebApplication app)
    {
        app.MapGet("/api/session", (HttpContext context, IAntiforgery antiforgery, StateStore store) => Results.Ok(new
        {
            version = typeof(AdminApi).Assembly.GetName().Version!.ToString(3),
            setupRequired = !store.IsInitialized,
            cryptoSuite = Wire.CryptoSuite,
            cryptoProvider = HybridKem.ProviderName,
            cryptoSupported = HybridKem.IsSupported,
            authenticated = context.User.Identity?.IsAuthenticated == true,
            name = context.User.Identity?.Name,
            csrfToken = antiforgery.GetAndStoreTokens(context).RequestToken
        }));
        app.MapPost("/api/setup", (Setup setup, HttpContext context, StateStore store, AuditLog audit) =>
        {
            if (!ServerSetupSecurity.IsLocalRequest(context))
                return Results.Json(new
                {
                    error = "Complete server setup from a browser on this computer."
                }, statusCode: StatusCodes.Status403Forbidden);
            if (store.IsInitialized)
                return Results.Conflict(new
                {
                    error = "Server setup is already complete. Sign in to manage it."
                });
            try
            {
                if (!store.TryCompleteSetup(setup.ServerName, setup.AdminName, setup.Password, setup.ConfirmPassword))
                    return Results.Conflict(new
                    {
                        error = "Server setup is already complete. Sign in to manage it."
                    });
                audit.Write(setup.AdminName, "ServerSetup", setup.ServerName);
                return Results.Ok();
            }
            catch (ArgumentException exception) { return Results.BadRequest(new { error = exception.Message }); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                return Results.BadRequest(new
                {
                    error = "Cannot save server setup. Check the service account and data directory."
                });
            }
        }).RequireRateLimiting("setup");
        app.MapPost("/api/login", async (Login login, HttpContext context, StateStore store, AuditLog audit) =>
        {
            var verified = store.AuthenticateAdmin(login.Name, login.Password);
            if (verified is null)
            {
                audit.Write(login.Name, "AdminLogin", "Web UI", "Denied");
                return Results.Unauthorized();
            }
            // Bind the cookie to the credential actually verified, not a later password-reset snapshot.
            var version = CredentialVersion(verified);
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity([new(ClaimTypes.Name, login.Name), new("credential", version)],
                    CookieAuthenticationDefaults.AuthenticationScheme)));
            audit.Write(login.Name, "AdminLogin", "Web UI");
            return Results.Ok();
        }).RequireRateLimiting("login");
        var api = app.MapGroup("/api").RequireAuthorization();
        api.MapPost("/server/name", (ServerNameUpdate update, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "RenameServer", update.Name, () => { store.RenameServer(update.Name); return true; }));
        api.MapPost("/server/ports", (PortUpdate update, ServerPortSettings ports, HttpContext context) =>
            ports.SaveAsync(update, context));
        api.MapPost("/logout", async (HttpContext context) => { await context.SignOutAsync(); return Results.Ok(); });
        api.MapGet("/state", (StateStore store, AuditLog audit, ServerOptions options, WebPortListener web, HttpContext context) => store.Read(s => Results.Ok(new
        {
            s.ServerName,
            s.ServerId,
            s.ServerPublicKey,
            s.ServerMlKemPublicKey,
            filePort = options.Port,
            webPort = web.CurrentPort,
            webPortEditable = ServerPortSettings.IsDirectWebEndpoint(context, web.CurrentPort),
            storageAccount = FileService.StorageAccount,
            cryptoSuite = Wire.CryptoSuite,
            cryptoProvider = HybridKem.ProviderName,
            cryptoSupported = HybridKem.IsSupported,
            groups = s.Groups.Select(group => new
            {
                group.Id,
                group.Name,
                isAdministrator = group.Id == StateStore.AdministratorGroupId
            }),
            s.Shares,
            s.Rules,
            devices = s.Devices.Select(d => new
            {
                d.Id,
                d.Name,
                d.GroupIds,
                d.Enabled,
                d.PublicIdentity,
                fingerprint = d.PublicIdentity
            }),
            pendingDevices = s.PendingDevices.Select(d => new
            {
                d.Id,
                d.Name,
                d.FirstSeenUtc,
                d.LastSeenUtc,
                d.Rejected,
                d.PublicIdentity,
                fingerprint = d.PublicIdentity
            }),
            invites = s.Invites.Select(invite => new
            {
                invite.Id,
                invite.Name,
                invite.GroupIds,
                invite.MaxUses,
                invite.Uses,
                invite.CreatedUtc,
                invite.ExpiresUtc,
                invite.Revoked
            }),
            permissions = Enum.GetValues<Permission>().Where(p => p != Permission.None && p != Permission.FullControl)
                .Select(p => new { name = p.ToString(), value = (int)p }),
            activity = audit.Recent()
        })));
        api.MapPut("/groups/{id:guid}", (Guid id, AppGroup group, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "Group", group.Name, () => store.Update(s =>
            {
                if (id != group.Id)
                    throw new ArgumentException("ID mismatch.");
                if (id == StateStore.AdministratorGroupId)
                    throw new ArgumentException("The built-in Administrator group cannot be edited.");
                Upsert(s.Groups, group, x => x.Id == id);
                return true;
            })));
        api.MapDelete("/groups/{id:guid}", (Guid id, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "DeleteGroup", id.ToString(), () => store.Update(s =>
            {
                if (id == StateStore.AdministratorGroupId)
                    throw new ArgumentException("The built-in Administrator group cannot be deleted.");
                s.Groups.RemoveAll(x => x.Id == id);
                s.Rules.RemoveAll(x => x.GroupId == id);
                s.Devices = s.Devices.Select(d => d with { GroupIds = d.GroupIds.Where(g => g != id).ToArray() }).ToList();
                s.Invites = s.Invites.Select(invite => invite with { GroupIds = invite.GroupIds.Where(group => group != id).ToArray() }).ToList();
                return true;
            })));
        api.MapPost("/invites", (InviteCreation request, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "CreateInvite", request.Name, () =>
            {
                var created = store.CreateInvite(request.Name, request.GroupIds, request.MaxUses, request.ExpiresUtc?.UtcDateTime);
                var invite = created.Invite;
                context.Response.Headers.CacheControl = "no-store";
                return new
                {
                    invite.Id,
                    code = created.Code,
                    invite.Name,
                    invite.GroupIds,
                    invite.MaxUses,
                    invite.Uses,
                    invite.CreatedUtc,
                    invite.ExpiresUtc,
                    invite.Revoked
                };
            }));
        api.MapDelete("/invites/{id:guid}", (Guid id, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "RevokeInvite", id.ToString(), () => { store.RevokeInvite(id); return true; }));
        api.MapPut("/shares/{id:guid}", (Guid id, ExportShare share, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "Share", share.Name, () => store.Update(s =>
            {
                if (id != share.Id)
                    throw new ArgumentException("ID mismatch.");
                var localPath = ValidateExportPath(share.LocalPath, store.DataDirectory);
                Upsert(s.Shares, share with
                {
                    LocalPath = localPath
                }, x => x.Id == id);
                return true;
            })));
        api.MapDelete("/shares/{id:guid}", (Guid id, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "DeleteShare", id.ToString(), () => store.Update(s =>
            {
                s.Shares.RemoveAll(x => x.Id == id);
                s.Rules.RemoveAll(x => x.ShareId == id);
                return true;
            })));
        api.MapPut("/rules/{id:guid}", (Guid id, PermissionRuleUpdate rule, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "PermissionRule", rule.Path, () => store.Update(s =>
            {
                if (id != rule.Id)
                    throw new ArgumentException("ID mismatch.");
                var existing = s.Rules.Find(entry => entry.Id == id);
                if (rule.AdditionalScopes is null && existing is { AdditionalScopes.Length: > 0 } &&
                    (existing.GroupId != rule.GroupId || existing.ShareId != rule.ShareId))
                    throw new ArgumentException("Include the additional permission paths when moving this rule to another group or share.");
                var scopes = rule.AdditionalScopes ?? existing?.AdditionalScopes ?? [];
                var updated = new AccessRule(id, rule.GroupId, rule.ShareId, StateStore.CanonicalRulePath(s, rule.ShareId, rule.Path),
                    rule.Allow, rule.Deny, rule.Inherit)
                {
                    AdditionalScopes = scopes.Select(scope =>
                    {
                        ArgumentNullException.ThrowIfNull(scope);
                        return scope with { Path = StateStore.CanonicalRulePath(s, rule.ShareId, scope.Path) };
                    }).ToArray()
                };
                Upsert(s.Rules, updated, x => x.Id == id);
                return true;
            })));
        api.MapDelete("/rules/{id:guid}", (Guid id, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "DeletePermissionRule", id.ToString(), () => store.Update(s => { s.Rules.RemoveAll(x => x.Id == id); return true; })));
        api.MapPost("/pending-devices/{id:guid}/approve", (Guid id, DeviceApproval approval, StateStore store,
            AuditLog audit, HttpContext context) => Save(context, audit, "ApproveDevice", id.ToString(), () =>
            {
                store.ApproveDevice(id, approval.GroupIds, approval.Fingerprint);
                return true;
            }));
        api.MapDelete("/pending-devices/{id:guid}", (Guid id, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "RejectDevice", id.ToString(), () => { store.RejectDevice(id); return true; }));
        api.MapPut("/devices/{id:guid}", (Guid id, DeviceUpdate update, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "Device", id.ToString(), () => store.Update(s =>
            {
                var device = s.Devices.SingleOrDefault(x => x.Id == id) ?? throw new ArgumentException("Unknown device.");
                Upsert(s.Devices, device with
                {
                    Enabled = update.Enabled,
                    GroupIds = update.GroupIds
                }, x => x.Id == id);
                return true;
            })));
        api.MapDelete("/devices/{id:guid}", (Guid id, StateStore store, AuditLog audit, HttpContext context) =>
            Save(context, audit, "BlockDevice", id.ToString(), () => store.Update(s =>
            {
                var device = s.Devices.SingleOrDefault(x => x.Id == id) ?? throw new ArgumentException("Unknown device.");
                Upsert(s.Devices, device with
                {
                    Enabled = false
                }, x => x.Id == id);
                return true;
            })));
        api.MapPost("/admin/password", (PasswordChange change, StateStore store, HttpContext context, AuditLog audit) =>
            Save(context, audit, "ChangeAdminPassword", "Administrator", () =>
            {
                store.ChangeAdminPassword(context.User.Identity!.Name!, change.CurrentPassword, change.NewPassword);
                return true;
            }));
    }
    private static void Upsert<T>(List<T> list, T value, Predicate<T> match)
    {
        var index = list.FindIndex(match);
        if (index < 0)
            list.Add(value);
        else
            list[index] = value;
    }
    private static string ValidateExportPath(string path, string dataDirectory)
    {
        var local = StateStore.NormalizeLocalSharePath(path);
        if (!File.Exists(local) && !Directory.Exists(local))
            throw new ArgumentException("The local path does not exist.");
        for (var ancestor = local; !string.IsNullOrEmpty(ancestor); ancestor = Path.GetDirectoryName(ancestor))
            if (WindowsPaths.TryGetAttributes(ancestor, out var attributes) && (attributes & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Choose the actual local path. Reparse points, symbolic links, and junctions cannot be exported.");
        var canonical = WindowsPaths.Canonical(local);
        if (FileService.IsProtectedExportPath(canonical, FileService.ProtectedRoots(dataDirectory)))
            throw new ArgumentException("BijouShare data, client profiles and executable directories cannot be exported.");
        return canonical;
    }
    private static IResult Save<T>(HttpContext context, AuditLog audit, string action, string target, Func<T> save)
    {
        try
        {
            var result = save();
            audit.Write(context.User.Identity!.Name!, action, target);
            return Results.Ok(result);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or System.Security.Cryptography.CryptographicException)
        {
            return Results.BadRequest(new
            {
                error = ex.Message
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Results.BadRequest(new
            {
                error = "Cannot access or persist the server configuration. Check the service account and paths."
            });
        }
    }
}
