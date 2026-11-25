using BijouShare.Shared;

namespace BijouShare.Server;

internal static class NetworkServicePolicySelfTests
{
    internal static void Run(StateStore store, AppGroup group, Device device, Action<bool, string> check, Action<Action, string> reject)
    {
        var service = new NetworkServiceShare(Guid.NewGuid(), "Printer", "printer.home.arpa", 9100, NetworkServiceProtocol.Tcp, true);
        void Add(NetworkServiceShare share) => store.Update(s => { s.NetworkServices.Add(share); return true; });
        Add(service);
        check(store.ListNetworkServices(device).Length == 0 && store.Permissions(device, service.Id, "") == Permission.None,
            "File permissions and file enumeration do not expose a network service");
        foreach (var invalid in new[] { "0.0.0.0", "::", "255.255.255.255", "::ffff:239.1.2.3", "ff02::1", "10.0.0.0/24", "https://printer", "printer:80" })
            reject(() => Add(service with { Id = Guid.NewGuid(), Name = "Other", Host = invalid }), "Invalid network service destination rejected: " + invalid);
        reject(() => Add(service with { Id = Guid.NewGuid(), Name = "Other", Port = 0 }), "Network service requires a concrete destination port");
        reject(() => Add(service with { Id = Guid.NewGuid(), Name = "Other", Protocol = (NetworkServiceProtocol)4 }), "Network service rejects unknown protocol bits");
        reject(() => Add(service with { Id = StateStore.AllSharesId, Name = "Other" }), "Network service cannot replace built-in All");
        var targetRule = new AccessRule(Guid.NewGuid(), group.Id, service.Id, "", Permission.None, Permission.None, false)
        {
            NetworkAllow = NetworkServiceAccess.Receive, NetworkDeny = NetworkServiceAccess.Send
        };
        store.Update(s =>
        {
            var all = s.Rules.FindIndex(r => r.GroupId == group.Id && r.ShareId == StateStore.AllSharesId);
            s.Rules[all] = s.Rules[all] with { NetworkAllow = NetworkServiceAccess.Both };
            s.Rules.Add(targetRule);
            return true;
        });
        var descriptor = store.ListNetworkServices(device).Single();
        var target = store.AuthorizeNetworkService(device, service.Id, NetworkServiceProtocol.Tcp);
        check(descriptor.Id == service.Id && descriptor.Access == NetworkServiceAccess.Receive &&
            target == new NetworkServiceTarget(service.Host, service.Port, NetworkServiceAccess.Receive),
            "Specific network denies take precedence over All and only the configured endpoint is authorized");
        var next = service with { Id = Guid.NewGuid(), Name = "Camera", Protocol = NetworkServiceProtocol.Both };
        Add(next);
        check(store.AuthorizeNetworkService(device, next.Id, NetworkServiceProtocol.Udp).Permissions == NetworkServiceAccess.Both,
            "Wildcard network permissions apply to future shares in either configured protocol");
        store.Update(s => { s.Devices[0] = device with { GroupIds = [group.Id, StateStore.AdministratorGroupId] }; return true; });
        check(store.AuthorizeNetworkService(device, service.Id, NetworkServiceProtocol.Tcp).Permissions == NetworkServiceAccess.Receive,
            "Administrator honors an explicit network deny from another group");
        void Denied(Action action, string label)
        {
            try { action(); }
            catch (UnauthorizedAccessException) { check(true, label); return; }
            check(false, label);
        }
        Denied(() => store.AuthorizeNetworkService(device, service.Id, NetworkServiceProtocol.Udp), "A TCP-only share rejects a UDP connection");
        Denied(() => store.ListNetworkServices(device with { EnrollmentId = Guid.NewGuid() }), "A stale network enrollment cannot list services");
        reject(() => store.Update(s => { s.Rules.Add(targetRule with { Id = Guid.NewGuid() }); return true; }), "Duplicate network group assignments are rejected");
        reject(() => store.Update(s => { s.Rules[^1] = targetRule with { Allow = Permission.ReadData }; return true; }), "File rights cannot be assigned to a network service");
        reject(() => store.Update(s => { s.Rules[^1] = targetRule with { NetworkAllow = NetworkServiceAccess.Send }; return true; }), "A network direction cannot be both allowed and denied in one assignment");
        store.Update(s => { s.NetworkServices[0] = service with { Enabled = false }; return true; });
        Denied(() => store.AuthorizeNetworkService(device, service.Id, NetworkServiceProtocol.Tcp), "Disabling a network service revokes existing authorizations");
        store.Update(s => { s.Devices[0] = device with { GroupIds = [] }; return true; });
        check(store.ListNetworkServices(device).Length == 0, "An existing session uses current network group memberships");
    }
}
