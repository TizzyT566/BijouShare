using System.Net;
using System.Net.Sockets;
using BijouShare.Shared;

namespace BijouShare.Server;

public sealed record NetworkServiceShare(Guid Id, string Name, string Host, int Port, NetworkServiceProtocol Protocol, bool Enabled);
internal sealed record NetworkServiceTarget(string Host, int Port, NetworkServiceAccess Permissions);

public sealed partial class StateStore
{
    internal static bool IsUnicastServiceAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => address.GetAddressBytes()[0] is > 0 and < 224,
            AddressFamily.InterNetworkV6 => !address.IsIPv6Multicast && address.GetAddressBytes().AsSpan().ContainsAnyExcept((byte)0),
            _ => false
        };
    }

    private static void ValidateNetworkService(NetworkServiceShare service)
    {
        ValidateName(service.Name);
        if (service.Id == Guid.Empty || service.Id == AllSharesId)
            throw new ArgumentException("Choose a unique network service ID.");
        if (service.Protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp or NetworkServiceProtocol.Both))
            throw new ArgumentException("Choose TCP, UDP, or both.");
        if (service.Port is < 1 or > 65535)
            throw new ArgumentException("The destination port must be between 1 and 65535.");
        var host = service.Host;
        if (!string.IsNullOrWhiteSpace(host) && host.Length <= 254 && host == host.Trim())
        {
            if (IPAddress.TryParse(host, out var address))
            {
                if (IsUnicastServiceAddress(address)) return;
            }
            else
            {
                var name = host.EndsWith('.') ? host[..^1] : host;
                if (name.Length <= 253 && name.Split('.').All(label =>
                        label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' &&
                        label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')))
                    return;
            }
        }
        throw new ArgumentException("Enter one destination hostname or unicast IP address, without a scheme, port, or path.");
    }

    private static Device CurrentNetworkDevice(ServerState state, Device authenticated)
    {
        var current = state.Devices.Find(d => d.Id == authenticated.Id);
        if (current is not { Enabled: true } || !current.HasSameIdentity(authenticated))
            throw new UnauthorizedAccessException();
        return current;
    }

    private static NetworkServiceAccess NetworkAccess(ServerState state, Device current, Guid shareId)
    {
        var allow = current.GroupIds.Contains(AdministratorGroupId) ? NetworkServiceAccess.Both : NetworkServiceAccess.None;
        var deny = NetworkServiceAccess.None;
        foreach (var rule in state.Rules)
        {
            if (!rule.AppliesToShare(shareId) || !current.GroupIds.Contains(rule.GroupId)) continue;
            allow |= rule.NetworkAllow;
            deny |= rule.NetworkDeny;
        }
        return allow & ~deny;
    }

    internal NetworkServiceDescriptor[] ListNetworkServices(Device authenticated) => Read(state =>
    {
        var current = CurrentNetworkDevice(state, authenticated);
        return state.NetworkServices.Where(service => service.Enabled)
            .Select(service => new NetworkServiceDescriptor(service.Id, service.Name, service.Protocol, service.Port, NetworkAccess(state, current, service.Id)))
            .Where(service => service.Access != NetworkServiceAccess.None).ToArray();
    });

    internal NetworkServiceTarget AuthorizeNetworkService(Device authenticated, Guid shareId, NetworkServiceProtocol protocol) => Read(state =>
    {
        var current = CurrentNetworkDevice(state, authenticated);
        var service = state.NetworkServices.Find(s => s.Id == shareId && s.Enabled);
        if (service is null || protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp) || (service.Protocol & protocol) == 0)
            throw new UnauthorizedAccessException();
        var access = NetworkAccess(state, current, service.Id);
        if (access == NetworkServiceAccess.None) throw new UnauthorizedAccessException();
        return new NetworkServiceTarget(service.Host, service.Port, access);
    });
}
