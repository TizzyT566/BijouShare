using System.Text.Json.Serialization;
using BijouShare.Shared;

namespace BijouShare.Client;

internal sealed record NetworkListenerSetting(string ServerId, Guid ShareId, string ServerName,
    string Name, NetworkServiceProtocol Protocol, int SuggestedPort, int LocalPort);

public sealed partial class ClientSettings
{
    internal const int MaximumNetworkListeners = 64;
    [JsonInclude] private List<NetworkListenerSetting> NetworkListeners { get; set; } = [];

    internal NetworkListenerSetting[] NetworkListenerSnapshot()
    {
        lock (persistenceGate) return NetworkListeners.ToArray();
    }

    internal void ChangeNetworkListener(string serverId, Guid shareId, NetworkListenerSetting? setting)
    {
        lock (persistenceGate)
        {
            var previous = NetworkListeners;
            NetworkListeners = previous.Where(s => s.ServerId != serverId || s.ShareId != shareId).ToList();
            if (setting is not null) NetworkListeners.Add(setting);
            try { PersistChange(); }
            catch { NetworkListeners = previous; throw; }
        }
    }

    private void ValidateNetworkListeners()
    {
        if (NetworkListeners is null || NetworkListeners.Count > MaximumNetworkListeners)
            throw new InvalidDataException($"A Windows profile can enable up to {MaximumNetworkListeners} network services.");
        var keys = new HashSet<(string, Guid)>();
        foreach (var listener in NetworkListeners)
        {
            if (listener is null || listener.ShareId == Guid.Empty || !keys.Add((listener.ServerId, listener.ShareId)) ||
                !Enum.IsDefined(listener.Protocol) || listener.SuggestedPort is < 1 or > 65535 || listener.LocalPort is < 1 or > 65535)
                throw new InvalidDataException("Invalid or duplicate network service listener.");
            ServerIdentityNaming.ValidateId(listener.ServerId);
            ValidateName(listener.ServerName, "server name");
            ValidateName(listener.Name, "network service name");
        }
    }
}
