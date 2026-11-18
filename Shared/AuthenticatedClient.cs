using System.Net.Sockets;
using System.Security.Cryptography;

namespace BijouShare.Shared;

public sealed class ServerIdentityMismatchException() : CryptographicException(
    "The server public keys do not match the fingerprint in this connection link.");

public static class AuthenticatedClient
{
    public static Task<SecureTransport> ConnectAsync(TcpClient socket, string host, int port, string deviceId,
        byte[] privateKey, HybridKem identityKem, string expectedServerId, CancellationToken token, bool binaryPayloads = true) =>
        ConnectCoreAsync(socket, host, port, deviceId, null, privateKey, identityKem, token, expectedServerId, null, binaryPayloads);

    public static Task<SecureTransport> ConnectDeviceAsync(TcpClient socket, string host, int port, string deviceId,
        string deviceName, byte[] privateKey, HybridKem identityKem, CancellationToken token, string expectedServerId, string? inviteCode = null) =>
        ConnectCoreAsync(socket, host, port, deviceId, deviceName, privateKey, identityKem, token, expectedServerId, inviteCode, true);

    private static async Task<SecureTransport> ConnectCoreAsync(TcpClient socket, string host, int port, string deviceId,
        string? deviceName, byte[] privateKey, HybridKem identityKem, CancellationToken token, string expectedServerId, string? inviteCode, bool binaryPayloads)
    {
        ServerIdentityNaming.ValidateId(expectedServerId);
        if (inviteCode is not null && (inviteCode.Length != 32 || inviteCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))))
            throw new ArgumentException("Invalid invite code format.");
        using var identity = KeyAgreement.ImportPrivate(privateKey);
        var ecPublic = identity.ExportSubjectPublicKeyInfo();
        var kemPublic = identityKem.ExportPublicKey();
        if (DeviceIdentity.Id(ecPublic, kemPublic) != deviceId)
            throw new CryptographicException("Device ID does not match its public keys.");

        socket.NoDelay = true;
        await socket.ConnectAsync(host, port, token);
        var stream = socket.GetStream();
        ServerHello server;
        byte[] material;
        using (var ephemeral = KeyAgreement.NewKey())
        using (var kem = HybridKem.Generate())
        using (var secrets = new HandshakeSecrets())
        {
            var hello = new ClientHello(Wire.Version, deviceId, RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
            {
                CryptoSuite = Wire.CryptoSuite,
                ClientPublicKey = Convert.ToBase64String(ecPublic),
                IdentityMlKemPublicKey = kemPublic,
                MlKemPublicKey = kem.ExportPublicKey(),
                DeviceName = deviceName,
                BinaryPayloads = binaryPayloads,
                InviteEnrollment = inviteCode is not null
            };
            await SecureTransport.WritePlainAsync(stream, hello, token);
            server = await SecureTransport.ReadPlainAsync<ServerHello>(stream, token);
            if (server.Version != Wire.Version || server.CryptoSuite != Wire.CryptoSuite ||
                server.Nonce is not { Length: 32 } || server.GlobalIdentityPublicKey is not { Length: >= 64 and <= 160 } ||
                server.EphemeralPublicKey is not { Length: >= 64 and <= 160 } ||
                server.EphemeralPublicKey.AsSpan().SequenceEqual(server.GlobalIdentityPublicKey) ||
                server.ServerMlKemPublicKey is not { Length: HybridKem.PublicKeySize } ||
                server.IdentityMlKemCiphertext is not { Length: HybridKem.CiphertextSize } ||
                server.MlKemCiphertext is not { Length: HybridKem.CiphertextSize } ||
                server.InviteEnrollment != hello.InviteEnrollment || (server.PendingApproval && deviceName is null))
                throw new CryptographicException("Invalid v6 hybrid server hello.");
            ServerIdentityNaming.ValidateName(server.ServerName);
            if (server.ServerId != expectedServerId || ServerIdentityNaming.Id(server.GlobalIdentityPublicKey, server.ServerMlKemPublicKey) != expectedServerId)
                throw new ServerIdentityMismatchException();

            var (ciphertext, serverKem) = HybridKem.Encapsulate(server.ServerMlKemPublicKey);
            secrets.Keep(serverKem);
            var exchange = new ClientKeyExchange(ciphertext);
            var transcript = KeyAgreement.Transcript(hello, server, exchange);
            var secret = secrets.Keep(KeyAgreement.SessionSecret(
                secrets.Keep(KeyAgreement.Agree(identity, server.GlobalIdentityPublicKey)),
                secrets.Keep(KeyAgreement.Agree(ephemeral, server.EphemeralPublicKey)),
                secrets.Keep(identityKem.Decapsulate(server.IdentityMlKemCiphertext)), serverKem,
                secrets.Keep(kem.Decapsulate(server.MlKemCiphertext))));
            await SecureTransport.WritePlainAsync(stream, exchange, token);
            var confirmation = await SecureTransport.ReadPlainAsync<ServerProof>(stream, token);
            if (!KeyAgreement.Equals(KeyAgreement.Proof(secret, transcript, "server"), confirmation.Proof))
                throw new CryptographicException("Server hybrid key confirmation failed.");
            await SecureTransport.WritePlainAsync(stream, new ClientProof(KeyAgreement.Proof(secret, transcript, "client")), token);
            material = KeyAgreement.SessionMaterial(secret, transcript);
        }

        SecureTransport transport;
        try { transport = new SecureTransport(stream, material, false, binaryPayloads); }
        finally { CryptographicOperations.ZeroMemory(material); }
        try
        {
            if (inviteCode is not null)
                await transport.SendAsync(new RpcRequest { Operation = "Enroll", InviteCode = inviteCode }, token);
            var ready = await transport.ReceiveAsync<RpcResponse>(token);
            if (ready.Error is not null)
                throw new RemoteException(ready.Error);
            if (server.PendingApproval && inviteCode is null)
                throw new CryptographicException("Unapproved device cannot start a file session.");
            var name = ready.DeviceName ?? ready.UserName;
            if (string.IsNullOrWhiteSpace(name) || name.Length > 100)
                throw new CryptographicException("Invalid device name in session confirmation.");
            transport.RemoteDeviceName = name;
            transport.RemoteUserName = ready.UserName ?? name;
            transport.RemoteIdentityPublicKey = server.GlobalIdentityPublicKey;
            transport.RemoteServerId = expectedServerId;
            transport.RemoteServerName = server.ServerName;
            transport.RemoteServerIdentityPublicKey = server.GlobalIdentityPublicKey;
            transport.RemoteServerMlKemPublicKey = server.ServerMlKemPublicKey;
            return transport;
        }
        catch { transport.Dispose(); throw; }
    }
}
