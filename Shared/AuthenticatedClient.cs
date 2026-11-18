using System.Net.Sockets;
using System.Security.Cryptography;

namespace BijouShare.Shared;

public sealed class ServerIdentityMismatchException() : CryptographicException(
    "The server identity changed. Verify the server, then explicitly reset server trust if this change was intended.");

public static class AuthenticatedClient
{
    // Pinned-identity convenience overload; it uses the same mandatory hybrid v3 handshake.
    public static Task<SecureTransport> ConnectAsync(TcpClient socket, string host, int port,
        string deviceId, byte[] privateKey, byte[] pinnedServerPublicKey, CancellationToken token, bool binaryPayloads = true) =>
        ConnectCoreAsync(socket, host, port, deviceId, null, privateKey, pinnedServerPublicKey, token, binaryPayloads);

    public static Task<SecureTransport> ConnectDeviceAsync(TcpClient socket, string host, int port,
        string deviceId, string deviceName, byte[] privateKey, byte[]? pinnedServerPublicKey, CancellationToken token, byte[]? pinnedServerIdentityPublicKey = null, string? inviteCode = null) =>
        ConnectCoreAsync(socket, host, port, deviceId, deviceName, privateKey, pinnedServerPublicKey, token, true, pinnedServerIdentityPublicKey, inviteCode);

    private static async Task<SecureTransport> ConnectCoreAsync(TcpClient socket, string host, int port,
        string deviceId, string? deviceName, byte[] privateKey, byte[]? pinnedServerPublicKey, CancellationToken token, bool binaryPayloads, byte[]? pinnedServerIdentityPublicKey = null, string? inviteCode = null)
    {
        if (inviteCode is not null && (inviteCode.Length != 32 || inviteCode.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))))
            throw new ArgumentException("Invalid invite code format.");
        HybridKem.EnsureSupported();
        await socket.ConnectAsync(host, port, token);
        using var kem = HybridKem.Generate();
        socket.NoDelay = true;
        var stream = socket.GetStream();
        using var identity = KeyAgreement.ImportPrivate(privateKey);
        using var ephemeral = KeyAgreement.NewKey();
        var registering = deviceName is not null;
        var hello = new ClientHello(Wire.Version, deviceId, RandomNumberGenerator.GetBytes(32), ephemeral.ExportSubjectPublicKeyInfo())
        {
            CryptoSuite = Wire.CryptoSuite,
            MlKemPublicKey = kem.ExportPublicKey(),
            InviteEnrollment = inviteCode is not null,
            BinaryPayloads = binaryPayloads,
            ServerIdentityMetadata = registering,
            DeviceName = deviceName,
            ClientPublicKey = registering ? Convert.ToBase64String(identity.ExportSubjectPublicKeyInfo()) : null
        };
        await SecureTransport.WritePlainAsync(stream, hello, token);
        var server = await SecureTransport.ReadPlainAsync<ServerHello>(stream, token);
        if (server.Version != Wire.Version || server.CryptoSuite != Wire.CryptoSuite ||
            server.MlKemCiphertext is not { Length: HybridKem.CiphertextSize } ||
            server.EphemeralPublicKey is not { Length: >= 64 and <= 160 } ||
            server.Nonce is not { Length: 32 } || server.Proof is not { Length: 32 })
            throw new CryptographicException("The server did not provide the required ECDH + ML-KEM-768 hybrid challenge.");
        if (hello.InviteEnrollment && !server.InviteEnrollment)
            throw new RemoteException("InviteUnsupported");
        if (hello.ServerIdentityMetadata)
        {
            if (server.ServerId is not { } id || server.GlobalIdentityPublicKey is not { Length: > 0 and <= 160 } ||
                server.ServerIdentityProof is not { Length: 32 })
                throw new CryptographicException("This server does not provide a persistent server identity.");
            try
            {
                ServerIdentityNaming.ValidateName(server.ServerName);
                ServerIdentityNaming.ValidateId(id);
                if (ServerIdentityNaming.Id(server.ServerName!, server.GlobalIdentityPublicKey) != id)
                    throw new CryptographicException("The server ID does not match its name and public key.");
                if (pinnedServerIdentityPublicKey is not null && !KeyAgreement.Equals(pinnedServerIdentityPublicKey, server.GlobalIdentityPublicKey))
                    throw new ServerIdentityMismatchException();
            }
            catch (ArgumentException ex) { throw new CryptographicException("Invalid server identity metadata.", ex); }
        }
        byte[] serverIdentity;
        if (registering)
        {
            if (server.IdentityPublicKey is not { Length: > 0 and <= 160 })
                throw new CryptographicException("This server does not support automatic device approval.");
            using var publicKey = KeyAgreement.ImportPublic(server.IdentityPublicKey);
            serverIdentity = publicKey.ExportSubjectPublicKeyInfo();
            if (server.PendingApproval)
            {
                if (!KeyAgreement.Equals(serverIdentity, server.EphemeralPublicKey))
                    throw new CryptographicException("Invalid pending-device challenge.");
            }
            else if (pinnedServerPublicKey is { Length: > 0 } && !KeyAgreement.Equals(pinnedServerPublicKey, serverIdentity))
                throw new ServerIdentityMismatchException();
        }
        else
            serverIdentity = pinnedServerPublicKey ?? throw new CryptographicException("Missing pinned server identity.");
        var identitySecret = KeyAgreement.Agree(identity, serverIdentity);
        byte[]? ephemeralSecret = null;
        byte[]? kemSecret = null;
        byte[] material;
        try
        {
            ephemeralSecret = KeyAgreement.Agree(ephemeral, server.EphemeralPublicKey);
            kemSecret = kem.Decapsulate(server.MlKemCiphertext);
            var transcript = KeyAgreement.Transcript(hello, server, serverIdentity);
            if (!KeyAgreement.Equals(KeyAgreement.HybridProof(identitySecret, ephemeralSecret, kemSecret, transcript, "server"), server.Proof))
                throw new CryptographicException("Server key authentication failed.");
            if (hello.ServerIdentityMetadata)
            {
                var globalSecret = KeyAgreement.Agree(identity, server.GlobalIdentityPublicKey!);
                try
                {
                    if (!KeyAgreement.Equals(KeyAgreement.HybridProof(globalSecret, ephemeralSecret, kemSecret, transcript, "server-identity"), server.ServerIdentityProof))
                        throw new CryptographicException("Server global identity authentication failed.");
                }
                finally { CryptographicOperations.ZeroMemory(globalSecret); }
            }
            await SecureTransport.WritePlainAsync(stream, new ClientProof(KeyAgreement.HybridProof(identitySecret, ephemeralSecret, kemSecret, transcript, "client")), token);
            material = KeyAgreement.SessionMaterial(identitySecret, ephemeralSecret, kemSecret, transcript);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identitySecret);
            if (ephemeralSecret is not null)
                CryptographicOperations.ZeroMemory(ephemeralSecret);
            if (kemSecret is not null)
                CryptographicOperations.ZeroMemory(kemSecret);
        }
        SecureTransport transport;
        try
        {
            transport = new SecureTransport(stream, material, false, binaryPayloads);
        }
        finally { CryptographicOperations.ZeroMemory(material); }
        try
        {
            if (hello.InviteEnrollment)
                await transport.SendAsync(new RpcRequest { Operation = "Enroll", InviteCode = inviteCode }, token);
            var ready = await transport.ReceiveAsync<RpcResponse>(token);
            if (server.PendingApproval)
            {
                if (hello.InviteEnrollment && ready.Error is null && ready.EnrollmentServerPublicKey is { Length: > 0 and <= 256 } enrolledKey)
                {
                    using var approved = KeyAgreement.ImportPublic(Convert.FromBase64String(enrolledKey));
                    serverIdentity = approved.ExportSubjectPublicKeyInfo();
                    if (enrolledKey != Convert.ToBase64String(serverIdentity))
                        throw new CryptographicException("Invalid enrolled server identity.");
                    if (pinnedServerPublicKey is { Length: > 0 } && !KeyAgreement.Equals(pinnedServerPublicKey, serverIdentity))
                        throw new ServerIdentityMismatchException();
                }
                else
                {
                    if (!registering || ready.Error is not ("PendingApproval" or "DeviceRejected" or "DeviceBlocked" or "InvalidInvite"))
                        throw new CryptographicException("Invalid pending-device result.");
                    throw new RemoteException(ready.Error);
                }
            }
            if (ready.Error is not null)
                throw new RemoteException(ready.Error);
            var remoteName = ready.DeviceName ?? ready.UserName;
            if (string.IsNullOrWhiteSpace(remoteName) || remoteName.Length > 100)
                throw new CryptographicException("Session rejected.");
            transport.RemoteDeviceName = remoteName;
            transport.RemoteUserName = ready.UserName ?? remoteName;
            transport.RemoteIdentityPublicKey = serverIdentity;
            if (hello.ServerIdentityMetadata)
            {
                transport.RemoteServerId = server.ServerId;
                transport.RemoteServerName = server.ServerName;
                transport.RemoteServerIdentityPublicKey = server.GlobalIdentityPublicKey;
            }
            return transport;
        }
        catch { transport.Dispose(); throw; }
    }
}
