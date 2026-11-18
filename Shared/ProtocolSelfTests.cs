using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BijouShare.Shared;

public static class ProtocolSelfTests
{
    public static async Task<int> RunAsync()
    {
        var count = 0;
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        using var client = KeyAgreement.NewKey();
        using var server = KeyAgreement.NewKey();
        var a = KeyAgreement.Agree(client, server.ExportSubjectPublicKeyInfo());
        var b = KeyAgreement.Agree(server, client.ExportSubjectPublicKeyInfo());
        Check(KeyAgreement.Equals(a, b), "ECDH peers derive the same identity secret");
        using var wrong = KeyAgreement.NewKey();
        Check(!KeyAgreement.Equals(a, KeyAgreement.Agree(wrong, server.ExportSubjectPublicKeyInfo())), "A different device cannot derive that secret");
        var transcript = RandomNumberGenerator.GetBytes(32);
        var serverProof = KeyAgreement.Proof(a, transcript, "server");
        Check(!KeyAgreement.Equals(serverProof, KeyAgreement.Proof(a, transcript, "client")), "Mutual proofs are bound to different roles");
        Check(!KeyAgreement.Equals(serverProof, KeyAgreement.Proof(a, RandomNumberGenerator.GetBytes(32), "server")), "Handshake replay fails with a fresh challenge");
        using var p384 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        try
        {
            using var invalid = KeyAgreement.ImportPublic(p384.ExportSubjectPublicKeyInfo());
            throw new Exception("Accepted P-384");
        }
        catch (CryptographicException) { Check(true, "Non-P-256 public keys are rejected"); }
        var kemSecret = RandomNumberGenerator.GetBytes(HybridKem.SharedSecretSize);
        var material = KeyAgreement.SessionMaterial(a, b, kemSecret, transcript);
        var other = KeyAgreement.SessionMaterial(a, b, kemSecret, RandomNumberGenerator.GetBytes(32));
        CryptographicOperations.ZeroMemory(kemSecret);
        Check(!KeyAgreement.Equals(material, other), "Fresh challenges produce different traffic keys");
        var stream = new MemoryStream();
        using var sender = new SecureTransport(stream, material, false);
        await sender.SendAsync(new RpcRequest { Operation = "Write", Data = [1, 2, 3], Offset = 123 }, CancellationToken.None);
        var frame = stream.ToArray();
        using (var input = new MemoryStream(frame))
        using (var receiver = new SecureTransport(input, material, true))
        {
            var decoded = await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
            Check(decoded.Offset == 123 && decoded.Data!.SequenceEqual(new byte[] { 1, 2, 3 }), "AES-GCM frames round-trip with independent directional keys");
        }
        var tampered = frame.ToArray();
        tampered[^1] ^= 1;
        await Reject(tampered, material, "Modified ciphertext is rejected", Check);
        await Reject(frame, other, "Incorrect session keys are rejected", Check);
        using (var input = new MemoryStream([.. frame, .. frame]))
        using (var receiver = new SecureTransport(input, material, true))
        {
            await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
            try
            {
                await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
                throw new Exception("Accepted replay");
            }
            catch (CryptographicException) { Check(true, "Replayed encrypted frames fail sequence authentication"); }
        }
        var oversized = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(oversized, Wire.MaxFrame + 1);
        using (var input = new MemoryStream(oversized))
        using (var receiver = new SecureTransport(input, material, true))
        {
            try
            {
                await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
                throw new Exception("Accepted oversized frame");
            }
            catch (InvalidDataException) { Check(true, "Oversized frames are rejected before allocation"); }
        }
        using (var output = new YieldingWriteStream())
        using (var concurrentSender = new SecureTransport(output, material, false))
        {
            await Task.WhenAll(Enumerable.Range(0, 24).Select(i => concurrentSender.SendAsync(new RpcRequest { Offset = i }, CancellationToken.None)));
            using var input = new MemoryStream(output.Bytes);
            using var receiver = new SecureTransport(input, material, true);
            var offsets = new HashSet<long>();
            for (var i = 0; i < 24; i++)
                offsets.Add((await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None)).Offset);
            Check(offsets.Count == 24 && offsets.Min() == 0 && offsets.Max() == 23, "Concurrent sends retain unique nonces and complete frame boundaries");
        }
        using (var input = new MemoryStream(tampered))
        using (var receiver = new SecureTransport(input, material, true))
        {
            try
            {
                await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
            }
            catch (CryptographicException) { }
            try
            {
                await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
                throw new Exception("Reused failed transport");
            }
            catch (ObjectDisposedException) { Check(true, "An authentication failure permanently closes the transport"); }
        }
        using (var input = new MemoryStream(frame[..^1]))
        using (var receiver = new SecureTransport(input, material, true))
        {
            try
            {
                await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
                throw new Exception("Accepted truncated frame");
            }
            catch (EndOfStreamException) { Check(true, "Truncated frames are rejected without partial plaintext"); }
        }
        using (var output = new MemoryStream())
        {
            try
            {
                await SecureTransport.WritePlainAsync(output, new
                {
                    text = new string('x', 8192)
                }, CancellationToken.None);
                throw new Exception("Accepted oversized handshake");
            }
            catch (InvalidDataException) { Check(output.Length == 0, "Oversized outbound handshakes fail before writing"); }
        }
        using (var input = new MemoryStream())
        {
            try
            {
                using var invalid = new SecureTransport(input, new byte[71], true);
                throw new Exception("Accepted invalid key material");
            }
            catch (ArgumentException) { Check(true, "Transport key material has an explicit fixed length"); }
        }
        var legacyHello = new ClientHello(Wire.Version, Guid.NewGuid().ToString(), new byte[32], client.ExportSubjectPublicKeyInfo());
        Check(!System.Text.Encoding.UTF8.GetString(Wire.Encode(legacyHello)).Contains("binaryPayloads", StringComparison.Ordinal),
            "Default payload encoding flags are omitted consistently");
        Check(!KeyAgreement.Equals(KeyAgreement.Transcript(legacyHello, new ServerHello(new byte[32], [], []), []),
            KeyAgreement.Transcript(legacyHello with
            {
                BinaryPayloads = true
            }, new ServerHello(new byte[32], [], []), [])),
            "Binary transfer negotiation is bound to the authenticated transcript");
        var metadataHello = legacyHello with
        {
            ServerIdentityMetadata = true,
            DeviceName = "Device",
            ClientPublicKey = Convert.ToBase64String(client.ExportSubjectPublicKeyInfo())
        };
        var metadataServer = new ServerHello(new byte[32], [], []) { ServerId = ServerIdentityNaming.Id("DarkArchives", server.ExportSubjectPublicKeyInfo()), ServerName = "DarkArchives", GlobalIdentityPublicKey = server.ExportSubjectPublicKeyInfo() };
        var metadataTranscript = KeyAgreement.Transcript(metadataHello, metadataServer, []);
        Check(!KeyAgreement.Equals(metadataTranscript, KeyAgreement.Transcript(metadataHello, metadataServer with
        {
            ServerName = "OtherServer"
        }, [])),
            "Server folder names are authenticated in the handshake transcript");
        Check(!KeyAgreement.Equals(metadataTranscript, KeyAgreement.Transcript(metadataHello, metadataServer with
        {
            ServerId = ServerIdentityNaming.Id("DarkArchives", wrong.ExportSubjectPublicKeyInfo())
        }, [])),
            "Persistent server IDs are authenticated in the handshake transcript");
        Check(!KeyAgreement.Equals(metadataTranscript, KeyAgreement.Transcript(metadataHello, metadataServer with
        {
            GlobalIdentityPublicKey = wrong.ExportSubjectPublicKeyInfo()
        }, [])),
            "The public key defining the server ID is authenticated in the handshake transcript");
        Check(!System.Text.Encoding.UTF8.GetString(Wire.Encode(legacyHello)).Contains("serverIdentityMetadata", StringComparison.Ordinal),
            "Default server metadata flags are omitted consistently");
        Check(!System.Text.Encoding.UTF8.GetString(Wire.Encode(metadataHello)).Contains("inviteEnrollment", StringComparison.Ordinal),
            "Ordinary handshakes omit invite enrollment to preserve existing transcript compatibility");
        var inviteHello = metadataHello with
        {
            InviteEnrollment = true
        };
        var inviteTranscript = KeyAgreement.Transcript(inviteHello, metadataServer with
        {
            InviteEnrollment = true
        }, []);
        Check(!KeyAgreement.Equals(inviteTranscript, KeyAgreement.Transcript(inviteHello, metadataServer, [])),
            "Invite support acknowledgement is bound to the authenticated transcript");
        using (var encryptedInvite = new MemoryStream())
        {
            const string bearerCode = "aBcdEfgHijkLmnOpqRstUvwxYz012345";
            using var encryptedSender = new SecureTransport(encryptedInvite, material, false, true);
            await encryptedSender.SendAsync(new RpcRequest { Operation = "Enroll", InviteCode = bearerCode }, CancellationToken.None);
            var encryptedBytes = encryptedInvite.ToArray();
            Check(!System.Text.Encoding.UTF8.GetString(encryptedBytes).Contains(bearerCode, StringComparison.Ordinal),
                "Invite bearer codes are encrypted inside AES-GCM frames");
            using var encryptedInput = new MemoryStream(encryptedBytes);
            using var encryptedReceiver = new SecureTransport(encryptedInput, material, true, true);
            var enrollment = await encryptedReceiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
            Check(enrollment.Operation == "Enroll" && enrollment.InviteCode == bearerCode,
                "Encrypted invite enrollment metadata round-trips through the binary transport");
            try
            {
                enrollment.Validate();
                throw new InvalidOperationException("Enrollment was accepted as a file RPC.");
            }
            catch (ArgumentException) { Check(true, "Invite enrollment cannot be replayed as an ordinary file RPC"); }
        }
        foreach (var size in new[] { 0, 3, Wire.MaxChunk })
        {
            var payload = RandomNumberGenerator.GetBytes(size);
            using var output = new MemoryStream();
            using var binarySender = new SecureTransport(output, material, false, true);
            await binarySender.SendAsync(new RpcRequest { Operation = "Write", RequestId = 19, Data = payload }, CancellationToken.None);
            var encrypted = output.ToArray();
            using var input = new MemoryStream(encrypted);
            using var binaryReceiver = new SecureTransport(input, material, true, true);
            var decoded = await binaryReceiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
            try
            {
                decoded.Validate();
                Check(decoded.RequestId == 19 && decoded.DataCount == size &&
                    decoded.Data!.AsSpan(decoded.DataOffset, decoded.DataCount).SequenceEqual(payload),
                    $"Encrypted binary payload round-trips {size} bytes with exact bounds");
            }
            finally { decoded.ReleasePayload(); }
            encrypted[^1] ^= 1;
            using var corrupt = new MemoryStream(encrypted);
            using var reject = new SecureTransport(corrupt, material, true, true);
            try
            {
                await reject.ReceiveAsync<RpcRequest>(CancellationToken.None);
                throw new Exception("Accepted modified binary data");
            }
            catch (CryptographicException) { Check(true, $"Binary AES-GCM authentication rejects tampering ({size} bytes)"); }
        }
        var rented = System.Buffers.ArrayPool<byte>.Shared.Rent(4096);
        Array.Fill(rented, (byte)0xEF);
        rented[0] = 42;
        var encoded = RpcEncoding.Encode(new RpcResponse { Data = rented, BorrowedCount = 1 }, true);
        try
        {
            var decoded = RpcEncoding.Decode<RpcResponse>(encoded.Buffer, encoded.Length, true);
            Check(decoded.Data is [42], "A short pooled read exposes only valid bytes, with no buffer tail");
            BinaryPrimitives.WriteInt32LittleEndian(encoded.Buffer.AsSpan(5), Wire.MaxChunk + 1);
            try
            {
                RpcEncoding.Decode<RpcResponse>(encoded.Buffer, encoded.Length, true);
                throw new Exception("Accepted oversized binary payload");
            }
            catch (InvalidDataException) { Check(true, "Binary payload bounds are validated before allocating data"); }
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(encoded.Buffer, clearArray: true);
            System.Buffers.ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
        foreach (var binary in new[] { false, true })
        {
            var slice = RpcEncoding.Encode(new RpcRequest { Operation = "Write", Data = [0, 42, 43, 99], DataOffset = 1, BorrowedCount = 2 }, binary);
            RpcRequest? decoded = null;
            try
            {
                decoded = RpcEncoding.Decode<RpcRequest>(slice.Buffer, slice.Length, binary);
                Check(decoded.DataCount == 2 && decoded.Data!.AsSpan(decoded.DataOffset, 2).SequenceEqual(new byte[] { 42, 43 }),
                    $"Borrowed write slices preserve exact bytes in {(binary ? "binary" : "legacy")} mode");
            }
            finally
            {
                // In binary mode the decoded request owns this same pooled frame.
                if (decoded is { OwnsFrame: true })
                    decoded.ReleasePayload();
                else if (binary)
                    System.Buffers.ArrayPool<byte>.Shared.Return(slice.Buffer, clearArray: true);
                else
                    CryptographicOperations.ZeroMemory(slice.Buffer);
            }
        }
        await RpcSessionSelfTests.RunAsync(material, Check);
        Console.WriteLine($"Protocol: {count} checks passed.");
        return 0;
    }
    private sealed class YieldingWriteStream : Stream
    {
        private readonly MemoryStream inner = new();
        public byte[] Bytes => inner.ToArray();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position
        {
            get => inner.Position; set => throw new NotSupportedException();
        }
        public override void Flush()
        {
        }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            inner.Write(buffer.Span);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
                inner.Dispose();
            base.Dispose(disposing);
        }
    }
    private static async Task Reject(byte[] frame, byte[] material, string label, Action<bool, string> check)
    {
        using var input = new MemoryStream(frame);
        using var receiver = new SecureTransport(input, material, true);
        try
        {
            await receiver.ReceiveAsync<RpcRequest>(CancellationToken.None);
            throw new Exception("Accepted invalid ciphertext");
        }
        catch (CryptographicException) { check(true, label); }
    }
}
