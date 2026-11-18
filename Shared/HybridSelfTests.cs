using System.Security.Cryptography;

namespace BijouShare.Shared;

public static class HybridSelfTests
{
    public static Task<int> RunAsync()
    {
        var count = 0;
        var sensitive = new List<byte[]>();
        byte[] Keep(byte[] value)
        {
            sensitive.Add(value);
            return value;
        }
        void Check(bool condition, string label)
        {
            if (!condition)
                throw new InvalidOperationException("FAIL: " + label);
            count++;
            Console.WriteLine("PASS: " + label);
        }
        void Reject(Action action, string label)
        {
            try
            {
                action();
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            {
                Check(true, label);
                return;
            }
            throw new InvalidOperationException("FAIL: " + label);
        }
        static byte[] Flip(byte[] value)
        {
            var changed = value.ToArray();
            changed[0] ^= 1;
            return changed;
        }

        HybridKem.EnsureSupported(); // Unsupported native providers must fail, rather than silently skip security checks.
        Check(HybridKem.IsSupported && HybridKem.ProviderName == "Windows CNG",
            "The hybrid suite uses an available native Windows ML-KEM provider");
        try
        {
            using var recipient = HybridKem.Generate();
            using var freshRecipient = HybridKem.Generate();
            var publicKey = recipient.ExportPublicKey();
            Check(publicKey.Length == HybridKem.PublicKeySize && HybridKem.PublicKeySize == 1184 &&
                HybridKem.CiphertextSize == 1088 && HybridKem.SharedSecretSize == 32,
                "ML-KEM-768 has the exact standardized public-key, ciphertext, and shared-secret sizes");
            Check(!publicKey.SequenceEqual(freshRecipient.ExportPublicKey()),
                "Fresh ephemeral ML-KEM keys do not reuse the previous handshake's public key");
            var first = HybridKem.Encapsulate(publicKey);
            Keep(first.Secret);
            var recovered = Keep(recipient.Decapsulate(first.Ciphertext));
            Check(first.Ciphertext.Length == HybridKem.CiphertextSize && first.Secret.Length == HybridKem.SharedSecretSize &&
                KeyAgreement.Equals(first.Secret, recovered),
                "Native ML-KEM encapsulation and decapsulation establish the same secret");
            var second = HybridKem.Encapsulate(publicKey);
            Keep(second.Secret);
            Check(!first.Ciphertext.SequenceEqual(second.Ciphertext) && !KeyAgreement.Equals(first.Secret, second.Secret),
                "Independent encapsulations to one ephemeral key use fresh ciphertexts and shared secrets");
            Check(!KeyAgreement.Equals(first.Secret, Keep(freshRecipient.Decapsulate(first.Ciphertext))),
                "Another ephemeral ML-KEM private key cannot recover the encapsulated secret");
            foreach (var length in new[] { 0, HybridKem.PublicKeySize - 1, HybridKem.PublicKeySize + 1 })
                Reject(() => HybridKem.Encapsulate(new byte[length]), "ML-KEM rejects a public key with an invalid length");
            Reject(() => HybridKem.Encapsulate(Enumerable.Repeat((byte)0xff, HybridKem.PublicKeySize).ToArray()),
                "The native provider rejects noncanonical ML-KEM public-key coefficients");
            foreach (var length in new[] { 0, HybridKem.CiphertextSize - 1, HybridKem.CiphertextSize + 1 })
                Reject(() => recipient.Decapsulate(new byte[length]), "ML-KEM rejects a ciphertext with an invalid length");

            using var clientIdentity = KeyAgreement.NewKey();
            using var serverIdentity = KeyAgreement.NewKey();
            using var clientEphemeral = KeyAgreement.NewKey();
            using var serverEphemeral = KeyAgreement.NewKey();
            var identity = Keep(KeyAgreement.Agree(clientIdentity, serverIdentity.ExportSubjectPublicKeyInfo()));
            var ephemeral = Keep(KeyAgreement.Agree(clientEphemeral, serverEphemeral.ExportSubjectPublicKeyInfo()));
            using var persistentKem = HybridKem.Generate();
            var persistentPublic = persistentKem.ExportPublicKey();
            var seed = Keep(persistentKem.ExportPrivateSeed());
            using var restored = HybridKem.ImportPrivateSeed(seed);
            Check(restored.ExportPublicKey().AsSpan().SequenceEqual(persistentPublic),
                "Restoring a protected ML-KEM seed retains its identity public key");
            var staticChallenge = HybridKem.Encapsulate(persistentPublic);
            var staticSecret = Keep(staticChallenge.Secret);
            Check(KeyAgreement.Equals(staticSecret, Keep(restored.Decapsulate(staticChallenge.Ciphertext))),
                "The restored identity key opens a fresh possession challenge");
            var generator = Convert.FromHexString("3059301306072a8648ce3d020106082a8648ce3d03010703420004" +
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
            Check(DeviceIdentity.Id(generator, new byte[HybridKem.PublicKeySize]) ==
                "709c897923c6641ab9fc76a96723b4515e884c41a8a563d24391d08030a50140",
                "A fixed P-256 SPKI and canonical ML-KEM encoding match the independent v6 fingerprint vector");
            var vector = Enumerable.Range(0, 192).Select(i => (byte)i).ToArray();
            var vectorSecret = Keep(KeyAgreement.SessionSecret(vector[..32], vector[32..64], vector[64..96], vector[96..128], vector[128..160]));
            Check(Convert.ToHexStringLower(vectorSecret) == "872c95f69e4e254ee0d0580c20693063903f42e0c9cd3d14f8e397a937b28757" &&
                Convert.ToHexStringLower(KeyAgreement.Proof(vectorSecret, vector[160..], "server")) ==
                    "0993040f7200b8ae44a71e6265ed72fcf616cdff4ded701813191e1f14f534ab" &&
                Convert.ToHexStringLower(Keep(KeyAgreement.SessionMaterial(vectorSecret, vector[160..]))) ==
                    "fb8a1d3710bed58b8fd982120ed763d0ba8a90f9be47f6bbbf811a2b6e1785d7cc819250ed70ae8e324ae792a260f1a5d7fa4253cf6834f91bbd2d60cb38c61be6903e2b87ee4169",
                "Independent SHA3 vectors match the hybrid combiner, server proof and directional traffic material");
            var canonicalPublic = clientIdentity.ExportSubjectPublicKeyInfo();
            var id = DeviceIdentity.Id(canonicalPublic, persistentPublic);
            Check(id == Convert.ToHexStringLower(SHA3_256.HashData([.. canonicalPublic, .. persistentPublic])) &&
                ServerIdentityNaming.Id(canonicalPublic, persistentPublic) == id,
                "Client and server use the same SHA3-256 fingerprint over the exact canonical public keys");
            Check(DeviceIdentity.Id(serverIdentity.ExportSubjectPublicKeyInfo(), persistentPublic) != id &&
                DeviceIdentity.Id(canonicalPublic, publicKey) != id, "Changing either persistent key changes the full fingerprint");
            using var serverKem = HybridKem.Generate();
            var serverKemPublic = serverKem.ExportPublicKey();
            var toServer = HybridKem.Encapsulate(serverKemPublic);
            Keep(toServer.Secret);
            var serverKemSecret = Keep(serverKem.Decapsulate(toServer.Ciphertext));
            var secret = Keep(KeyAgreement.SessionSecret(identity, ephemeral, staticSecret, toServer.Secret, recovered));
            var serverSecret = Keep(KeyAgreement.SessionSecret(
                Keep(KeyAgreement.Agree(serverIdentity, canonicalPublic)),
                Keep(KeyAgreement.Agree(serverEphemeral, clientEphemeral.ExportSubjectPublicKeyInfo())),
                staticSecret, serverKemSecret, first.Secret));
            Check(KeyAgreement.Equals(secret, serverSecret), "The peers independently derive the same bidirectional hybrid secret");
            Check(KeyAgreement.Equals(secret, SHA3_256.HashData([
                .. SHA3_256.HashData([.. identity, .. ephemeral]),
                .. SHA3_256.HashData([.. staticSecret, .. serverKemSecret, .. first.Secret])])),
                "The hybrid secret combines raw P-256 and ML-KEM shared contributions with SHA3-256");
            var inputs = new[] { identity, ephemeral, staticSecret, serverKemSecret, first.Secret };
            for (var i = 0; i < inputs.Length; i++)
            {
                var changed = inputs.ToArray();
                changed[i] = Keep(Flip(changed[i]));
                Check(!KeyAgreement.Equals(secret, Keep(KeyAgreement.SessionSecret(changed[0],changed[1],changed[2],changed[3],changed[4]))),
                    $"Hybrid secret contribution {i + 1} affects authentication and traffic keys");
            }
            var hello = new ClientHello(Wire.Version, id, RandomNumberGenerator.GetBytes(32), clientEphemeral.ExportSubjectPublicKeyInfo())
            {
                CryptoSuite = Wire.CryptoSuite, ClientPublicKey = Convert.ToBase64String(canonicalPublic), DeviceName = "Device",
                IdentityMlKemPublicKey = persistentPublic, MlKemPublicKey = publicKey, BinaryPayloads = true
            };
            var serverPublic = serverIdentity.ExportSubjectPublicKeyInfo();
            var response = new ServerHello(RandomNumberGenerator.GetBytes(32),serverEphemeral.ExportSubjectPublicKeyInfo())
            {
                Version = Wire.Version, CryptoSuite = Wire.CryptoSuite, GlobalIdentityPublicKey = serverPublic, ServerMlKemPublicKey = serverKemPublic,
                ServerName = "Server", ServerId = ServerIdentityNaming.Id(serverPublic, serverKemPublic),
                MlKemCiphertext = first.Ciphertext, IdentityMlKemCiphertext = staticChallenge.Ciphertext
            };
            var exchange = new ClientKeyExchange(toServer.Ciphertext);
            var transcript = KeyAgreement.Transcript(hello, response, exchange);
            var serverProof = KeyAgreement.Proof(serverSecret, transcript, "server");
            var clientProof = KeyAgreement.Proof(secret, transcript, "client");
            Check(KeyAgreement.Equals(serverProof, KeyAgreement.Proof(secret, transcript, "server")) && !KeyAgreement.Equals(clientProof, serverProof),
                "Fresh client and server key confirmation proofs agree only for the designated sender");
            var traffic = Keep(KeyAgreement.SessionMaterial(secret, transcript));
            Check(traffic.Length == 72 && !traffic.AsSpan(0,32).SequenceEqual(traffic.AsSpan(32,32)) &&
                !traffic.AsSpan(0,32).SequenceEqual(clientProof) && !traffic.AsSpan(32,32).SequenceEqual(serverProof),
                "Directional AES-256 keys and nonce prefixes are separate from confirmation proofs");
            void Bound(ClientHello h, ServerHello r, ClientKeyExchange x, string field)
            {
                var other = KeyAgreement.Transcript(h, r, x);
                Check(!KeyAgreement.Equals(serverProof, KeyAgreement.Proof(secret, other, "server")) &&
                    !KeyAgreement.Equals(traffic, Keep(KeyAgreement.SessionMaterial(secret, other))),
                    $"{field} is bound to key confirmation and traffic keys");
            }
            Bound(hello with { Nonce = Flip(hello.Nonce) }, response, exchange, "Client freshness");
            Bound(hello,response with { Nonce = Flip(response.Nonce) },exchange,"Server freshness");
            Bound(hello with { Version = 5 }, response, exchange, "Client protocol version");
            Bound(hello,response with { CryptoSuite = null },exchange,"Server suite");
            Bound(hello with { ClientPublicKey = null, IdentityMlKemPublicKey = null }, response, exchange, "Client identity keys");
            Bound(hello,response with { GlobalIdentityPublicKey = null, ServerMlKemPublicKey = null },exchange,"Server identity keys");
            Bound(hello,response with { ServerName = "Other" },exchange,"Server display name");
            Bound(hello,response with { ServerId = id },exchange,"Expected server fingerprint");
            Bound(hello with { BinaryPayloads = false }, response, exchange, "Transfer negotiation");
            Bound(hello,response with { PendingApproval = true, InviteEnrollment = true },exchange,"Enrollment status");
            Bound(hello,response with { IdentityMlKemCiphertext = Flip(staticChallenge.Ciphertext) },exchange,"Challenge to the client identity key");
            Bound(hello,response with { MlKemCiphertext = Flip(first.Ciphertext) },exchange,"Ephemeral ML-KEM challenge");
            Bound(hello,response,exchange with { MlKemCiphertext = Flip(exchange.MlKemCiphertext) },"Challenge to the server identity key");
            Reject(() => KeyAgreement.SessionSecret([],ephemeral,staticSecret,serverKemSecret,first.Secret), "Malformed raw secret length is rejected");
            Reject(() => KeyAgreement.Proof(secret, [], "server"), "Malformed transcript length is rejected");
            Reject(() => KeyAgreement.Proof(secret, transcript, "reflection"), "Unknown proof roles are rejected");
        }
        finally
        {
            foreach (var bytes in sensitive)
                CryptographicOperations.ZeroMemory(bytes);
        }
        Console.WriteLine($"Hybrid cryptography: {count} checks passed.");
        return Task.FromResult(count);
    }
}
