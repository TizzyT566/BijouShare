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
            var serverPublic = serverIdentity.ExportSubjectPublicKeyInfo();
            var hello = new ClientHello(Wire.Version, Guid.NewGuid().ToString(), RandomNumberGenerator.GetBytes(32), clientEphemeral.ExportSubjectPublicKeyInfo())
            {
                CryptoSuite = Wire.CryptoSuite,
                MlKemPublicKey = publicKey,
                DeviceName = "Hybrid regression device",
                ClientPublicKey = Convert.ToBase64String(clientIdentity.ExportSubjectPublicKeyInfo()),
                ServerIdentityMetadata = true,
                BinaryPayloads = true
            };
            var response = new ServerHello(RandomNumberGenerator.GetBytes(32), serverEphemeral.ExportSubjectPublicKeyInfo(), [])
            {
                Version = Wire.Version,
                CryptoSuite = Wire.CryptoSuite,
                MlKemCiphertext = first.Ciphertext,
                IdentityPublicKey = serverPublic,
                ServerName = "HybridServer",
                ServerId = ServerIdentityNaming.Id("HybridServer", serverPublic),
                GlobalIdentityPublicKey = serverPublic
            };
            var transcript = KeyAgreement.Transcript(hello, response, serverPublic);
            var material = Keep(KeyAgreement.SessionMaterial(identity, ephemeral, first.Secret, transcript));
            Check(material.Length == 72 && !material.AsSpan(0, 32).SequenceEqual(material.AsSpan(32, 32)),
                "The hybrid schedule creates independent directional AES-256 keys and nonce prefixes");
            Check(!KeyAgreement.Equals(material, Keep(KeyAgreement.SessionMaterial(Keep(Flip(identity)), ephemeral, first.Secret, transcript))) &&
                !KeyAgreement.Equals(material, Keep(KeyAgreement.SessionMaterial(identity, Keep(Flip(ephemeral)), first.Secret, transcript))) &&
                !KeyAgreement.Equals(material, Keep(KeyAgreement.SessionMaterial(identity, ephemeral, Keep(Flip(first.Secret)), transcript))),
                "Every static ECDH, ephemeral ECDH, and ML-KEM contribution affects the traffic keys");
            var serverProof = KeyAgreement.HybridProof(identity, ephemeral, first.Secret, transcript, "server");
            Check(KeyAgreement.Equals(serverProof, KeyAgreement.HybridProof(identity, ephemeral, recovered, transcript, "server")) &&
                !KeyAgreement.Equals(serverProof, KeyAgreement.HybridProof(identity, ephemeral, first.Secret, transcript, "client")) &&
                !KeyAgreement.Equals(serverProof, KeyAgreement.HybridProof(identity, ephemeral, first.Secret, transcript, "server-identity")),
                "Hybrid key confirmation agrees between peers and separates server, client, and global-identity roles");
            var rejectedSecret = Keep(recipient.Decapsulate(Flip(first.Ciphertext)));
            Check(!KeyAgreement.Equals(first.Secret, rejectedSecret) &&
                !KeyAgreement.Equals(serverProof, KeyAgreement.HybridProof(identity, ephemeral, rejectedSecret, transcript, "server")),
                "ML-KEM implicit rejection produces a different secret and fails authenticated key confirmation");
            Check(!KeyAgreement.Equals(material, Keep(KeyAgreement.SessionMaterial(identity, ephemeral, first.Secret, Flip(transcript)))) &&
                !KeyAgreement.Equals(serverProof, KeyAgreement.HybridProof(identity, ephemeral, first.Secret, Flip(transcript), "server")),
                "Fresh or modified transcripts change both traffic keys and authentication proofs");

            void Bound(ClientHello changedHello, ServerHello changedResponse, string label) =>
                Check(!KeyAgreement.Equals(transcript, KeyAgreement.Transcript(changedHello, changedResponse, serverPublic)), label);
            Bound(hello with
            {
                Version = Wire.Version - 1
            }, response, "The client protocol version is bound to hybrid authentication");
            Bound(hello, response with
            {
                Version = Wire.Version - 1
            }, "The server protocol version is bound to hybrid authentication");
            Bound(hello with
            {
                CryptoSuite = "classical-only"
            }, response, "The client cipher suite cannot be stripped or replaced without detection");
            Bound(hello, response with
            {
                CryptoSuite = "classical-only"
            }, "The server cipher suite cannot be stripped or replaced without detection");
            Bound(hello with
            {
                MlKemPublicKey = freshRecipient.ExportPublicKey()
            }, response,
                "The client's ephemeral ML-KEM public key is bound to the authenticated transcript");
            Bound(hello, response with
            {
                MlKemCiphertext = second.Ciphertext
            },
                "The server's ML-KEM ciphertext is bound to the authenticated transcript");
            Bound(hello with
            {
                MlKemPublicKey = null
            }, response, "Omitting the ML-KEM public key changes the authenticated transcript");
            Bound(hello, response with
            {
                MlKemCiphertext = null
            }, "Omitting the ML-KEM ciphertext changes the authenticated transcript");
            Bound(hello with
            {
                InviteEnrollment = true
            }, response, "Invitation capability is bound to the hybrid transcript");
            Bound(hello, response with
            {
                InviteEnrollment = true
            }, "Invitation acknowledgement is bound to the hybrid transcript");
            Bound(hello, response with
            {
                PendingApproval = true
            }, "The pending/approved decision is bound to the hybrid transcript");
            Bound(hello, response with
            {
                ServerName = "AnotherServer"
            }, "The server name is bound to the hybrid transcript");
            Bound(hello, response with
            {
                GlobalIdentityPublicKey = clientIdentity.ExportSubjectPublicKeyInfo()
            },
                "The pinned global server identity is bound to the hybrid transcript");
            Check(KeyAgreement.Equals(transcript, KeyAgreement.Transcript(hello, response with
            {
                Proof = RandomNumberGenerator.GetBytes(32),
                ServerIdentityProof = RandomNumberGenerator.GetBytes(32)
            }, serverPublic)), "Authentication proofs are excluded from their own transcript to avoid circular key derivation");
            foreach (var length in new[] { 31, 33 })
            {
                Reject(() => KeyAgreement.SessionMaterial(new byte[length], ephemeral, first.Secret, transcript),
                    "The hybrid schedule rejects an invalid static ECDH secret length");
                Reject(() => KeyAgreement.SessionMaterial(identity, new byte[length], first.Secret, transcript),
                    "The hybrid schedule rejects an invalid ephemeral ECDH secret length");
                Reject(() => KeyAgreement.SessionMaterial(identity, ephemeral, new byte[length], transcript),
                    "The hybrid schedule rejects an invalid ML-KEM secret length");
                Reject(() => KeyAgreement.HybridProof(identity, ephemeral, first.Secret, new byte[length], "server"),
                    "Hybrid authentication rejects an invalid transcript hash length");
            }
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
