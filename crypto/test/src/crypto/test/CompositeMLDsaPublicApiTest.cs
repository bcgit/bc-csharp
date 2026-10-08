using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// Composite ML-DSA driven purely through the existing, algorithm-agnostic public entry points.
    /// </summary>
    /// <remarks>
    /// Nothing here names a Composite ML-DSA type: everything is reached by algorithm name or OID and held as
    /// <see cref="AsymmetricKeyParameter"/>, <see cref="ISigner"/> or
    /// <see cref="IAsymmetricCipherKeyPairGenerator"/>. Those types are internal to the library, so this fixture
    /// is the proof that a consumer can still do everything they need to.
    /// </remarks>
    [TestFixture]
    public class CompositeMLDsaPublicApiTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Context = Strings.ToByteArray("public API context");

        [Test]
        public void TestNoCompositeTypesExported()
        {
            /*
             * The implementation types are deliberately internal: within v2.x anything public is locked, and
             * their shape is still expected to change. The rest of this fixture shows they are not needed.
             */
            var exported = new List<string>();
            foreach (var type in typeof(SignerUtilities).Assembly.GetExportedTypes())
            {
                if (type.Name.StartsWith("CompositeMLDsa"))
                {
                    exported.Add(type.FullName);
                }
            }

            Assert.IsEmpty(exported, "Composite ML-DSA types must not be public: " + string.Join(", ", exported));
        }

        [Test]
        public void TestKeyEncodingRoundTrip()
        {
            foreach (var testVector in LoadCompositeVectors(out byte[] message))
            {
                string name = testVector["name"];
                var oid = SignerUtilities.GetObjectIdentifier(name);
                Assert.NotNull(oid, name + ": registered with SignerUtilities");

                byte[] skPkcs8 = Base64.Decode(testVector["sk_pkcs8"]);
                var privateKey = PrivateKeyFactory.CreateKey(skPkcs8);
                Assert.True(privateKey.IsPrivate, name + ": decoded key is private");
                Assert.True(Arrays.AreEqual(skPkcs8,
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded(Asn1Encodable.Der)),
                    name + ": PKCS#8 re-encode");

                var certificate = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]));
                var publicKey = certificate.GetPublicKey();
                Assert.False(publicKey.IsPrivate, name + ": certificate key is public");

                var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                Assert.AreEqual(oid, spki.Algorithm.Algorithm, name + ": SPKI algorithm OID");
                Assert.IsNull(spki.Algorithm.Parameters, name + ": SPKI AlgorithmIdentifier must omit parameters");
                Assert.True(Arrays.AreEqual(Base64.Decode(testVector["pk"]), spki.PublicKey.GetOctets()),
                    name + ": SPKI body");
                Assert.True(Arrays.AreEqual(certificate.SubjectPublicKeyInfo.GetEncoded(Asn1Encodable.Der),
                    spki.GetEncoded(Asn1Encodable.Der)), name + ": SPKI re-encode");

                var decodedPublicKey = PublicKeyFactory.CreateKey(spki);
                Assert.True(Arrays.AreEqual(spki.GetEncoded(Asn1Encodable.Der),
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(decodedPublicKey)
                        .GetEncoded(Asn1Encodable.Der)),
                    name + ": SPKI decode and re-encode");

                // The published signature verifies through a signer looked up by name.
                var verifier = SignerUtilities.GetSigner(name);
                verifier.Init(forSigning: false, publicKey);
                verifier.BlockUpdate(message, 0, message.Length);
                Assert.True(verifier.VerifySignature(Base64.Decode(testVector["s"])), name + ": published signature");
            }
        }

        [Test]
        public void TestSignerUtilitiesWithContext()
        {
            foreach (var testVector in LoadCompositeVectors(out byte[] message))
            {
                string name = testVector["name"];
                var oid = SignerUtilities.GetObjectIdentifier(name);
                var privateKey = PrivateKeyFactory.CreateKey(Base64.Decode(testVector["sk_pkcs8"]));
                var publicKey = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]))
                    .GetPublicKey();

                // Signer by name, verifier by OID.
                byte[] signature = Sign(SignerUtilities.GetSigner(name), privateKey, Context, message);
                Assert.True(Verify(SignerUtilities.GetSigner(oid), publicKey, Context, message, signature),
                    name + ": name-signed, OID-verified, with context");
                Assert.False(Verify(SignerUtilities.GetSigner(oid), publicKey, null, message, signature),
                    name + ": verification without the context must fail");

                // Signer by OID, verifier by name.
                signature = Sign(SignerUtilities.GetSigner(oid), privateKey, Context, message);
                Assert.True(Verify(SignerUtilities.GetSigner(name), publicKey, Context, message, signature),
                    name + ": OID-signed, name-verified, with context");
                Assert.False(Verify(SignerUtilities.GetSigner(name), publicKey, null, message, signature),
                    name + ": verification without the context must fail");
            }
        }

        [Test]
        public void TestAsn1SignatureFactory()
        {
            foreach (var testVector in LoadCompositeVectors(out byte[] message))
            {
                string name = testVector["name"];
                var oid = SignerUtilities.GetObjectIdentifier(name);
                var privateKey = PrivateKeyFactory.CreateKey(Base64.Decode(testVector["sk_pkcs8"]));
                var publicKey = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]))
                    .GetPublicKey();

                foreach (string algorithm in new string[]{ name, oid.GetID() })
                {
                    var signatureFactory = new Asn1SignatureFactory(algorithm, privateKey, Random);
                    var algID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;
                    Assert.AreEqual(oid, algID.Algorithm, algorithm + ": signature algorithm OID");
                    Assert.IsNull(algID.Parameters, algorithm + ": AlgorithmIdentifier must omit parameters");

                    byte[] signature = Calculate(signatureFactory, message);

                    Assert.True(IsVerified(new Asn1VerifierFactory(name, publicKey), message, signature),
                        algorithm + ": verified by name");
                    Assert.True(IsVerified(new Asn1VerifierFactory(algID, publicKey), message, signature),
                        algorithm + ": verified by AlgorithmIdentifier");
                }
            }
        }

        [Test]
        public void TestGeneratorUtilities()
        {
            foreach (var testVector in LoadCompositeVectors(out byte[] message))
            {
                string name = testVector["name"];

                // RSA-4096 key generation takes seconds; the shorter moduli exercise the same path.
                if (name.Contains("RSA4096"))
                    continue;

                var generator = GeneratorUtilities.GetKeyPairGenerator(name);
                generator.Init(new KeyGenerationParameters(Random, 0));
                CheckKeyPair(name, generator.GenerateKeyPair(), message);
            }
        }

        [Test]
        public void TestGeneratorUtilitiesByOid()
        {
            /*
             * A generator is bound to its combination when it is constructed, so a non-null result only shows
             * that the OID resolves to some combination; generating through it shows it resolves to the right
             * one. RSA key generation is too slow to repeat here, so the RSA combinations get only the lookup.
             */
            byte[] message = Strings.ToByteArray("generated by OID");

            int generated = 0;
            foreach (var testVector in LoadCompositeVectors(out _))
            {
                string name = testVector["name"];
                var generator = GeneratorUtilities.GetKeyPairGenerator(SignerUtilities.GetObjectIdentifier(name));
                Assert.NotNull(generator, name + ": generator by OID");

                if (name.Contains("-RSA"))
                    continue;

                generator.Init(new KeyGenerationParameters(Random, 0));
                CheckKeyPair(name, generator.GenerateKeyPair(), message);
                ++generated;
            }

            Assert.AreEqual(10, generated, "every EC and EdDSA combination generated by OID");
        }

        private static void CheckKeyPair(string name, AsymmetricCipherKeyPair keyPair, byte[] message)
        {
            var publicKey = keyPair.Public;
            var privateKey = keyPair.Private;

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            Assert.AreEqual(SignerUtilities.GetObjectIdentifier(name), spki.Algorithm.Algorithm,
                name + ": generated key's SPKI algorithm OID");

            var decodedPrivateKey = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey));
            var decodedPublicKey = PublicKeyFactory.CreateKey(spki);

            byte[] signature = Sign(SignerUtilities.GetSigner(name), decodedPrivateKey, Context, message);
            Assert.True(Verify(SignerUtilities.GetSigner(name), publicKey, Context, message, signature),
                name + ": generated key pair signs and verifies");
            Assert.True(Verify(SignerUtilities.GetSigner(name), decodedPublicKey, Context, message, signature),
                name + ": decoded generated public key verifies");
        }

        /// <summary>
        /// The composite vectors only, each with its algorithm name (the <c>tcId</c> minus <c>id-</c>) added.
        /// </summary>
        private static IList<IDictionary<string, string>> LoadCompositeVectors(out byte[] message)
        {
            var result = new List<IDictionary<string, string>>();
            foreach (var testVector in CompositeMLDsaTest.LoadTestVectors(out message))
            {
                string tcId = testVector["tcId"];

                // The file also carries plain ML-DSA baselines, which the ML-DSA tests already cover.
                if (tcId.StartsWith("id-ML-DSA-"))
                    continue;

                Assert.True(tcId.StartsWith("id-"), "unrecognised test case: " + tcId);
                testVector["name"] = tcId.Substring("id-".Length);
                result.Add(testVector);
            }

            Assert.AreEqual(18, result.Count, "composite vector count");
            return result;
        }

        private static byte[] Sign(ISigner signer, AsymmetricKeyParameter privateKey, byte[] context, byte[] message)
        {
            signer.Init(forSigning: true,
                new ParametersWithContext(new ParametersWithRandom(privateKey, Random), context));
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        private static bool Verify(ISigner signer, AsymmetricKeyParameter publicKey, byte[] context, byte[] message,
            byte[] signature)
        {
            ICipherParameters parameters = publicKey;
            if (context != null)
            {
                parameters = new ParametersWithContext(parameters, context);
            }

            signer.Init(forSigning: false, parameters);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }

        private static byte[] Calculate(ISignatureFactory signatureFactory, byte[] message)
        {
            var calculator = signatureFactory.CreateCalculator();
            using (var stream = calculator.Stream)
            {
                stream.Write(message, 0, message.Length);
            }
            return calculator.GetResult().Collect();
        }

        private static bool IsVerified(IVerifierFactory verifierFactory, byte[] message, byte[] signature)
        {
            var calculator = verifierFactory.CreateCalculator();
            using (var stream = calculator.Stream)
            {
                stream.Write(message, 0, message.Length);
            }
            return calculator.GetResult().IsVerified(signature);
        }
    }
}
