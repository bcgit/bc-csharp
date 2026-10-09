using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// Composite ML-DSA tests driven by the published test vectors accompanying
    /// draft-ietf-lamps-pq-composite-sigs, which live in the bc-test-data repository under
    /// <c>pqc/crypto/composite</c>.
    /// </summary>
    [TestFixture]
    public class CompositeMLDsaTest
    {
        private static readonly IDictionary<string, CompositeMLDsaParameters> ParametersByTcId = CreateTcIdMap();

        private static IDictionary<string, CompositeMLDsaParameters> CreateTcIdMap()
        {
            var d = new Dictionary<string, CompositeMLDsaParameters>();
            foreach (var parameters in new CompositeMLDsaParameters[]
            {
                CompositeMLDsaParameters.MLDSA44_RSA2048_PSS_SHA256,
                CompositeMLDsaParameters.MLDSA44_RSA2048_PKCS15_SHA256,
                CompositeMLDsaParameters.MLDSA44_Ed25519_SHA512,
                CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256,
                CompositeMLDsaParameters.MLDSA65_RSA3072_PSS_SHA512,
                CompositeMLDsaParameters.MLDSA65_RSA3072_PKCS15_SHA512,
                CompositeMLDsaParameters.MLDSA65_RSA4096_PSS_SHA512,
                CompositeMLDsaParameters.MLDSA65_RSA4096_PKCS15_SHA512,
                CompositeMLDsaParameters.MLDSA65_ECDSA_P256_SHA512,
                CompositeMLDsaParameters.MLDSA65_ECDSA_P384_SHA512,
                CompositeMLDsaParameters.MLDSA65_ECDSA_brainpoolP256r1_SHA512,
                CompositeMLDsaParameters.MLDSA65_Ed25519_SHA512,
                CompositeMLDsaParameters.MLDSA87_ECDSA_P384_SHA512,
                CompositeMLDsaParameters.MLDSA87_ECDSA_brainpoolP384r1_SHA512,
                CompositeMLDsaParameters.MLDSA87_Ed448_SHAKE256,
                CompositeMLDsaParameters.MLDSA87_RSA3072_PSS_SHA512,
                CompositeMLDsaParameters.MLDSA87_RSA4096_PSS_SHA512,
                CompositeMLDsaParameters.MLDSA87_ECDSA_P521_SHA512,
            })
            {
                d.Add("id-" + parameters.Name, parameters);
            }
            return d;
        }

        internal static IList<IDictionary<string, string>> LoadTestVectors(out byte[] message)
        {
            string json;
            using (var stream = SimpleTest.FindTestResource("pqc", "crypto/composite", "testvectors.json"))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                json = reader.ReadToEnd();
            }

            var root = (IDictionary<string, object>)MiniJson.Parse(json);

            message = Base64.Decode((string)root["m"]);

            var result = new List<IDictionary<string, string>>();
            foreach (var entry in (IList<object>)root["tests"])
            {
                var test = new Dictionary<string, string>();
                foreach (var kvp in (IDictionary<string, object>)entry)
                {
                    test[kvp.Key] = (string)kvp.Value;
                }
                result.Add(test);
            }
            return result;
        }

        [Test]
        public void TestVectors()
        {
            var testVectors = LoadTestVectors(out byte[] message);

            int count = 0;
            foreach (var testVector in testVectors)
            {
                string tcId = testVector["tcId"];
                if (!ParametersByTcId.TryGetValue(tcId, out var parameters))
                {
                    // The file also carries plain ML-DSA baselines, which the ML-DSA tests already cover.
                    Assert.True(tcId.StartsWith("id-ML-DSA-"), "unrecognised test case: " + tcId);
                    continue;
                }

                RunTestVector(parameters, tcId, message, testVector);
                ++count;
            }

            Assert.AreEqual(ParametersByTcId.Count, count, "not all combinations were exercised");
        }

        private static void RunTestVector(CompositeMLDsaParameters parameters, string tcId, byte[] message,
            IDictionary<string, string> testVector)
        {
            byte[] pk = Base64.Decode(testVector["pk"]);
            byte[] sk = Base64.Decode(testVector["sk"]);
            byte[] signature = Base64.Decode(testVector["s"]);

            var oid = SignerUtilities.GetObjectIdentifier(parameters.Name);
            Assert.AreEqual(tcId, "id-" + SignerUtilities.GetEncodingName(oid), tcId + ": OID registration");

            var publicKey = CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, pk);
            Assert.True(Arrays.AreEqual(pk, publicKey.GetEncoded()), tcId + ": public key round-trip");

            var privateKey = CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, sk);
            Assert.True(Arrays.AreEqual(sk, privateKey.GetEncoded()), tcId + ": private key round-trip");

            Assert.True(Arrays.AreEqual(pk, privateKey.GetPublicKey().GetEncoded()),
                tcId + ": public key derived from private key");

            // The published PKCS#8 encoding must decode through the standard factory, and re-encode identically.
            byte[] skPkcs8 = Base64.Decode(testVector["sk_pkcs8"]);
            var decodedPrivateKey = (CompositeMLDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(skPkcs8);
            Assert.AreEqual(parameters, decodedPrivateKey.Parameters, tcId + ": PKCS#8 combination");
            Assert.True(Arrays.AreEqual(sk, decodedPrivateKey.GetEncoded()), tcId + ": PKCS#8 decode");
            Assert.True(Arrays.AreEqual(skPkcs8,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(decodedPrivateKey).GetEncoded(Asn1Encodable.Der)),
                tcId + ": PKCS#8 re-encode");

            // Likewise the SubjectPublicKeyInfo round-trip through the standard factories.
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            Assert.AreEqual(oid, spki.Algorithm.Algorithm, tcId + ": SPKI algorithm OID");
            Assert.True(Arrays.AreEqual(pk, spki.PublicKey.GetOctets()), tcId + ": SPKI body");

            var decodedPublicKey = (CompositeMLDsaPublicKeyParameters)PublicKeyFactory.CreateKey(spki);
            Assert.True(Arrays.AreEqual(pk, decodedPublicKey.GetEncoded()), tcId + ": SPKI decode");

            // The published self-signed certificate must parse and verify against its own public key.
            var certificate = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]));
            Assert.AreEqual(oid.Id, certificate.SigAlgOid, tcId + ": certificate signature algorithm");
            certificate.Verify(certificate.GetPublicKey());

            // ... and resolving the signer purely from the certificate's OID must reach the same result.
            var oidSigner = SignerUtilities.InitSigner(certificate.SigAlgOid, forSigning: false,
                certificate.GetPublicKey(), random: null);
            oidSigner.BlockUpdate(message, 0, message.Length);
            Assert.True(oidSigner.VerifySignature(signature), tcId + ": signer resolved by OID");

            // 1. The published signature verifies under the published public key.
            Assert.True(Verify(parameters, publicKey, message, signature), tcId + ": published signature");

            // 2. A signature we generate ourselves verifies under the same public key.
            var signer = new CompositeMLDsaSigner(parameters);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(message, 0, message.Length);
            byte[] generated = signer.GenerateSignature();

            Assert.True(generated.Length <= signer.GetMaxSignatureSize(), tcId + ": signature size bound");
            Assert.True(Verify(parameters, publicKey, message, generated), tcId + ": generated signature");

            // 3. Tampering with either half, or with the message, is rejected.
            byte[] tamperedMLDsa = Arrays.Clone(signature);
            tamperedMLDsa[0] ^= 0x01;
            Assert.False(Verify(parameters, publicKey, message, tamperedMLDsa), tcId + ": tampered ML-DSA half");

            byte[] tamperedTraditional = Arrays.Clone(signature);
            tamperedTraditional[tamperedTraditional.Length - 1] ^= 0x01;
            Assert.False(Verify(parameters, publicKey, message, tamperedTraditional),
                tcId + ": tampered traditional half");

            byte[] tamperedMessage = Arrays.Clone(message);
            tamperedMessage[0] ^= 0x01;
            Assert.False(Verify(parameters, publicKey, tamperedMessage, signature), tcId + ": tampered message");
        }

        [Test]
        public void TestPreHashed()
        {
            var testVectors = LoadTestVectors(out byte[] message);

            foreach (var testVector in testVectors)
            {
                if (!ParametersByTcId.TryGetValue(testVector["tcId"], out var parameters))
                    continue;

                byte[] pk = Base64.Decode(testVector["pk"]);
                byte[] signature = Base64.Decode(testVector["s"]);

                var publicKey = CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, pk);

                // Pre-hashing out of band must reach the same message representative.
                var digest = DigestUtilities.GetDigest(parameters.PreHashAlgorithm);
                byte[] preHash = new byte[digest.GetDigestSize()];
                digest.BlockUpdate(message, 0, message.Length);
                digest.DoFinal(preHash, 0);

                var signer = new CompositeMLDsaSigner(parameters, preHashed: true);
                signer.Init(forSigning: false, publicKey);
                signer.BlockUpdate(preHash, 0, preHash.Length);

                Assert.True(signer.VerifySignature(signature), testVector["tcId"] + ": pre-hashed verification");
            }
        }

        [Test]
        public void TestContextSeparation()
        {
            var parameters = CompositeMLDsaParameters.MLDSA44_Ed25519_SHA512;
            var keyPair = GenerateKeyPair(parameters);

            byte[] message = Strings.ToByteArray("Hello, how was your day?");
            byte[] context = Strings.ToByteArray("context");

            var signer = new CompositeMLDsaSigner(parameters);
            signer.Init(forSigning: true, new ParametersWithContext(keyPair.Private, context));
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();

            signer.Init(forSigning: false, new ParametersWithContext(keyPair.Public, context));
            signer.BlockUpdate(message, 0, message.Length);
            Assert.True(signer.VerifySignature(signature), "matching context");

            signer.Init(forSigning: false, keyPair.Public);
            signer.BlockUpdate(message, 0, message.Length);
            Assert.False(signer.VerifySignature(signature), "context omitted");

            signer.Init(forSigning: false,
                new ParametersWithContext(keyPair.Public, Strings.ToByteArray("other")));
            signer.BlockUpdate(message, 0, message.Length);
            Assert.False(signer.VerifySignature(signature), "differing context");
        }

        [Test]
        public void TestDomainSeparation()
        {
            /*
             * A signature must not verify under a combination it was not made for. These two combinations
             * share the ML-DSA parameter set, the traditional signature algorithm and the pre-hash, so with the
             * same component keys bound under both, only their signature labels tell them apart.
             */
            var signing = CompositeMLDsaParameters.MLDSA65_ECDSA_P256_SHA512;
            var other = CompositeMLDsaParameters.MLDSA65_ECDSA_brainpoolP256r1_SHA512;

            Assert.AreEqual(signing.MLDsaParameters, other.MLDsaParameters);
            Assert.AreEqual(signing.TraditionalSignatureAlgorithm, other.TraditionalSignatureAlgorithm);
            Assert.AreEqual(signing.PreHashAlgorithm, other.PreHashAlgorithm);

            var keyPair = GenerateKeyPair(signing);

            byte[] message = Strings.ToByteArray("Hello, how was your day?");

            var signer = new CompositeMLDsaSigner(signing);
            signer.Init(forSigning: true, keyPair.Private);
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();

            // Rebinding the same ML-DSA key under the other combination must not accept the signature.
            var crossPublicKey = new CompositeMLDsaPublicKeyParameters(other,
                ((CompositeMLDsaPublicKeyParameters)keyPair.Public).MLDsaPublicKey,
                ((CompositeMLDsaPublicKeyParameters)keyPair.Public).TraditionalPublicKey);

            var crossSigner = new CompositeMLDsaSigner(other);
            crossSigner.Init(forSigning: false, crossPublicKey);
            crossSigner.BlockUpdate(message, 0, message.Length);
            Assert.False(crossSigner.VerifySignature(signature), "signature accepted under the wrong combination");
        }

        [Test]
        public void TestKeyPairGeneration()
        {
            byte[] message = Strings.ToByteArray("Hello, how was your day?");

            foreach (var parameters in ParametersByTcId.Values)
            {
                // RSA-4096 key generation is slow enough to dominate this fixture; the shorter moduli exercise
                // the same code path.
                if (parameters.Name.Contains("RSA4096"))
                    continue;

                var keyPair = GenerateKeyPair(parameters);

                var publicKey = (CompositeMLDsaPublicKeyParameters)keyPair.Public;
                var privateKey = (CompositeMLDsaPrivateKeyParameters)keyPair.Private;

                Assert.True(Arrays.AreEqual(publicKey.GetEncoded(), privateKey.GetPublicKey().GetEncoded()),
                    parameters.Name + ": generated key pair agrees");

                byte[] pk = publicKey.GetEncoded();
                Assert.True(Arrays.AreEqual(pk,
                    CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, pk).GetEncoded()),
                    parameters.Name + ": generated public key round-trip");

                byte[] sk = privateKey.GetEncoded();
                Assert.True(Arrays.AreEqual(sk,
                    CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, sk).GetEncoded()),
                    parameters.Name + ": generated private key round-trip");

                var signer = new CompositeMLDsaSigner(parameters);
                signer.Init(forSigning: true, privateKey);
                signer.BlockUpdate(message, 0, message.Length);
                byte[] signature = signer.GenerateSignature();

                Assert.True(Verify(parameters, publicKey, message, signature), parameters.Name + ": sign/verify");
            }
        }

        [Test]
        public void TestRecoversAfterFailedOperation()
        {
            /*
             * However a sign or verify leaves, the signer must go back to the state Init left it in.
             * Resetting only on the normal exits left a throw from inside the operation - a pre-hash of
             * the wrong length is the reachable case - with the buffered bytes still in place, so every
             * later attempt overflowed the buffer and threw again and the object could not be reused.
             */
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            var keyPair = GenerateKeyPair(parameters);
            byte[] message = Strings.ToByteArray("recovery after a failed operation");

            var digest = DigestUtilities.GetDigest(parameters.PreHashAlgorithm);
            byte[] preHash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(message, 0, message.Length);
            digest.DoFinal(preHash, 0);

            var signer = new CompositeMLDsaSigner(parameters, preHashed: true);
            signer.Init(forSigning: true, keyPair.Private);

            // One byte short, so the failure comes from inside GenerateSignature.
            signer.BlockUpdate(preHash, 0, preHash.Length - 1);
            Assert.Throws<InvalidOperationException>(() => signer.GenerateSignature());

            // The same object must now accept a complete pre-hash as a fresh operation.
            signer.BlockUpdate(preHash, 0, preHash.Length);
            byte[] signature = signer.GenerateSignature();
            Assert.True(Verify(parameters, (CompositeMLDsaPublicKeyParameters)keyPair.Public, message, signature),
                "signature produced after a failed operation");

            // Same contract on the verify side.
            var verifier = new CompositeMLDsaSigner(parameters, preHashed: true);
            verifier.Init(forSigning: false, keyPair.Public);
            verifier.BlockUpdate(preHash, 0, preHash.Length - 1);
            Assert.Throws<InvalidOperationException>(() => verifier.VerifySignature(signature));

            verifier.BlockUpdate(preHash, 0, preHash.Length);
            Assert.True(verifier.VerifySignature(signature), "verification after a failed operation");
        }

        [Test]
        public void TestMalformedTraditionalComponent()
        {
            /*
             * The draft treats any component failure as an invalid signature (Section 3.3). A traditional
             * component its own signer cannot even parse - an RSA block of the wrong length or out of range is
             * the reachable case - must return false like any other mismatch, and must not leave the signer
             * unusable. All 18 vectors between them cover the four traditional families.
             */
            var testVectors = LoadTestVectors(out byte[] message);

            string[] labels = { "byte appended", "traditional half zeroed", "traditional half set to 0xFF" };

            int count = 0;
            foreach (var testVector in testVectors)
            {
                string tcId = testVector["tcId"];
                if (!ParametersByTcId.TryGetValue(tcId, out var parameters))
                    continue;

                var publicKey = CompositeMLDsaPublicKeyParameters.FromEncoding(parameters,
                    Base64.Decode(testVector["pk"]));
                byte[] signature = Base64.Decode(testVector["s"]);

                int mlDsaLength = parameters.MLDsaSignatureLength;
                byte[] zeroed = Arrays.Clone(signature);
                Arrays.Fill(zeroed, mlDsaLength, zeroed.Length, 0x00);
                byte[] ones = Arrays.Clone(signature);
                Arrays.Fill(ones, mlDsaLength, ones.Length, 0xFF);

                byte[][] mutations = { Arrays.Append(signature, 0x00), zeroed, ones };

                // One verifier throughout, so a mutation that left state behind would fail the final check.
                var verifier = new CompositeMLDsaSigner(parameters);
                verifier.Init(forSigning: false, publicKey);

                for (int i = 0; i < mutations.Length; ++i)
                {
                    verifier.BlockUpdate(message, 0, message.Length);
                    Assert.False(verifier.VerifySignature(mutations[i]), tcId + ": " + labels[i]);
                }

                verifier.BlockUpdate(message, 0, message.Length);
                Assert.True(verifier.VerifySignature(signature), tcId + ": valid signature after rejected ones");
                ++count;
            }

            Assert.AreEqual(ParametersByTcId.Count, count, "not all combinations were exercised");
        }

        [Test]
        public void TestAlgorithmIdentifierRegistration()
        {
            /*
             * The draft requires the composite AlgorithmIdentifier to omit its parameters entirely; an
             * explicit NULL is a silent interoperability failure. The name-to-identifier tables default to
             * DerNull, so absent parameters depend on each combination being registered as "no params".
             * TestCertificateGeneration covers the Asn1SignatureFactory table end to end for one combination;
             * this covers every combination through the public signature-algorithm finder.
             */
            var finder = DefaultSignatureAlgorithmFinder.Instance;

            foreach (var parameters in ParametersByTcId.Values)
            {
                var oid = SignerUtilities.GetObjectIdentifier(parameters.Name);
                Assert.NotNull(oid, parameters.Name + ": registered with SignerUtilities");

                var algID = finder.Find(parameters.Name);
                Assert.AreEqual(oid, algID.Algorithm, parameters.Name + ": signature algorithm OID");
                Assert.IsNull(algID.Parameters, parameters.Name + ": AlgorithmIdentifier must omit parameters");

                // The name must survive the OID-to-name direction too, since Asn1SignatureFactory resolves a
                // received AlgorithmIdentifier back to a name before it can construct a signer.
                Assert.AreEqual(parameters.Name, SignerUtilities.GetEncodingName(oid),
                    parameters.Name + ": OID maps back to the same name");
            }
        }

        [Test]
        public void TestCertificateGeneration()
        {
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            var keyPair = GenerateKeyPair(parameters);

            var name = new X509Name("CN=Composite ML-DSA Test");

            var generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(BigInteger.One);
            generator.SetIssuerDN(name);
            generator.SetSubjectDN(name);
            generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
            generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
            generator.SetPublicKey(keyPair.Public);

            var certificate = generator.Generate(
                new Asn1SignatureFactory(parameters.Name, keyPair.Private, new SecureRandom()));

            // Per the draft the composite AlgorithmIdentifier carries no parameters at all.
            var signatureAlgorithm = certificate.CertificateStructure.SignatureAlgorithm;
            Assert.AreEqual(SignerUtilities.GetObjectIdentifier(parameters.Name), signatureAlgorithm.Algorithm);
            Assert.IsNull(signatureAlgorithm.Parameters, "composite AlgorithmIdentifier must omit parameters");

            certificate.Verify(certificate.GetPublicKey());

            var recoveredPublicKey = (CompositeMLDsaPublicKeyParameters)certificate.GetPublicKey();
            Assert.True(Arrays.AreEqual(((CompositeMLDsaPublicKeyParameters)keyPair.Public).GetEncoded(),
                recoveredPublicKey.GetEncoded()));
        }

        [Test]
        public void TestMalformedEncodings()
        {
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;

            // A body shorter than the ML-DSA component must not surface as an out-of-range exception.
            Assert.Throws<ArgumentException>(
                () => CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, new byte[16]));
            Assert.Throws<ArgumentException>(
                () => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, new byte[16]));

            // Exactly the ML-DSA component (1312 bytes for ML-DSA-44), with no traditional component, is also
            // malformed.
            Assert.Throws<ArgumentException>(
                () => CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, new byte[1312]));

            // A signature shorter than the ML-DSA half is rejected rather than throwing.
            var keyPair = GenerateKeyPair(parameters);
            var signer = new CompositeMLDsaSigner(parameters);
            signer.Init(forSigning: false, keyPair.Public);
            signer.BlockUpdate(new byte[1], 0, 1);
            Assert.False(signer.VerifySignature(new byte[16]));
        }

        [Test]
        public void TestRsaModulusSize()
        {
            // Each RSA combination fixes the modulus size: any other size is malformed, however valid as RSA.
            var parameters = CompositeMLDsaParameters.MLDSA44_RSA2048_PSS_SHA256;
            GetVectorKeys(parameters, out byte[] pk, out byte[] sk);

            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024,
                100));
            var keyPair = generator.GenerateKeyPair();
            var publicKey = (RsaKeyParameters)keyPair.Public;
            var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            byte[] pk1024 = Arrays.Concatenate(Arrays.CopyOfRange(pk, 0, parameters.MLDsaPublicKeyLength),
                new RsaPublicKeyStructure(publicKey.Modulus, publicKey.Exponent).GetEncoded(Asn1Encodable.Der));
            AssertMalformed(() => CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, pk1024),
                "RSA-1024 public key under an RSA-2048 combination");

            byte[] sk1024 = Arrays.Concatenate(Arrays.CopyOfRange(sk, 0, parameters.MLDsaSeedLength),
                new RsaPrivateKeyStructure(privateKey.Modulus, privateKey.PublicExponent, privateKey.Exponent,
                    privateKey.P, privateKey.Q, privateKey.DP, privateKey.DQ, privateKey.QInv)
                    .GetEncoded(Asn1Encodable.Der));
            AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, sk1024),
                "RSA-1024 private key under an RSA-2048 combination");
        }

        [Test]
        public void TestECPrivateKeyCurve()
        {
            // The ECPrivateKey must carry its curve, and it must be the one the combination specifies.
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            GetVectorKeys(parameters, out _, out byte[] sk);

            byte[] seed = Arrays.CopyOfRange(sk, 0, parameters.MLDsaSeedLength);
            var d = ECPrivateKeyStructure.GetInstance(Arrays.CopyOfRange(sk, seed.Length, sk.Length)).GetKey();

            byte[] wrongCurve = Arrays.Concatenate(seed,
                new ECPrivateKeyStructure(256, d, SecObjectIdentifiers.SecP256k1).GetEncoded(Asn1Encodable.Der));
            AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, wrongCurve),
                "ECPrivateKey naming secp256k1 under a P-256 combination");

            byte[] noCurve = Arrays.Concatenate(seed,
                new ECPrivateKeyStructure(256, d).GetEncoded(Asn1Encodable.Der));
            AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, noCurve),
                "ECPrivateKey without parameters");
        }

        [Test]
        public void TestECPrivateKeyPublicKeyOmitted()
        {
            // The draft requires the ECPrivateKey to omit the optional publicKey field.
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            GetVectorKeys(parameters, out byte[] pk, out byte[] sk);

            byte[] seed = Arrays.CopyOfRange(sk, 0, parameters.MLDsaSeedLength);
            var d = ECPrivateKeyStructure.GetInstance(Arrays.CopyOfRange(sk, seed.Length, sk.Length)).GetKey();
            var publicPoint = new DerBitString(Arrays.CopyOfRange(pk, parameters.MLDsaPublicKeyLength, pk.Length));

            byte[] withPublicKey = Arrays.Concatenate(seed,
                new ECPrivateKeyStructure(256, d, publicPoint, SecObjectIdentifiers.SecP256r1)
                    .GetEncoded(Asn1Encodable.Der));
            AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, withPublicKey),
                "ECPrivateKey including the public key");
        }

        [Test]
        public void TestECPrivateKeyLength()
        {
            // RFC 5915 fixes the privateKey octets at the byte length of the curve order, here 32.
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            GetVectorKeys(parameters, out _, out byte[] sk);

            byte[] seed = Arrays.CopyOfRange(sk, 0, parameters.MLDsaSeedLength);
            byte[] d = ECPrivateKeyStructure.GetInstance(Arrays.CopyOfRange(sk, seed.Length, sk.Length))
                .PrivateKey.GetOctets();
            Assert.AreEqual(32, d.Length);

            // Both still denote valid scalars, so only the length check rejects them.
            byte[] shortD = Arrays.CopyOfRange(d, 1, d.Length);
            byte[] longD = Arrays.Prepend(d, 0x00);

            foreach (byte[] octets in new byte[][]{ shortD, longD })
            {
                byte[] encoding = Arrays.Concatenate(seed, new ECPrivateKeyStructure(new DerOctetString(octets),
                    SecObjectIdentifiers.SecP256r1, null).GetEncoded(Asn1Encodable.Der));
                AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, encoding),
                    "ECPrivateKey with " + octets.Length + " private key octets");
            }
        }

        [Test]
        public void TestDerEncoding()
        {
            // The draft requires DER; the same structures in valid BER, with a non-minimal length, are malformed.
            var rsa = CompositeMLDsaParameters.MLDSA44_RSA2048_PSS_SHA256;
            GetVectorKeys(rsa, out byte[] rsaPk, out byte[] rsaSk);

            byte[] berPk = Arrays.Concatenate(Arrays.CopyOfRange(rsaPk, 0, rsa.MLDsaPublicKeyLength),
                WithNonMinimalLength(Arrays.CopyOfRange(rsaPk, rsa.MLDsaPublicKeyLength, rsaPk.Length)));
            AssertMalformed(() => CompositeMLDsaPublicKeyParameters.FromEncoding(rsa, berPk),
                "BER-encoded RSAPublicKey");

            byte[] berSk = Arrays.Concatenate(Arrays.CopyOfRange(rsaSk, 0, rsa.MLDsaSeedLength),
                WithNonMinimalLength(Arrays.CopyOfRange(rsaSk, rsa.MLDsaSeedLength, rsaSk.Length)));
            AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(rsa, berSk),
                "BER-encoded RSAPrivateKey");

            var ec = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            GetVectorKeys(ec, out _, out byte[] ecSk);

            byte[] berEcSk = Arrays.Concatenate(Arrays.CopyOfRange(ecSk, 0, ec.MLDsaSeedLength),
                WithNonMinimalLength(Arrays.CopyOfRange(ecSk, ec.MLDsaSeedLength, ecSk.Length)));
            AssertMalformed(() => CompositeMLDsaPrivateKeyParameters.FromEncoding(ec, berEcSk),
                "BER-encoded ECPrivateKey");
        }

        [Test]
        public void TestECPublicKeyUncompressed()
        {
            // The draft mandates the uncompressed point; anything else would not re-encode to the same bytes.
            var parameters = CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256;
            GetVectorKeys(parameters, out byte[] pk, out _);

            byte[] mlDsaPk = Arrays.CopyOfRange(pk, 0, parameters.MLDsaPublicKeyLength);
            var q = ((ECPublicKeyParameters)CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, pk)
                .TraditionalPublicKey).Q;

            byte[] compressed = Arrays.Concatenate(mlDsaPk, q.GetEncoded(compressed: true));
            AssertMalformed(() => CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, compressed),
                "compressed EC point");

            byte[] hybridPoint = q.GetEncoded(compressed: false);
            hybridPoint[0] = (byte)(q.AffineYCoord.TestBitZero() ? 0x07 : 0x06);
            byte[] hybrid = Arrays.Concatenate(mlDsaPk, hybridPoint);
            AssertMalformed(() => CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, hybrid),
                "hybrid EC point");
        }

        [Test]
        public void TestTrailingBytes()
        {
            // The traditional component must consume the rest of the encoding exactly, for every family.
            foreach (var testVector in LoadTestVectors(out _))
            {
                string tcId = testVector["tcId"];
                if (!ParametersByTcId.TryGetValue(tcId, out var parameters))
                    continue;

                byte[] pk = Arrays.Append(Base64.Decode(testVector["pk"]), 0x00);
                Assert.Throws<ArgumentException>(() => CompositeMLDsaPublicKeyParameters.FromEncoding(parameters, pk),
                    tcId + ": public key with a trailing byte");

                byte[] sk = Arrays.Append(Base64.Decode(testVector["sk"]), 0x00);
                Assert.Throws<ArgumentException>(
                    () => CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, sk),
                    tcId + ": private key with a trailing byte");
            }
        }

        private static void AssertMalformed(TestDelegate decode, string message)
        {
            var e = Assert.Throws<ArgumentException>(decode, message);
            StringAssert.StartsWith("malformed composite", e.Message, message);
        }

        /// <summary>
        /// Re-encode the outer length of a DER object in long form with a redundant leading zero octet: still valid
        /// BER, but not DER.
        /// </summary>
        private static byte[] WithNonMinimalLength(byte[] der)
        {
            int lengthOctets = (der[1] & 0x80) == 0 ? 0 : der[1] & 0x7F;
            int contentsOff = 2 + lengthOctets;
            byte[] length = lengthOctets == 0 ? new byte[]{ der[1] } : Arrays.CopyOfRange(der, 2, contentsOff);

            return Arrays.ConcatenateAll(new byte[]{ der[0], (byte)(0x80 | (length.Length + 1)), 0x00 }, length,
                Arrays.CopyOfRange(der, contentsOff, der.Length));
        }

        private static void GetVectorKeys(CompositeMLDsaParameters parameters, out byte[] pk, out byte[] sk)
        {
            foreach (var testVector in LoadTestVectors(out _))
            {
                if (testVector["tcId"] == "id-" + parameters.Name)
                {
                    pk = Base64.Decode(testVector["pk"]);
                    sk = Base64.Decode(testVector["sk"]);
                    return;
                }
            }

            throw new InvalidOperationException("no test vector for " + parameters.Name);
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(CompositeMLDsaParameters parameters)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(parameters.Name);
            generator.Init(new KeyGenerationParameters(new SecureRandom(), 0));
            return generator.GenerateKeyPair();
        }

        private static bool Verify(CompositeMLDsaParameters parameters,
            CompositeMLDsaPublicKeyParameters publicKey, byte[] message, byte[] signature)
        {
            var signer = new CompositeMLDsaSigner(parameters);
            signer.Init(forSigning: false, publicKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }

        /// <summary>
        /// Just enough of a JSON reader for the published vector files, which contain nothing but nested
        /// objects, arrays and strings. Anything else is an error rather than something to guess at.
        /// </summary>
        private static class MiniJson
        {
            internal static object Parse(string s)
            {
                int pos = 0;
                object result = ParseValue(s, ref pos);
                SkipWhitespace(s, ref pos);
                if (pos != s.Length)
                    throw new IOException("trailing content in JSON at offset " + pos);
                return result;
            }

            private static object ParseValue(string s, ref int pos)
            {
                SkipWhitespace(s, ref pos);

                if (pos >= s.Length)
                    throw new IOException("unexpected end of JSON");

                switch (s[pos])
                {
                case '{': return ParseObject(s, ref pos);
                case '[': return ParseArray(s, ref pos);
                case '"': return ParseString(s, ref pos);
                default:
                    throw new IOException("unsupported JSON value at offset " + pos);
                }
            }

            private static IDictionary<string, object> ParseObject(string s, ref int pos)
            {
                var result = new Dictionary<string, object>();

                Expect(s, ref pos, '{');
                SkipWhitespace(s, ref pos);
                if (Peek(s, pos) == '}')
                {
                    ++pos;
                    return result;
                }

                for (;;)
                {
                    SkipWhitespace(s, ref pos);
                    string name = ParseString(s, ref pos);
                    SkipWhitespace(s, ref pos);
                    Expect(s, ref pos, ':');
                    result[name] = ParseValue(s, ref pos);

                    SkipWhitespace(s, ref pos);
                    char c = Peek(s, pos);
                    ++pos;
                    if (c == '}')
                        return result;
                    if (c != ',')
                        throw new IOException("malformed JSON object at offset " + (pos - 1));
                }
            }

            private static IList<object> ParseArray(string s, ref int pos)
            {
                var result = new List<object>();

                Expect(s, ref pos, '[');
                SkipWhitespace(s, ref pos);
                if (Peek(s, pos) == ']')
                {
                    ++pos;
                    return result;
                }

                for (;;)
                {
                    result.Add(ParseValue(s, ref pos));

                    SkipWhitespace(s, ref pos);
                    char c = Peek(s, pos);
                    ++pos;
                    if (c == ']')
                        return result;
                    if (c != ',')
                        throw new IOException("malformed JSON array at offset " + (pos - 1));
                }
            }

            private static string ParseString(string s, ref int pos)
            {
                Expect(s, ref pos, '"');

                var sb = new StringBuilder();
                for (;;)
                {
                    if (pos >= s.Length)
                        throw new IOException("unterminated JSON string");

                    char c = s[pos++];
                    if (c == '"')
                        return sb.ToString();

                    if (c != '\\')
                    {
                        sb.Append(c);
                        continue;
                    }

                    if (pos >= s.Length)
                        throw new IOException("unterminated JSON escape");

                    char e = s[pos++];
                    switch (e)
                    {
                    case '"':  sb.Append('"');  break;
                    case '\\': sb.Append('\\'); break;
                    case '/':  sb.Append('/');  break;
                    case 'b':  sb.Append('\b'); break;
                    case 'f':  sb.Append('\f'); break;
                    case 'n':  sb.Append('\n'); break;
                    case 'r':  sb.Append('\r'); break;
                    case 't':  sb.Append('\t'); break;
                    case 'u':
                        if (pos + 4 > s.Length)
                            throw new IOException("truncated JSON unicode escape");
                        sb.Append((char)Convert.ToInt32(s.Substring(pos, 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw new IOException("unsupported JSON escape at offset " + (pos - 1));
                    }
                }
            }

            private static char Peek(string s, int pos)
            {
                if (pos >= s.Length)
                    throw new IOException("unexpected end of JSON");

                return s[pos];
            }

            private static void Expect(string s, ref int pos, char c)
            {
                if (Peek(s, pos) != c)
                    throw new IOException("expected '" + c + "' at offset " + pos);

                ++pos;
            }

            private static void SkipWhitespace(string s, ref int pos)
            {
                while (pos < s.Length && char.IsWhiteSpace(s[pos]))
                {
                    ++pos;
                }
            }
        }
    }
}
