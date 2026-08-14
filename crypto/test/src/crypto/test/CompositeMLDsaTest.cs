using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
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
                CompositeMLDsaParameters.MLDsa44_RSA2048_PSS_SHA256,
                CompositeMLDsaParameters.MLDsa44_RSA2048_PKCS15_SHA256,
                CompositeMLDsaParameters.MLDsa44_Ed25519_SHA512,
                CompositeMLDsaParameters.MLDsa44_ECDsa_P256_SHA256,
                CompositeMLDsaParameters.MLDsa65_RSA3072_PSS_SHA512,
                CompositeMLDsaParameters.MLDsa65_RSA3072_PKCS15_SHA512,
                CompositeMLDsaParameters.MLDsa65_RSA4096_PSS_SHA512,
                CompositeMLDsaParameters.MLDsa65_RSA4096_PKCS15_SHA512,
                CompositeMLDsaParameters.MLDsa65_ECDsa_P256_SHA512,
                CompositeMLDsaParameters.MLDsa65_ECDsa_P384_SHA512,
                CompositeMLDsaParameters.MLDsa65_ECDsa_brainpoolP256r1_SHA512,
                CompositeMLDsaParameters.MLDsa65_Ed25519_SHA512,
                CompositeMLDsaParameters.MLDsa87_ECDsa_P384_SHA512,
                CompositeMLDsaParameters.MLDsa87_ECDsa_brainpoolP384r1_SHA512,
                CompositeMLDsaParameters.MLDsa87_Ed448_SHAKE256,
                CompositeMLDsaParameters.MLDsa87_RSA3072_PSS_SHA512,
                CompositeMLDsaParameters.MLDsa87_RSA4096_PSS_SHA512,
                CompositeMLDsaParameters.MLDsa87_ECDsa_P521_SHA512,
            })
            {
                d.Add("id-" + parameters.Name, parameters);
            }
            return d;
        }

        private static IList<IDictionary<string, string>> LoadTestVectors(out byte[] message)
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
            var parameters = CompositeMLDsaParameters.MLDsa44_Ed25519_SHA512;
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
             * The two ML-DSA-65/Ed25519 and ML-DSA-44/Ed25519 combinations differ only in ML-DSA strength, but
             * the ML-DSA-65 pairing shares its pre-hash with several others; a signature must not verify under
             * a combination it was not made for. Use two combinations with identical component algorithms and
             * pre-hash but different domain separators.
             */
            var signing = CompositeMLDsaParameters.MLDsa65_ECDsa_P256_SHA512;
            var other = CompositeMLDsaParameters.MLDsa65_ECDsa_brainpoolP256r1_SHA512;

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
        public void TestCertificateGeneration()
        {
            var parameters = CompositeMLDsaParameters.MLDsa44_ECDsa_P256_SHA256;
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
            var parameters = CompositeMLDsaParameters.MLDsa44_ECDsa_P256_SHA256;

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

        private static AsymmetricCipherKeyPair GenerateKeyPair(CompositeMLDsaParameters parameters)
        {
            var generator = new CompositeMLDsaKeyPairGenerator();
            generator.Init(new CompositeMLDsaKeyGenerationParameters(new SecureRandom(), parameters));
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
