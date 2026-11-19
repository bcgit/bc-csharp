using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Isara;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// XMSS and XMSS^MT reached through the name and OID registries: <see cref="SignerUtilities"/>,
    /// <see cref="GeneratorUtilities"/>, and the X.509 signature factory that resolves "XMSS" to the RFC 9802
    /// algorithm identifier.
    /// </summary>
    [TestFixture]
    public class XmssUtilitiesRegistrationTests
    {
        private static readonly byte[] Message = { 0x61, 0x62, 0x63 };

        [Test]
        public void SignerUtilities_GetSigner_Xmss_SignsAndVerifies()
        {
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(4);

            ISigner signer = SignerUtilities.GetSigner("XMSS");

            Assert.IsInstanceOf(typeof(XmssSigner), signer);
            Assert.AreEqual("XMSS", signer.AlgorithmName);

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);
            byte[] signature = signer.GenerateSignature();

            ISigner verifier = SignerUtilities.InitSigner("xmss", false, kp.Public, null);
            verifier.BlockUpdate(Message, 0, Message.Length);

            Assert.IsTrue(verifier.VerifySignature(signature));
        }

        [Test]
        public void SignerUtilities_GetSigner_XmssMT_SignsAndVerifies()
        {
            AsymmetricCipherKeyPair kp = GenerateXmssMTKeyPair(4, 2);

            ISigner signer = SignerUtilities.GetSigner("XMSSMT");

            Assert.IsInstanceOf(typeof(XmssMTSigner), signer);
            Assert.AreEqual("XMSSMT", signer.AlgorithmName);

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);
            byte[] signature = signer.GenerateSignature();

            ISigner verifier = SignerUtilities.InitSigner("xmssmt", false, kp.Public, null);
            verifier.BlockUpdate(Message, 0, Message.Length);

            Assert.IsTrue(verifier.VerifySignature(signature));
        }

        [Test]
        public void SignerUtilities_GetSigner_ByOid_ResolvesXmssAndXmssMT()
        {
            DerObjectIdentifier[] xmssOids = {
                IanaObjectIdentifiers.id_alg_xmss_hashsig,
                PqcObjectIdentifiers.xmss,
                IsaraObjectIdentifiers.id_alg_xmss,
            };
            foreach (DerObjectIdentifier oid in xmssOids)
            {
                Assert.IsInstanceOf(typeof(XmssSigner), SignerUtilities.GetSigner(oid), oid.Id);
                Assert.IsInstanceOf(typeof(XmssSigner), SignerUtilities.GetSigner(oid.Id), oid.Id);
                Assert.AreEqual("XMSS", SignerUtilities.GetEncodingName(oid), oid.Id);
            }

            DerObjectIdentifier[] xmssMTOids = {
                IanaObjectIdentifiers.id_alg_xmssmt_hashsig,
                PqcObjectIdentifiers.xmss_mt,
                IsaraObjectIdentifiers.id_alg_xmssmt,
            };
            foreach (DerObjectIdentifier oid in xmssMTOids)
            {
                Assert.IsInstanceOf(typeof(XmssMTSigner), SignerUtilities.GetSigner(oid), oid.Id);
                Assert.IsInstanceOf(typeof(XmssMTSigner), SignerUtilities.GetSigner(oid.Id), oid.Id);
                Assert.AreEqual("XMSSMT", SignerUtilities.GetEncodingName(oid), oid.Id);
            }

            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmss_hashsig, SignerUtilities.GetObjectIdentifier("XMSS"));
            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmssmt_hashsig,
                SignerUtilities.GetObjectIdentifier("XMSSMT"));
            CollectionAssert.Contains(SignerUtilities.Algorithms, "XMSS");
            CollectionAssert.Contains(SignerUtilities.Algorithms, "XMSSMT");
        }

        [Test]
        public void GeneratorUtilities_GetKeyPairGenerator_Xmss()
        {
            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("XMSS");

            Assert.IsInstanceOf(typeof(XmssKeyPairGenerator), kpg);
            Assert.IsInstanceOf(typeof(XmssKeyPairGenerator), GeneratorUtilities.GetKeyPairGenerator("xmss"));

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(4, new Sha256Digest())));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            Assert.IsInstanceOf(typeof(XmssPrivateKeyParameters), kp.Private);
            Assert.IsInstanceOf(typeof(XmssPublicKeyParameters), kp.Public);
        }

        [Test]
        public void GeneratorUtilities_GetKeyPairGenerator_XmssMT()
        {
            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("XMSSMT");

            Assert.IsInstanceOf(typeof(XmssMTKeyPairGenerator), kpg);
            Assert.IsInstanceOf(typeof(XmssMTKeyPairGenerator), GeneratorUtilities.GetKeyPairGenerator("xmssmt"));

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(4, 2, new Sha256Digest())));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            Assert.IsInstanceOf(typeof(XmssMTPrivateKeyParameters), kp.Private);
            Assert.IsInstanceOf(typeof(XmssMTPublicKeyParameters), kp.Public);
        }

        /// <summary>The key pair generators answer to the OIDs the signers answer to.</summary>
        [Test]
        public void GeneratorUtilities_GetKeyPairGenerator_ByOid()
        {
            foreach (DerObjectIdentifier oid in new DerObjectIdentifier[]{ IanaObjectIdentifiers.id_alg_xmss_hashsig,
                PqcObjectIdentifiers.xmss, IsaraObjectIdentifiers.id_alg_xmss })
            {
                Assert.IsInstanceOf(typeof(XmssKeyPairGenerator), GeneratorUtilities.GetKeyPairGenerator(oid), oid.Id);
                Assert.IsInstanceOf(typeof(XmssKeyPairGenerator), GeneratorUtilities.GetKeyPairGenerator(oid.Id),
                    oid.Id);
            }

            foreach (DerObjectIdentifier oid in new DerObjectIdentifier[]{
                IanaObjectIdentifiers.id_alg_xmssmt_hashsig, PqcObjectIdentifiers.xmss_mt,
                IsaraObjectIdentifiers.id_alg_xmssmt })
            {
                Assert.IsInstanceOf(typeof(XmssMTKeyPairGenerator), GeneratorUtilities.GetKeyPairGenerator(oid),
                    oid.Id);
                Assert.IsInstanceOf(typeof(XmssMTKeyPairGenerator), GeneratorUtilities.GetKeyPairGenerator(oid.Id),
                    oid.Id);
            }
        }

        [Test]
        [Explicit] // slow: ~36s
        public void SelfSignedCertificate_Xmss_Verifies()
        {
            CheckSelfSignedCertificate(GenerateXmssKeyPair(10), "XMSS", IanaObjectIdentifiers.id_alg_xmss_hashsig);
        }

        [Test]
        public void SelfSignedCertificate_XmssSmallTree_Verifies()
        {
            CheckSelfSignedCertificate(GenerateXmssKeyPair(2), "XMSS", IanaObjectIdentifiers.id_alg_xmss_hashsig);
        }

        [Test]
        public void SelfSignedCertificate_XmssMTSmallTree_Verifies()
        {
            CheckSelfSignedCertificate(GenerateXmssMTKeyPair(4, 2), "XMSSMT",
                IanaObjectIdentifiers.id_alg_xmssmt_hashsig);
        }

        /// <summary>
        /// A registered parameter set, whose public key goes into the certificate in the RFC 9802 form: the hashsig
        /// OID with the parameters absent, and the raw RFC 8391 key. XMSSMT-SHA2_20/4_256 has subtrees of 32 leaves,
        /// small enough for the default run; the other heights above carry no parameter set identifier and go in
        /// the legacy form.
        /// </summary>
        [Test]
        public void SelfSignedCertificate_XmssMTRfc9802PublicKey_Verifies()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), XmssMTParameters.LookupByOid(2)));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            X509Certificate cert = CheckSelfSignedCertificate(kp, "XMSSMT",
                IanaObjectIdentifiers.id_alg_xmssmt_hashsig);

            AlgorithmIdentifier keyAlgID = cert.SubjectPublicKeyInfo.Algorithm;
            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmssmt_hashsig, keyAlgID.Algorithm);
            Assert.IsNull(keyAlgID.Parameters);
            Assert.AreEqual(((XmssMTPublicKeyParameters)kp.Public).GetEncoded(),
                cert.SubjectPublicKeyInfo.PublicKey.GetOctets());
        }

        private static X509Certificate CheckSelfSignedCertificate(AsymmetricCipherKeyPair kp, string algorithm,
            DerObjectIdentifier expectedSigOid)
        {
            X509Name name = new X509Name("CN=XMSS Test");

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(name);
            certGen.SetSubjectDN(name);
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            certGen.SetPublicKey(kp.Public);

            X509Certificate cert = certGen.Generate(new Asn1SignatureFactory(algorithm, kp.Private));

            // RFC 9802: the signature AlgorithmIdentifier carries the hashsig OID with the parameters absent
            AlgorithmIdentifier sigAlgID = cert.SignatureAlgorithm;
            Assert.AreEqual(expectedSigOid, sigAlgID.Algorithm);
            Assert.IsNull(sigAlgID.Parameters);

            cert.Verify(kp.Public);

            // and again from the encoding, with the public key recovered from the certificate itself
            X509Certificate parsed = new X509Certificate(cert.GetEncoded());
            parsed.Verify(parsed.GetPublicKey());
            Assert.IsTrue(parsed.IsSignatureValid(kp.Public));

            return parsed;
        }

        private static AsymmetricCipherKeyPair GenerateXmssKeyPair(int height)
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();
            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(height, new Sha256Digest())));
            return kpg.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateXmssMTKeyPair(int height, int layers)
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(height, layers, new Sha256Digest())));
            return kpg.GenerateKeyPair();
        }
    }
}
