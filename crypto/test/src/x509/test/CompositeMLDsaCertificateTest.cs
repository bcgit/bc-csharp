using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.X509.Tests
{
    /// <summary>
    /// The CA/RA certificate issuance flow with Composite ML-DSA keys, through public, algorithm-agnostic API only.
    /// </summary>
    /// <remarks>
    /// Beyond listing the combinations, nothing here names a Composite ML-DSA type: keys are held as
    /// <see cref="AsymmetricKeyParameter"/> and algorithms are chosen by name, exactly as for any other signature
    /// algorithm. The composite root and CA keys are the published test vector keys, so the test is fast and
    /// deterministic.
    /// </remarks>
    [TestFixture]
    public class CompositeMLDsaCertificateTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly char[] Password = "composite".ToCharArray();

        // The root for the tests that are not run per combination.
        private static readonly string RootName = CompositeMLDsaParameters.MLDSA87_Ed448_SHAKE256.Name;

        private static readonly IList<string> Names = new List<string>(CompositeMLDsaParameters.ByName.Keys);

        // RSA key generation is slow, so the generated subjects cover one combination of each other family.
        private static readonly string[] GeneratedSubjectNames =
        {
            CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256.Name,
            CompositeMLDsaParameters.MLDSA65_Ed25519_SHA512.Name,
            CompositeMLDsaParameters.MLDSA87_Ed448_SHAKE256.Name,
            CompositeMLDsaParameters.MLDSA44_RSA2048_PKCS15_SHA256.Name,
        };

        private sealed class Party
        {
            internal Party(string algorithm, AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey)
            {
                Algorithm = algorithm;
                Private = privateKey;
                Public = publicKey;
            }

            /// <summary>The signature algorithm this party signs with.</summary>
            internal string Algorithm { get; }

            internal AsymmetricKeyParameter Private { get; }

            internal AsymmetricKeyParameter Public { get; }
        }

        private IDictionary<string, Party> m_vectorParties;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            m_vectorParties = new Dictionary<string, Party>();
            foreach (var testVector in CompositeMLDsaTest.LoadTestVectors(out _))
            {
                string name = testVector["tcId"].Substring("id-".Length);
                if (!IsComposite(name))
                    continue;

                var privateKey = PrivateKeyFactory.CreateKey(Base64.Decode(testVector["sk_pkcs8"]));
                var publicKey = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]))
                    .GetPublicKey();

                m_vectorParties.Add(name, new Party(name, privateKey, publicKey));
            }

            Assert.AreEqual(Names.Count, m_vectorParties.Count, "test vector keys");
        }

        /// <summary>
        /// Each combination as the CA, under a root holding the previous combination's key and issuing to a subject
        /// holding the next combination's key, so that every combination also appears once as a root and once as a
        /// subject.
        /// </summary>
        [TestCaseSource(nameof(Names))]
        public void TestIssuance(string caName)
        {
            int index = Names.IndexOf(caName);
            string rootName = Names[(index + Names.Count - 1) % Names.Count];
            string subjectName = Names[(index + 1) % Names.Count];

            RunIssuance(m_vectorParties[rootName], m_vectorParties[caName], m_vectorParties[subjectName]);
        }

        [TestCaseSource(nameof(GeneratedSubjectNames))]
        public void TestIssuanceToGeneratedSubject(string subjectName)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(subjectName);
            generator.Init(new KeyGenerationParameters(Random, 0));
            var keyPair = generator.GenerateKeyPair();

            RunIssuance(m_vectorParties[RootName],
                m_vectorParties[CompositeMLDsaParameters.MLDSA65_ECDSA_P384_SHA512.Name],
                new Party(subjectName, keyPair.Private, keyPair.Public));
        }

        [Test]
        public void TestCompositeCAIssuingToECSubject()
        {
            RunIssuance(m_vectorParties[RootName],
                m_vectorParties[CompositeMLDsaParameters.MLDSA65_ECDSA_P384_SHA512.Name], GenerateECParty());
        }

        [Test]
        public void TestECCAIssuingToCompositeSubject()
        {
            RunIssuance(m_vectorParties[RootName], GenerateECParty(),
                m_vectorParties[CompositeMLDsaParameters.MLDSA44_ECDSA_P256_SHA256.Name]);
        }

        [Test]
        public void TestMLDsaCAIssuingToCompositeSubject()
        {
            RunIssuance(m_vectorParties[RootName], GenerateMLDsaParty(),
                m_vectorParties[CompositeMLDsaParameters.MLDSA65_ECDSA_P256_SHA512.Name]);
        }

        private static void RunIssuance(Party root, Party ca, Party subject)
        {
            var rootDN = new X509Name("CN=" + root.Algorithm + " Root CA,O=Bouncy Castle");
            var caDN = new X509Name("CN=" + ca.Algorithm + " CA,O=Bouncy Castle");
            var subjectDN = new X509Name("CN=" + subject.Algorithm + " Subject,O=Bouncy Castle");

            // 1. Subject: a PKCS#10 request, signed with the subject's own key as proof of possession.
            byte[] requestEncoding = new Pkcs10CertificationRequest(
                new Asn1SignatureFactory(subject.Algorithm, subject.Private, Random), subjectDN, subject.Public,
                null).GetEncoded();

            // 2. RA: parse the request, check the proof of possession, and take the key it carries.
            var request = new Pkcs10CertificationRequest(requestEncoding);
            Assert.True(request.Verify(), subject.Algorithm + ": PKCS#10 proof of possession");
            CheckAlgorithm(subject.Algorithm, request.SignatureAlgorithm, "PKCS#10 request");
            var subjectPublicKeyInfo = request.GetCertificationRequestInfo().SubjectPublicKeyInfo;

            /*
             * 3. CA: a self-signed root issues the intermediate CA certificate, and the CA issues the certificate for
             * the requested key. Each also issues a second certificate to revoke, and the CA issues a certificate
             * under the one to be revoked.
             */
            var caPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ca.Public);

            var rootCert = MakeRootCertificate(root, rootDN);
            var caCert = IssueCertificate(root, rootCert, caPublicKeyInfo, caDN, BigInteger.Two, isCA: true);
            var revokedCACert = IssueCertificate(root, rootCert, caPublicKeyInfo, caDN, BigInteger.Three, isCA: true);

            var subjectCert = IssueCertificate(ca, caCert, subjectPublicKeyInfo, subjectDN, BigInteger.Two,
                isCA: false);
            var revokedCert = IssueCertificate(ca, caCert, subjectPublicKeyInfo, subjectDN, BigInteger.Three,
                isCA: false);
            var underRevokedCACert = IssueCertificate(ca, revokedCACert, subjectPublicKeyInfo, subjectDN,
                BigInteger.Four, isCA: false);

            CheckCertificateAlgorithm(root.Algorithm, rootCert);
            CheckCertificateAlgorithm(root.Algorithm, caCert);
            CheckCertificateAlgorithm(ca.Algorithm, subjectCert);

            // 4. Over the wire: re-parse the chain, verify each against its issuer, and use the subject's key.
            var parser = new X509CertificateParser();
            var parsedRootCert = parser.ReadCertificate(rootCert.GetEncoded());
            var parsedCACert = parser.ReadCertificate(caCert.GetEncoded());
            var parsedSubjectCert = parser.ReadCertificate(subjectCert.GetEncoded());

            parsedRootCert.Verify(parsedRootCert.GetPublicKey());
            parsedCACert.Verify(parsedRootCert.GetPublicKey());
            parsedSubjectCert.Verify(parsedCACert.GetPublicKey());

            byte[] message = Strings.ToByteArray("signed by the certified key");
            var signer = SignerUtilities.GetSigner(subject.Algorithm);
            signer.Init(forSigning: true, new ParametersWithRandom(subject.Private, Random));
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();

            var verifier = SignerUtilities.GetSigner(subject.Algorithm);
            verifier.Init(forSigning: false, parsedSubjectCert.GetPublicKey());
            verifier.BlockUpdate(message, 0, message.Length);
            Assert.True(verifier.VerifySignature(signature), subject.Algorithm + ": key from issued certificate");

            /*
             * 5. Revocation: a CRL from each CA, revoking its second certificate, then revocation-enabled path
             * validation of the two-certificate path below the root.
             */
            var crlParser = new X509CrlParser();

            var rootCrl = crlParser.ReadCrl(MakeCrl(root, rootCert, revokedCACert.SerialNumber).GetEncoded());
            CheckAlgorithm(root.Algorithm, rootCrl.CertificateList.SignatureAlgorithm, "root CRL");
            rootCrl.Verify(parsedRootCert.GetPublicKey());

            var caCrl = crlParser.ReadCrl(MakeCrl(ca, caCert, revokedCert.SerialNumber).GetEncoded());
            CheckAlgorithm(ca.Algorithm, caCrl.CertificateList.SignatureAlgorithm, "CRL");
            caCrl.Verify(parsedCACert.GetPublicKey());

            var crls = new X509Crl[]{ rootCrl, caCrl };

            Validate(parsedRootCert, parsedCACert, parsedSubjectCert, crls);

            var builtPath = BuildPath(parsedRootCert, parsedCACert, parsedSubjectCert, crls).Certificates;
            Assert.AreEqual(2, builtPath.Count, ca.Algorithm + ": built path length");
            Assert.AreEqual(parsedSubjectCert, builtPath[0], ca.Algorithm + ": built path subject certificate");
            Assert.AreEqual(parsedCACert, builtPath[1], ca.Algorithm + ": built path CA certificate");

            var e = Assert.Throws<PkixCertPathValidatorException>(
                () => Validate(parsedRootCert, parsedCACert, revokedCert, crls),
                ca.Algorithm + ": revoked certificate must not validate");
            Assert.AreEqual(PkixCertPathValidatorReason.Revoked, e.Reason, ca.Algorithm + ": rejection reason");
            Assert.AreEqual(0, e.Index, ca.Algorithm + ": rejected certificate");

            e = Assert.Throws<PkixCertPathValidatorException>(
                () => Validate(parsedRootCert, revokedCACert, underRevokedCACert, crls),
                root.Algorithm + ": certificate under a revoked CA must not validate");
            Assert.AreEqual(PkixCertPathValidatorReason.Revoked, e.Reason, root.Algorithm + ": CA rejection reason");
            Assert.AreEqual(1, e.Index, root.Algorithm + ": rejected CA certificate");

            // 6. Key storage: PKCS#8, PKCS#12 with the certificate chain, and PEM.
            byte[] pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subject.Private).GetEncoded(Asn1Encodable.Der);
            CheckSamePrivateKey(pkcs8, PrivateKeyFactory.CreateKey(pkcs8), subject.Algorithm + ": PKCS#8");

            CheckPkcs12(subject, pkcs8, parsedSubjectCert, parsedCACert);
            CheckPem(subject, pkcs8, parsedSubjectCert, request);
        }

        private static X509Certificate MakeRootCertificate(Party root, X509Name rootDN)
        {
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(rootDN);
            certGen.SetSubjectDN(rootDN);
            certGen.SetNotBefore(now.AddMinutes(-5));
            certGen.SetNotAfter(now.AddDays(1));
            certGen.SetPublicKey(root.Public);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(true));
            certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(root.Public));

            return certGen.Generate(new Asn1SignatureFactory(root.Algorithm, root.Private, Random));
        }

        private static X509Certificate IssueCertificate(Party ca, X509Certificate caCert,
            SubjectPublicKeyInfo subjectPublicKeyInfo, X509Name subjectDN, BigInteger serialNumber, bool isCA)
        {
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(caCert.SubjectDN);
            certGen.SetSubjectDN(subjectDN);
            certGen.SetNotBefore(now.AddMinutes(-5));
            certGen.SetNotAfter(now.AddHours(1));
            certGen.SetSubjectPublicKeyInfo(subjectPublicKeyInfo);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(isCA));
            certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(isCA ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature));
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caCert));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectPublicKeyInfo));

            return certGen.Generate(new Asn1SignatureFactory(ca.Algorithm, ca.Private, Random));
        }

        private static X509Crl MakeCrl(Party ca, X509Certificate caCert, BigInteger revokedSerialNumber)
        {
            DateTime now = DateTime.UtcNow;

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(caCert.SubjectDN);
            crlGen.SetThisUpdate(now.AddMinutes(-5));
            crlGen.SetNextUpdate(now.AddHours(1));
            crlGen.AddCrlEntry(revokedSerialNumber, now.AddMinutes(-1), CrlReason.KeyCompromise);

            return crlGen.Generate(new Asn1SignatureFactory(ca.Algorithm, ca.Private, Random));
        }

        private static void Validate(X509Certificate rootCert, X509Certificate caCert, X509Certificate eeCert,
            X509Crl[] crls)
        {
            var pkixParams = new PkixParameters(CreateTrustAnchors(rootCert));
            ConfigureParameters(pkixParams, rootCert, caCert, eeCert, crls);

            var certPath = new PkixCertPath(new List<X509Certificate>{ eeCert, caCert });

            new PkixCertPathValidator().Validate(certPath, pkixParams);
        }

        private static PkixCertPath BuildPath(X509Certificate rootCert, X509Certificate caCert, X509Certificate eeCert,
            X509Crl[] crls)
        {
            var target = new X509CertStoreSelector{ Certificate = eeCert };

            var pkixParams = new PkixBuilderParameters(CreateTrustAnchors(rootCert), target);
            ConfigureParameters(pkixParams, rootCert, caCert, eeCert, crls);

            return new PkixCertPathBuilder().Build(pkixParams).CertPath;
        }

        private static ISet<TrustAnchor> CreateTrustAnchors(X509Certificate rootCert) =>
            new HashSet<TrustAnchor>{ new TrustAnchor(rootCert, null) };

        private static void ConfigureParameters(PkixParameters pkixParams, X509Certificate rootCert,
            X509Certificate caCert, X509Certificate eeCert, X509Crl[] crls)
        {
            pkixParams.AddStoreCert(
                CollectionUtilities.CreateStore(new List<X509Certificate>{ rootCert, caCert, eeCert }));
            pkixParams.AddStoreCrl(CollectionUtilities.CreateStore(new List<X509Crl>(crls)));
            pkixParams.Date = DateTime.UtcNow;
            pkixParams.IsRevocationEnabled = true;
        }

        private static void CheckPkcs12(Party subject, byte[] pkcs8, X509Certificate subjectCert,
            X509Certificate caCert)
        {
            var store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry("subject", new AsymmetricKeyEntry(subject.Private),
                new X509CertificateEntry[]{ new X509CertificateEntry(subjectCert), new X509CertificateEntry(caCert) });

            var bOut = new MemoryStream();
            store.Save(bOut, Password, Random);

            var loaded = new Pkcs12StoreBuilder().Build();
            loaded.Load(new MemoryStream(bOut.ToArray(), false), Password);

            CheckSamePrivateKey(pkcs8, loaded.GetKey("subject").Key, subject.Algorithm + ": PKCS#12 key");

            var chain = loaded.GetCertificateChain("subject");
            Assert.AreEqual(2, chain.Length, subject.Algorithm + ": PKCS#12 chain length");
            Assert.AreEqual(subjectCert, chain[0].Certificate, subject.Algorithm + ": PKCS#12 subject certificate");
            Assert.AreEqual(caCert, chain[1].Certificate, subject.Algorithm + ": PKCS#12 CA certificate");
        }

        private static void CheckPem(Party subject, byte[] pkcs8, X509Certificate subjectCert,
            Pkcs10CertificationRequest request)
        {
            var sw = new StringWriter();
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(subject.Private);
            pemWriter.WriteObject(subjectCert);
            pemWriter.WriteObject(request);
            pemWriter.Writer.Flush();

            var pemReader = new PemReader(new StringReader(sw.ToString()));

            // Traditional key types use their own PEM types, which read back as a key pair.
            object key = pemReader.ReadObject();
            var privateKey = key as AsymmetricKeyParameter ?? ((AsymmetricCipherKeyPair)key).Private;
            CheckSamePrivateKey(pkcs8, privateKey, subject.Algorithm + ": PEM key");

            Assert.AreEqual(subjectCert, pemReader.ReadObject(), subject.Algorithm + ": PEM certificate");
            Assert.AreEqual(request, pemReader.ReadObject(), subject.Algorithm + ": PEM request");
            Assert.IsNull(pemReader.ReadObject(), subject.Algorithm + ": PEM end");
        }

        private static void CheckCertificateAlgorithm(string algorithm, X509Certificate cert)
        {
            CheckAlgorithm(algorithm, cert.SignatureAlgorithm, "certificate");
            if (IsComposite(algorithm))
            {
                Assert.AreEqual(algorithm, cert.SigAlgName, algorithm + ": certificate SigAlgName");
            }
        }

        private static void CheckAlgorithm(string algorithm, AlgorithmIdentifier algID, string what)
        {
            Assert.AreEqual(SignerUtilities.GetObjectIdentifier(algorithm), algID.Algorithm,
                algorithm + ": " + what + " signature algorithm");
            Assert.IsNull(algID.Parameters, algorithm + ": " + what + " AlgorithmIdentifier must omit parameters");
        }

        private static void CheckSamePrivateKey(byte[] expectedPkcs8, AsymmetricKeyParameter privateKey,
            string message)
        {
            Assert.True(Arrays.AreEqual(expectedPkcs8,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded(Asn1Encodable.Der)), message);
        }

        private static Party GenerateECParty()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("EC");
            generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));
            var keyPair = generator.GenerateKeyPair();
            return new Party("SHA256withECDSA", keyPair.Private, keyPair.Public);
        }

        private static Party GenerateMLDsaParty()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("ML-DSA");
            generator.Init(new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_65));
            var keyPair = generator.GenerateKeyPair();
            return new Party(MLDsaParameters.ml_dsa_65.Name, keyPair.Private, keyPair.Public);
        }

        private static bool IsComposite(string algorithm) => CompositeMLDsaParameters.ByName.ContainsKey(algorithm);
    }
}
