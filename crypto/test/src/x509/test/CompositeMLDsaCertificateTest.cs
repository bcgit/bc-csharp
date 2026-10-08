using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
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

namespace Org.BouncyCastle.X509.Tests
{
    /// <summary>
    /// The CA/RA certificate issuance flow with Composite ML-DSA keys, through public, algorithm-agnostic API only.
    /// </summary>
    /// <remarks>
    /// Nothing here names a Composite ML-DSA type: keys are held as <see cref="AsymmetricKeyParameter"/> and
    /// algorithms are chosen by name, exactly as for any other signature algorithm. The CA keys are the published
    /// test vector keys, so the test is fast and deterministic.
    /// </remarks>
    [TestFixture]
    public class CompositeMLDsaCertificateTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly char[] Password = "composite".ToCharArray();

        private static readonly string[] Names =
        {
            "MLDSA44-RSA2048-PSS-SHA256",
            "MLDSA44-RSA2048-PKCS15-SHA256",
            "MLDSA44-Ed25519-SHA512",
            "MLDSA44-ECDSA-P256-SHA256",
            "MLDSA65-RSA3072-PSS-SHA512",
            "MLDSA65-RSA3072-PKCS15-SHA512",
            "MLDSA65-RSA4096-PSS-SHA512",
            "MLDSA65-RSA4096-PKCS15-SHA512",
            "MLDSA65-ECDSA-P256-SHA512",
            "MLDSA65-ECDSA-P384-SHA512",
            "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
            "MLDSA65-Ed25519-SHA512",
            "MLDSA87-ECDSA-P384-SHA512",
            "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
            "MLDSA87-Ed448-SHAKE256",
            "MLDSA87-RSA3072-PSS-SHA512",
            "MLDSA87-RSA4096-PSS-SHA512",
            "MLDSA87-ECDSA-P521-SHA512",
        };

        // RSA key generation is slow, so the generated subjects cover one combination of each other family.
        private static readonly string[] GeneratedSubjectNames =
        {
            "MLDSA44-ECDSA-P256-SHA256",
            "MLDSA65-Ed25519-SHA512",
            "MLDSA87-Ed448-SHAKE256",
            "MLDSA44-RSA2048-PKCS15-SHA256",
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
                if (Array.IndexOf(Names, name) < 0)
                    continue;

                var privateKey = PrivateKeyFactory.CreateKey(Base64.Decode(testVector["sk_pkcs8"]));
                var publicKey = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]))
                    .GetPublicKey();

                m_vectorParties.Add(name, new Party(name, privateKey, publicKey));
            }

            Assert.AreEqual(Names.Length, m_vectorParties.Count, "test vector keys");
        }

        /// <summary>
        /// Each combination as the CA, issuing to a subject holding the next combination's key, so that every
        /// combination also appears once as a subject.
        /// </summary>
        [TestCaseSource(nameof(Names))]
        public void TestIssuance(string caName)
        {
            string subjectName = Names[(Array.IndexOf(Names, caName) + 1) % Names.Length];

            RunIssuance(m_vectorParties[caName], m_vectorParties[subjectName]);
        }

        [TestCaseSource(nameof(GeneratedSubjectNames))]
        public void TestIssuanceToGeneratedSubject(string subjectName)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(subjectName);
            generator.Init(new KeyGenerationParameters(Random, 0));
            var keyPair = generator.GenerateKeyPair();

            RunIssuance(m_vectorParties["MLDSA65-ECDSA-P384-SHA512"],
                new Party(subjectName, keyPair.Private, keyPair.Public));
        }

        [Test]
        public void TestCompositeCAIssuingToECSubject()
        {
            RunIssuance(m_vectorParties["MLDSA65-ECDSA-P384-SHA512"], GenerateECParty());
        }

        [Test]
        public void TestECCAIssuingToCompositeSubject()
        {
            RunIssuance(GenerateECParty(), m_vectorParties["MLDSA44-ECDSA-P256-SHA256"]);
        }

        [Test]
        public void TestMLDsaCAIssuingToCompositeSubject()
        {
            RunIssuance(GenerateMLDsaParty(), m_vectorParties["MLDSA65-ECDSA-P256-SHA512"]);
        }

        private static void RunIssuance(Party ca, Party subject)
        {
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

            // 3. CA: a self-signed CA certificate, then two certificates for the requested key, one to revoke.
            var caCert = MakeCACertificate(ca, caDN);
            var subjectCert = IssueCertificate(ca, caCert, subjectPublicKeyInfo, subjectDN, BigInteger.Two);
            var revokedCert = IssueCertificate(ca, caCert, subjectPublicKeyInfo, subjectDN, BigInteger.Three);

            foreach (var cert in new X509Certificate[]{ caCert, subjectCert })
            {
                CheckAlgorithm(ca.Algorithm, cert.SignatureAlgorithm, "certificate");
                if (IsComposite(ca.Algorithm))
                {
                    Assert.AreEqual(ca.Algorithm, cert.SigAlgName, ca.Algorithm + ": certificate SigAlgName");
                }
            }

            // 4. Over the wire: re-parse both, verify each against its issuer, and use the subject's key.
            var parser = new X509CertificateParser();
            var parsedCACert = parser.ReadCertificate(caCert.GetEncoded());
            var parsedSubjectCert = parser.ReadCertificate(subjectCert.GetEncoded());

            parsedCACert.Verify(parsedCACert.GetPublicKey());
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

            // 5. Revocation: a CRL revoking one of the two, then revocation-enabled path validation.
            var crl = new X509CrlParser().ReadCrl(MakeCrl(ca, caCert, revokedCert.SerialNumber).GetEncoded());
            CheckAlgorithm(ca.Algorithm, crl.CertificateList.SignatureAlgorithm, "CRL");
            crl.Verify(parsedCACert.GetPublicKey());

            Validate(parsedCACert, parsedSubjectCert, crl);

            var e = Assert.Throws<PkixCertPathValidatorException>(() => Validate(parsedCACert, revokedCert, crl),
                ca.Algorithm + ": revoked certificate must not validate");
            Assert.AreEqual(PkixCertPathValidatorReason.Revoked, e.Reason, ca.Algorithm + ": rejection reason");

            // 6. Key storage: PKCS#8, PKCS#12 with the certificate chain, and PEM.
            byte[] pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subject.Private).GetEncoded(Asn1Encodable.Der);
            CheckSamePrivateKey(pkcs8, PrivateKeyFactory.CreateKey(pkcs8), subject.Algorithm + ": PKCS#8");

            CheckPkcs12(subject, pkcs8, parsedSubjectCert, parsedCACert);
            CheckPem(subject, pkcs8, parsedSubjectCert, request);
        }

        private static X509Certificate MakeCACertificate(Party ca, X509Name caDN)
        {
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(caDN);
            certGen.SetSubjectDN(caDN);
            certGen.SetNotBefore(now.AddMinutes(-5));
            certGen.SetNotAfter(now.AddDays(1));
            certGen.SetPublicKey(ca.Public);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(true));
            certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(ca.Public));

            return certGen.Generate(new Asn1SignatureFactory(ca.Algorithm, ca.Private, Random));
        }

        private static X509Certificate IssueCertificate(Party ca, X509Certificate caCert,
            SubjectPublicKeyInfo subjectPublicKeyInfo, X509Name subjectDN, BigInteger serialNumber)
        {
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(caCert.SubjectDN);
            certGen.SetSubjectDN(subjectDN);
            certGen.SetNotBefore(now.AddMinutes(-5));
            certGen.SetNotAfter(now.AddHours(1));
            certGen.SetSubjectPublicKeyInfo(subjectPublicKeyInfo);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(false));
            certGen.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.DigitalSignature));
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

        private static void Validate(X509Certificate caCert, X509Certificate eeCert, X509Crl crl)
        {
            var certPath = new PkixCertPath(new List<X509Certificate>{ eeCert });

            var trustAnchors = new HashSet<TrustAnchor>{ new TrustAnchor(caCert, null) };

            var pkixParams = new PkixParameters(trustAnchors);
            pkixParams.AddStoreCert(CollectionUtilities.CreateStore(new List<X509Certificate>{ caCert, eeCert }));
            pkixParams.AddStoreCrl(CollectionUtilities.CreateStore(new List<X509Crl>{ crl }));
            pkixParams.Date = DateTime.UtcNow;
            pkixParams.IsRevocationEnabled = true;

            new PkixCertPathValidator().Validate(certPath, pkixParams);
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
            generator.Init(new MLDsaKeyGenerationParameters(Random, NistObjectIdentifiers.id_ml_dsa_65));
            var keyPair = generator.GenerateKeyPair();
            return new Party("ML-DSA-65", keyPair.Private, keyPair.Public);
        }

        private static bool IsComposite(string algorithm) => Array.IndexOf(Names, algorithm) >= 0;
    }
}
