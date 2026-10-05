using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tests;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix.Tests
{
    /// <summary>
    /// Tests for CertPath validation of a certificate listed on a CRL with a reasonCode that RFC 5280 sec. 5.3.1 does
    /// not define.
    /// </summary>
    /// <remarks>
    /// The CRL entry is what revokes the certificate; an undefined reason code is treated as unspecified. In
    /// particular, codes 11 and 12 must not be confused with <see cref="CertStatus.Unrevoked"/> and
    /// <see cref="CertStatus.Undetermined"/>.
    /// </remarks>
    [TestFixture]
    public class CrlReasonCodeTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly TestCaseData[] ReasonCodeCases =
        {
            new TestCaseData(1L, "keyCompromise").SetArgDisplayNames("keyCompromise"),
            new TestCaseData(7L, "unspecified").SetArgDisplayNames("unused 7"),
            new TestCaseData(11L, "unspecified").SetArgDisplayNames("11 Unrevoked"),
            new TestCaseData(12L, "unspecified").SetArgDisplayNames("12 Undetermined"),
            new TestCaseData(1L << 40, "unspecified").SetArgDisplayNames("beyond int"),
        };

        private AsymmetricCipherKeyPair m_caKP;
        private X509Certificate m_caCert;
        private X509Certificate m_eeCert;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            m_caKP = GenerateRsaKP();
            m_caCert = TestUtilities.MakeTrustAnchor(m_caKP, "CN=Root,O=BC");
            m_eeCert = MakeEE(m_caCert, m_caKP.Private, GenerateRsaKP().Public);
        }

        [TestCaseSource(nameof(ReasonCodeCases))]
        public void RevokedWithReasonCode(long reasonCode, string expectedReason)
        {
            X509Crl crl = MakeCrl(m_caCert, m_caKP.Private, m_eeCert.SerialNumber, reasonCode);

            var e = Assert.Throws<PkixCertPathValidatorException>(() => Validate(m_caCert, m_eeCert, crl));

            Assert.AreEqual(0, e.Index);
            Assert.AreEqual(PkixCertPathValidatorReason.Revoked, e.Reason);
            StringAssert.EndsWith(", reason: " + expectedReason, e.Message);
        }

        private static AsymmetricCipherKeyPair GenerateRsaKP()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new KeyGenerationParameters(Random, 1024));
            return kpg.GenerateKeyPair();
        }

        private static X509Certificate MakeEE(X509Certificate caCert, AsymmetricKeyParameter caKey,
            AsymmetricKeyParameter eePublicKey)
        {
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(caCert.SubjectDN);
            certGen.SetSerialNumber(BigInteger.ValueOf(2));
            certGen.SetNotBefore(now.AddMinutes(-5));
            certGen.SetNotAfter(now.AddHours(1));
            certGen.SetSubjectDN(new X509Name("CN=EE"));
            certGen.SetPublicKey(eePublicKey);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(false));

            return certGen.Generate(new Asn1SignatureFactory("SHA256withRSA", caKey));
        }

        private static X509Crl MakeCrl(X509Certificate issuerCert, AsymmetricKeyParameter issuerKey,
            BigInteger serialNumber, long reasonCode)
        {
            DateTime now = DateTime.UtcNow;

            // Built directly, since the reasonCode values of interest are not all valid CrlReasons
            var entryExtGen = new X509ExtensionsGenerator();
            entryExtGen.AddExtension(X509Extensions.ReasonCode, false, new DerEnumerated(reasonCode));

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(issuerCert.SubjectDN);
            crlGen.SetThisUpdate(now.AddMinutes(-5));
            crlGen.SetNextUpdate(now.AddHours(1));
            crlGen.AddCrlEntry(serialNumber, now.AddMinutes(-1), entryExtGen.Generate());

            return crlGen.Generate(new Asn1SignatureFactory("SHA256withRSA", issuerKey));
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
    }
}
