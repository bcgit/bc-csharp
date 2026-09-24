using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cert.Tests
{
    /// <summary>
    /// Two certification authorities share a Subject DN, and each delegates CRL signing to a second certificate
    /// carrying that same DN, so every CRL and every candidate CRL signer in the PKI is indistinguishable by name.
    /// Building a path for an end-entity certificate under the first authority used to re-enter the CRL check for
    /// the same signer indefinitely, because each candidate signer triggered a further path build
    /// (github bc-java #2291).
    /// </summary>
    [TestFixture]
    public class CertPathLoopTest
    {
        private const string SignatureAlgorithm = "SHA256withRSA";

        // Fixtures may run in parallel, and thread safety is not a guaranteed property of the key pair generator
        // API, so each authority gets its own rather than sharing one across the fixture.
        private static IAsymmetricCipherKeyPairGenerator CreateKeyPairGenerator()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            return kpg;
        }

        [Test]
        public void SharedCrlIssuerDnDoesNotLoop()
        {
            CA caA = new CA();
            CA caB = new CA();

            // Both authorities are trusted, and both contribute a CRL signer and a CRL.
            var anchors = new HashSet<TrustAnchor>() { caA.Anchor, caB.Anchor };

            X509Certificate targetCert = caA.MakeNewCert();

            var certs = new List<X509Certificate>() { targetCert, caA.CrlSignerCert, caB.CrlSignerCert };
            var crls = new List<X509Crl>() { caA.Crl, caB.Crl };

            X509CertStoreSelector target = new X509CertStoreSelector();
            target.Certificate = targetCert;

            PkixBuilderParameters pkixParams = new PkixBuilderParameters(anchors, target);
            pkixParams.AddStoreCert(CollectionUtilities.CreateStore(certs));
            pkixParams.AddStoreCrl(CollectionUtilities.CreateStore(crls));
            pkixParams.IsRevocationEnabled = true;

            // The first authority's CRL signer chains to its trust anchor and verifies its CRL, so a valid signer is
            // found and the path validates; the point of the test is that the search terminates at all.
            Assert.NotNull(new PkixCertPathBuilder().Build(pkixParams), "CertPath build returned null");
        }

        /// <summary>A certification authority signing certificates and CRLs with separate keys.</summary>
        private class CA
        {
            private readonly IAsymmetricCipherKeyPairGenerator m_kpg;
            private readonly AsymmetricKeyParameter m_certSigningKey;
            private readonly X509Name m_subject;

            private int m_counter = 1;

            /// <summary>The self-issued certificate signing certificate, as a trust anchor.</summary>
            internal TrustAnchor Anchor { get; }

            /// <summary>The delegated CRL signing certificate, sharing the authority's Subject DN.</summary>
            internal X509Certificate CrlSignerCert { get; }

            internal X509Crl Crl { get; }

            internal CA()
            {
                m_kpg = CreateKeyPairGenerator();

                AsymmetricCipherKeyPair certKeyPair = m_kpg.GenerateKeyPair();
                AsymmetricCipherKeyPair crlKeyPair = m_kpg.GenerateKeyPair();

                m_certSigningKey = certKeyPair.Private;
                m_subject = new X509Name("CN=AC_0");

                DateTime notBefore = DateTime.UtcNow;
                DateTime notAfter = notBefore.AddDays(1);

                // Certificate authority (cA asserted) but not a CRL signer, and self-issued, so it can be trusted.
                X509V3CertificateGenerator certGen = Builder(NextSerialNumber(), m_subject, notBefore, notAfter,
                    certKeyPair.Public);
                certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: true));
                certGen.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.KeyCertSign));

                Anchor = new TrustAnchor(Sign(certGen), null);

                // CRL signer but not a certificate authority, carrying the authority's own Subject DN.
                certGen = Builder(NextSerialNumber(), m_subject, notBefore, notAfter, crlKeyPair.Public);
                certGen.AddExtension(X509Extensions.BasicConstraints, critical: false, new BasicConstraints(cA: false));
                certGen.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.CrlSign));

                CrlSignerCert = Sign(certGen);

                X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
                crlGen.SetIssuerDN(m_subject);
                crlGen.SetThisUpdate(notBefore);
                crlGen.SetNextUpdate(notAfter);

                Crl = crlGen.Generate(new Asn1SignatureFactory(SignatureAlgorithm, crlKeyPair.Private));
            }

            /// <summary>Issues an end-entity certificate that is not permitted to do anything.</summary>
            internal X509Certificate MakeNewCert()
            {
                AsymmetricKeyParameter publicKey = m_kpg.GenerateKeyPair().Public;

                DateTime notBefore = DateTime.UtcNow;
                DateTime notAfter = notBefore.AddDays(1);

                BigInteger serialNumber = NextSerialNumber();
                X509Name subject = new X509Name("CN=EU_" + serialNumber.ToString());

                X509V3CertificateGenerator certGen = Builder(serialNumber, subject, notBefore, notAfter, publicKey);
                certGen.AddExtension(X509Extensions.BasicConstraints, critical: false, new BasicConstraints(cA: false));
                certGen.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(0));

                return Sign(certGen);
            }

            private BigInteger NextSerialNumber() => BigInteger.ValueOf(m_counter++);

            private X509V3CertificateGenerator Builder(BigInteger serialNumber, X509Name subject, DateTime notBefore,
                DateTime notAfter, AsymmetricKeyParameter publicKey)
            {
                X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
                certGen.SetIssuerDN(m_subject);
                certGen.SetSerialNumber(serialNumber);
                certGen.SetNotBefore(notBefore);
                certGen.SetNotAfter(notAfter);
                certGen.SetSubjectDN(subject);
                certGen.SetPublicKey(publicKey);
                return certGen;
            }

            private X509Certificate Sign(X509V3CertificateGenerator certGen) =>
                certGen.Generate(new Asn1SignatureFactory(SignatureAlgorithm, m_certSigningKey));
        }
    }
}
