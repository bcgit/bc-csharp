using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cert.Tests
{
    /// <summary>
    /// A root CA that delegates CRL signing to a separate certificate publishes an indirect CRL, and the PKI carries
    /// two root generations whose CRL signers share a Subject DN. RFC 5280 sec. 6.3.3 (f) requires the CRL issuer's
    /// certification path to be anchored at the same trust anchor as the certificate under check, so a CRL signed by
    /// the other generation's signer cannot be used - but the reason for that never reached the caller, who was told
    /// instead that no CRL had been found at all (github bc-java #2427).
    /// </summary>
    [TestFixture]
    public class IndirectCrlSignerTest
    {
        private static readonly string SignatureAlgorithm = "SHA256withRSA";

        private int m_serialNumber = 0;

        // Fixtures may run in parallel, and thread safety is not a guaranteed property of the key pair generator
        // API, so each PKI gets its own rather than sharing one across the fixture.
        private static IAsymmetricCipherKeyPairGenerator CreateKeyPairGenerator()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            return kpg;
        }

        private int NextSerialNumber() => Interlocked.Increment(ref m_serialNumber);

        private BigInteger AllocateSerialNumber() => BigInteger.ValueOf(NextSerialNumber());

        /// <summary>
        /// The compatibility half: one root generation, so the delegated CRL signer necessarily chains
        /// to the same trust anchor as the certificate being checked and the path validates.
        /// </summary>
        [Test]
        public void SingleGenerationValidates()
        {
            Assert.NotNull(Validate(BuildPki(1)), "CertPath build with a single root generation returned null");
        }

        [Test]
        public void RolledRootReportsTheRealFailure()
        {
            try
            {
                Validate(BuildPki(2));
                Assert.Fail("CRL signed under a different trust anchor accepted");
            }
            catch (PkixCertPathBuilderException e)
            {
                string chain = MessageChain(e);

                Assert.GreaterOrEqual(chain.IndexOf("CertPath for CRL signer failed to validate"), 0,
                    "failure of the CRL signer's own path not reported: " + chain);
                Assert.GreaterOrEqual(
                    chain.IndexOf("The CRL distribution points of the certificate were tried first and failed"), 0,
                    "distribution point failure not linked to the fallback: " + chain);

                // The certificate's own issuer is appended to the candidate signer set unconditionally,
                // and used to have the last word: it is a keyCertSign-only root, which is precisely why
                // CRL signing was delegated, so the caller was told the CRL issuer could not sign CRLs.
                Assert.Less(chain.IndexOf("Issuer certificate key usage extension does not permit CRL signing"), 0,
                    "key usage of the certificate's issuer reported instead of the real failure: " + chain);
            }
        }

        private static string MessageChain(Exception e)
        {
            StringBuilder sb = new StringBuilder();

            while (e != null)
            {
                sb.Append(e.Message).Append(" | ");
                e = e.InnerException;
            }

            return sb.ToString();
        }

        private PkixCertPathBuilderResult Validate(Pki pki)
        {
            HashSet<TrustAnchor> anchors = new HashSet<TrustAnchor>();
            for (int i = 0; i < pki.roots.Count; i++)
            {
                anchors.Add(new TrustAnchor(pki.roots[i], null));
            }

            var certs = new List<X509Certificate>(pki.signers) { pki.subCa };
            var crls = new List<X509Crl>() { pki.crl };

            var certStore = CollectionUtilities.CreateStore(certs);
            var crlStore = CollectionUtilities.CreateStore(crls);

            X509CertStoreSelector target = new X509CertStoreSelector();
            target.Certificate = pki.subCa;

            PkixBuilderParameters pkixParams = new PkixBuilderParameters(anchors, target);
            pkixParams.AddStoreCert(certStore);
            pkixParams.AddStoreCrl(crlStore);
            pkixParams.IsRevocationEnabled = true;

            return new PkixCertPathBuilder().Build(pkixParams);
        }

        /**
         * Every generation issues a CRL signer carrying the same Subject DN, which is also the
         * cRLIssuer named by the distribution point of every certificate under any of the roots. The
         * certificate under check chains to the first generation while the single published CRL is
         * signed by the last generation's signer.
         */
        private Pki BuildPki(int generations)
        {
            Pki pki = new Pki();

            var kpg = CreateKeyPairGenerator();

            X509Name signerDn = new X509Name("CN=Test-Root.CRL-S, O=Test-PKI, C=DE");
            CrlDistPoint crlDp = new CrlDistPoint(new DistributionPoint[]{
                new DistributionPoint(null, null, new GeneralNames(new GeneralName(signerDn))) });

            List<AsymmetricCipherKeyPair> rootKeys = new List<AsymmetricCipherKeyPair>();
            List<AsymmetricCipherKeyPair> signerKeys = new List<AsymmetricCipherKeyPair>();

            for (int g = 1; g <= generations; g++)
            {
                AsymmetricCipherKeyPair rootKey = kpg.GenerateKeyPair();
                X509Certificate root = SelfSigned(rootKey,
                    new X509Name("CN=Test-Root.CA, O=Test-PKI, C=DE, SERIALNUMBER=" + g));

                rootKeys.Add(rootKey);
                pki.roots.Add(root);

                AsymmetricCipherKeyPair signerKey = kpg.GenerateKeyPair();
                // Self-referencing CRLDP: the signer's own path is validated with revocation enabled
                // before its key is trusted, so the signer needs a resolvable CRLDP of its own.
                pki.signers.Add(CrlSigner(signerKey.Public, signerDn, rootKey, root, crlDp));
                signerKeys.Add(signerKey);
            }

            pki.subCa = SubCa(kpg.GenerateKeyPair().Public, new X509Name("CN=Test-Sub.CA, O=Test-PKI, C=DE"),
                rootKeys[0], pki.roots[0], crlDp);

            int last = pki.signers.Count - 1;
            pki.crl = IndirectCrl(signerKeys[last], pki.signers[last]);

            return pki;
        }

        private X509Certificate SelfSigned(AsymmetricCipherKeyPair key, X509Name subject)
        {
            X509V3CertificateGenerator b = Builder(issuer: subject, subject, key.Public);

            b.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: true));
            b.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.KeyCertSign));
            b.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(key.Public));

            return Sign(b, key.Private);
        }

        private X509Certificate CrlSigner(AsymmetricKeyParameter pub, X509Name subject, AsymmetricCipherKeyPair caKey,
            X509Certificate caCert, CrlDistPoint dp)
        {
            X509V3CertificateGenerator b = Builder(SubjectOf(caCert), subject, pub);

            b.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: false));
            b.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.CrlSign));
            b.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(pub));
            b.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caCert));
            b.AddExtension(X509Extensions.CrlDistributionPoints, critical: false, dp);

            return Sign(b, caKey.Private);
        }

        private X509Certificate SubCa(AsymmetricKeyParameter pub, X509Name subject, AsymmetricCipherKeyPair caKey,
            X509Certificate caCert, CrlDistPoint dp)
        {
            X509V3CertificateGenerator b = Builder(SubjectOf(caCert), subject, pub);

            b.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(0));
            b.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            b.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(pub));
            b.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caCert));
            b.AddExtension(X509Extensions.CrlDistributionPoints, critical: false, dp);

            return Sign(b, caKey.Private);
        }

        private X509Crl IndirectCrl(AsymmetricCipherKeyPair signerKey, X509Certificate signerCert)
        {
            DateTime now = DateTime.UtcNow;

            X509V2CrlGenerator b = new X509V2CrlGenerator();
            b.SetIssuerDN(SubjectOf(signerCert));
            b.SetThisUpdate(now.AddHours(-1));
            b.SetNextUpdate(now.AddMonths(1));

            b.AddExtension(X509Extensions.IssuingDistributionPoint, critical: true,
                new IssuingDistributionPoint(null, false, false, null, true, false));
            b.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(signerCert));

            return b.Generate(new Asn1SignatureFactory(SignatureAlgorithm, signerKey.Private));
        }

        private X509V3CertificateGenerator Builder(X509Name issuer, X509Name subject, AsymmetricKeyParameter publicKey)
        {
            DateTime now = DateTime.UtcNow;

            X509V3CertificateGenerator b = new X509V3CertificateGenerator();
            b.SetIssuerDN(issuer);
            b.SetSerialNumber(AllocateSerialNumber());
            b.SetNotBefore(now.AddDays(-1));
            b.SetNotAfter(now.AddYears(1));
            b.SetSubjectDN(subject);
            b.SetPublicKey(publicKey);
            return b;
        }

        private static X509Certificate Sign(X509V3CertificateGenerator b, AsymmetricKeyParameter privateKey) =>
            b.Generate(new Asn1SignatureFactory(SignatureAlgorithm, privateKey));

        private static X509Name SubjectOf(X509Certificate cert) => cert.SubjectDN;

        private class Pki
        {
            internal readonly List<X509Certificate> roots = new List<X509Certificate>();
            internal readonly List<X509Certificate> signers = new List<X509Certificate>();
            internal X509Certificate subCa;
            internal X509Crl crl;
        }
    }
}
