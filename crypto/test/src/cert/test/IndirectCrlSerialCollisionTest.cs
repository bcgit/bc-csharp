using System;
using System.Collections.Generic;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cert.Tests
{
    /// <summary>
    /// An indirect CRL (RFC 5280 sec. 5.2.5) lists certificates from more than one issuer, and a serial number is only
    /// unique within its issuer, so two of its entries may carry the same serial number for different issuers, each
    /// applying to the issuer named by its own or a preceding entry's certificateIssuer extension (sec. 5.3.3). An
    /// entry looked up by serial number alone is therefore whichever of them comes first, and a certificate whose own
    /// entry followed another issuer's entry with the same serial number was reported as not revoked.
    /// </summary>
    [TestFixture]
    public class IndirectCrlSerialCollisionTest
    {
        private static readonly string SignatureAlgorithm = "SHA256withRSA";

        private static readonly BigInteger SharedSerial = BigInteger.ValueOf(7);
        private static readonly X509Name OtherCA = new X509Name("CN=Other.CA, O=Test-PKI, C=DE");

        [Test]
        public void Basic()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new KeyGenerationParameters(new SecureRandom(), 1024));

            var caKey = kpg.GenerateKeyPair();
            var caName = new X509Name("CN=Test-Root.CA, O=Test-PKI, C=DE");
            var caCert = SelfSigned(caKey, caName);

            X509Certificate ee = Certificate(caKey.Private, kpg.GenerateKeyPair().Public, caName,
                new X509Name("CN=Test-EE, O=Test-PKI, C=DE"), SharedSerial);
            // the same serial number under the other issuer: only that issuer's entry applies to it.
            X509Certificate other = Certificate(caKey.Private, kpg.GenerateKeyPair().Public, OtherCA,
                new X509Name("CN=Other-EE, O=Test-PKI, C=DE"), SharedSerial);

            // the entry naming the CA follows the other issuer's entry for the same serial number.
            X509Crl otherFirst = IndirectCrl(caName, caKey.Private, new X509Name[]{ OtherCA, caName });
            // the compatibility half: the entry naming the CA comes first.
            X509Crl caFirst = IndirectCrl(caName, caKey.Private, new X509Name[]{ caName, OtherCA });
            // only the other issuer has revoked this serial number.
            X509Crl otherOnly = IndirectCrl(caName, caKey.Private, new X509Name[]{ OtherCA });

            RevokedBy(caCert, ee, caFirst, false);
            RevokedBy(caCert, ee, otherFirst, false);
            ValidatesWith(caCert, ee, otherOnly, false);

            // TODO[pkix] Support for explicit revocation checker
            //RevokedBy(caCert, ee, caFirst, true);
            //RevokedBy(caCert, ee, otherFirst, true);
            //ValidatesWith(caCert, ee, otherOnly, true);

            IsRevoked(ee, other, caFirst, otherFirst, otherOnly);

            EntryLookup(caName, ee, other, otherFirst, otherOnly);
        }

        /// <summary>
        /// (In bc-java) CRL.isRevoked() stopped at the first entry carrying the serial number, and reported the
        /// certificate as not revoked when that entry was another issuer's.
        /// </summary>
        private void IsRevoked(X509Certificate ee, X509Certificate other, X509Crl caFirst, X509Crl otherFirst,
            X509Crl otherOnly)
        {
            Assert.True(caFirst.IsRevoked(ee), "revoked certificate not reported by IsRevoked() (own entry first)");
            Assert.True(otherFirst.IsRevoked(ee), "revoked certificate not reported by IsRevoked() (other issuer's entry first)");
            Assert.True(otherFirst.IsRevoked(other), "other issuer's revoked certificate not reported by IsRevoked()");
            Assert.False(otherOnly.IsRevoked(ee), "another issuer's entry reported by IsRevoked()");
        }

        private void RevokedBy(X509Certificate caCert, X509Certificate cert, X509Crl crl, bool useChecker)
        {
            try
            {
                ValidatesWith(caCert, cert, crl, useChecker);
                Assert.Fail("revoked certificate accepted (validator)");
            }
            catch (PkixCertPathValidatorException e)
            {
                string chain = MessageChain(e);

                Assert.True(chain.IndexOf("revocation") >= 0 || chain.IndexOf("revoked") >= 0,
                    "unexpected failure: " + chain);
            }
        }

        private void ValidatesWith(X509Certificate caCert, X509Certificate cert, X509Crl crl, bool useChecker)
        {
            var anchor = new TrustAnchor(caCert, null);
            var anchors = new HashSet<TrustAnchor>() { anchor };

            var pkixParams = new PkixParameters(anchors);

            var crlStore = CollectionUtilities.CreateStore(new List<X509Crl>() { crl });

            if (useChecker)
            {
                // TODO[pkix] Support for explicit revocation checker
                //pkixParams.IsRevocationEnabled = false;
                //pkixParams.AddCertPathChecker(new X509RevocationChecker.Builder(anchor).AddCrls(crlStore).Build());
                return;
            }
            else
            {
                pkixParams.AddStoreCrl(CollectionUtilities.CreateStore(new List<X509Crl>() { crl }));
                pkixParams.IsRevocationEnabled = true;
            }

            var certPath = new PkixCertPath(new List<X509Certificate>() { cert });

            var certPathValidator = new PkixCertPathValidator();
            certPathValidator.Validate(certPath, pkixParams);
        }

        /// <summary>
        /// (In bc-java) X509CRL.getRevokedCertificate(X509Certificate) is the JDK's lookup for indirect CRLs, keyed by
        /// issuer and serial number; it has to find the entry naming the certificate's issuer, and no other.
        /// </summary>
        private void EntryLookup(X509Name caName, X509Certificate ee, X509Certificate other, X509Crl otherFirst,
            X509Crl otherOnly)
        {
            // the two entries for the shared serial number encode identically and differ only in the
            // issuer they inherit, so the set of entries must keep them both.
            Assert.AreEqual(4, otherFirst.GetRevokedCertificates().Count,
                "entry for a second issuer lost from the set of entries");

            X509CrlEntry entry = otherFirst.GetRevokedCertificate(ee);

            Assert.NotNull(entry, "no entry found for the certificate");
            Assert.True(NamesIssuer(entry, otherFirst, caName), "another issuer's entry returned for the certificate");

            entry = otherFirst.GetRevokedCertificate(other);

            Assert.NotNull(entry, "no entry found for the other issuer's certificate");
            Assert.True(NamesIssuer(entry, otherFirst, OtherCA),
                "wrong entry returned for the other issuer's certificate");

            entry = otherOnly.GetRevokedCertificate(ee);

            Assert.Null(entry, "entry of another issuer returned for an unrevoked certificate");
        }

        private static bool NamesIssuer(X509CrlEntry entry, X509Crl crl, X509Name issuer)
        {
            X509Name entryIssuer = entry.GetCertificateIssuer() ?? crl.IssuerDN;

            return issuer.Equivalent(entryIssuer, true);
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

        private X509Certificate SelfSigned(AsymmetricCipherKeyPair key, X509Name subject)
        {
            X509V3CertificateGenerator b = Builder(issuer: subject, subject, key.Public, BigInteger.One);

            b.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: true));
            b.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            return Sign(b, key.Private);
        }

        private X509Certificate Certificate(AsymmetricKeyParameter caPrivateKey, AsymmetricKeyParameter pub,
            X509Name issuer, X509Name subject, BigInteger serial)
        {
            X509V3CertificateGenerator b = Builder(issuer, subject, pub, serial);

            b.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: false));

            return Sign(b, caPrivateKey);
        }

        /// <summary>
        /// An indirect CRL issued by the CA, revoking 'SharedSerial' once under each of the given issuers, in that
        /// order. Each issuer's entries are introduced by one carrying the certificateIssuer extension, which the
        /// entries after it inherit (RFC 5280 sec. 5.3.3).
        /// </summary>
        private X509Crl IndirectCrl(X509Name caName, AsymmetricKeyParameter caPrivateKey, X509Name[] issuers)
        {
            DateTime now = DateTime.UtcNow;
            DateTime revocationDate = now.AddHours(-1);

            X509V2CrlGenerator b = new X509V2CrlGenerator();
            b.SetIssuerDN(caName);
            b.SetThisUpdate(revocationDate);
            b.SetNextUpdate(now.AddMonths(1));

            b.AddExtension(X509Extensions.IssuingDistributionPoint, critical: true,
                new IssuingDistributionPoint(null, false, false, null, true, false));

            for (int i = 0; i != issuers.Length; i++)
            {
                var gen = new X509ExtensionsGenerator();
                gen.AddExtension(X509Extensions.CertificateIssuer, critical: true,
                    new GeneralNames(new GeneralName(issuers[i])));
                var extensions = gen.Generate();

                b.AddCrlEntry(BigInteger.ValueOf(100 + i), revocationDate, extensions);
                b.AddCrlEntry(SharedSerial, revocationDate, CrlReason.KeyCompromise);
            }

            return b.Generate(new Asn1SignatureFactory(SignatureAlgorithm, caPrivateKey));
        }

        private X509V3CertificateGenerator Builder(X509Name issuer, X509Name subject, AsymmetricKeyParameter publicKey,
            BigInteger serial)
        {
            DateTime now = DateTime.UtcNow;

            X509V3CertificateGenerator b = new X509V3CertificateGenerator();
            b.SetIssuerDN(issuer);
            b.SetSerialNumber(serial);
            b.SetNotBefore(now.AddDays(-1));
            b.SetNotAfter(now.AddYears(1));
            b.SetSubjectDN(subject);
            b.SetPublicKey(publicKey);
            return b;
        }

        private static X509Certificate Sign(X509V3CertificateGenerator b, AsymmetricKeyParameter privateKey) =>
            b.Generate(new Asn1SignatureFactory(SignatureAlgorithm, privateKey));
    }
}
