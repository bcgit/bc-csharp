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
    /// Tests for CertPath validation of IssuingDistributionPoint relative names.
    /// </summary>
    /// <remarks>
    /// Per RFC 5280 sec. 4.2.1.13, IssuingDistributionPoint's <c>nameRelativeToCRLIssuer</c> is a single
    /// RelativeDistinguishedName (a SET of AttributeTypeAndValue) that, per sec. 5.2.5, is appended as one element
    /// to the CRL issuer's RDNSequence to form the full distribution-point DN. This test exercises the spec-compliant
    /// case where that single RDN is multi-valued (O=Bouncy+OU=Test) so the expansion in
    /// <see cref="Rfc3280CertPathUtilities"/> goes through the SET-as-one-RDN path - locking in behaviour the schema
    /// mandates and that github (bc-java) #1241 questioned (issue closed as not-a-bug; the schema does not permit a
    /// sequence of RDNs here).
    /// </remarks>
    [TestFixture]
    public class IdpRelativeNameTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void MultiValuedRelativeNameRoundTrip()
        {
            X509Name crlIssuerDn = new X509Name("CN=Root,O=BC");
            Asn1Set relativeRdn = GetFirstRdnSet(new X509Name("O=Bouncy+OU=Test"));
            X509Name expandedDn = new X509Name("CN=Root,O=BC,O=Bouncy+OU=Test");

            var caKp = GenerateRsaKp();
            X509Certificate caCert = TestUtilities.MakeTrustAnchor(caKp, "CN=Root,O=BC");
            X509Certificate eeCert = MakeEE(caCert, caKp, expandedDn);

            X509Crl matchingCrl = MakeCrlWithRelativeIdp(crlIssuerDn, caKp.Private, relativeRdn);
            RunValidate(caCert, eeCert, matchingCrl);
        }

        [Test]
        public void RelativeNameMismatchRejected()
        {
            X509Name crlIssuerDn = new X509Name("CN=Root,O=BC");
            X509Name expandedDn = new X509Name("CN=Root,O=BC,O=Bouncy+OU=Test");

            var caKP = GenerateRsaKp();
            X509Certificate caCert = TestUtilities.MakeTrustAnchor(caKP, "CN=Root,O=BC");
            X509Certificate eeCert = MakeEE(caCert, caKP, expandedDn);

            Asn1Set wrongRdn = GetFirstRdnSet(new X509Name("O=Wrong+OU=Other"));
            X509Crl mismatchingCrl = MakeCrlWithRelativeIdp(crlIssuerDn, caKP.Private, wrongRdn);
            try
            {
                RunValidate(caCert, eeCert, mismatchingCrl);
                Assert.Fail("expected PkixCertPathValidatorException; none thrown");
            }
            catch (PkixCertPathValidatorException e)
            {
                string expectedPrefix = "No match for certificate CRL issuing distribution point name";

                Exception cause = e;
                while (cause != null)
                {
                    string msg = cause.Message;
                    if (msg != null && msg.StartsWith(expectedPrefix))
                        return;

                    cause = cause.InnerException;
                }
                Assert.Fail("unexpected exception message: " + e.Message);
            }
        }

        private static AsymmetricCipherKeyPair GenerateRsaKp()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new KeyGenerationParameters(Random, 1024));
            return kpg.GenerateKeyPair();
        }

        private static Asn1Set GetFirstRdnSet(X509Name name)
        {
            Asn1Sequence seq = (Asn1Sequence)name.ToAsn1Object();
            return (Asn1Set)seq[0];
        }

        private static X509Certificate MakeEE(X509Certificate ca, AsymmetricCipherKeyPair caKP, X509Name expandedDn)
        {
            var subject = new X509Name("CN=EE");

            DateTime now = DateTime.UtcNow;

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(ca.SubjectDN);
            certGen.SetSerialNumber(BigInteger.ValueOf(2));
            certGen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
            certGen.SetSubjectDN(subject);
            certGen.SetPublicKey(caKP.Public);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(false));

            DistributionPointName dpName = new DistributionPointName(new GeneralNames(new GeneralName(expandedDn)));
            DistributionPoint dp = new DistributionPoint(dpName, null, null);
            certGen.AddExtension(X509Extensions.CrlDistributionPoints, critical: false,
                new CrlDistPoint(new DistributionPoint[]{ dp }));

            var signer = new Asn1SignatureFactory("SHA256withRSA", caKP.Private);
            return certGen.Generate(signer);
        }

        private static X509Crl MakeCrlWithRelativeIdp(X509Name issuerDN, AsymmetricKeyParameter issuerPrivKey,
            Asn1Set relativeRdn)
        {
            DateTime now = DateTime.UtcNow;

            X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(issuerDN);
            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(now.AddHours(1));

            DistributionPointName dpName = new DistributionPointName(DistributionPointName.NameRelativeToCrlIssuer,
                relativeRdn);
            IssuingDistributionPoint idp = new IssuingDistributionPoint(dpName, false, false);
            crlGen.AddExtension(X509Extensions.IssuingDistributionPoint, true, idp);

            var signer = new Asn1SignatureFactory("SHA256withRSA", issuerPrivKey);
            return crlGen.Generate(signer);
        }

        private void RunValidate(X509Certificate ca, X509Certificate ee, X509Crl crl)
        {
            var certs = new List<X509Certificate>();
            certs.Add(ca);
            certs.Add(ee);

            var crlsx509Crls = new List<X509Crl>();
            crlsx509Crls.Add(crl);

            var certStore = CollectionUtilities.CreateStore(certs);
            var crlStore = CollectionUtilities.CreateStore(crlsx509Crls);

            var chain = new List<X509Certificate>();
            chain.Add(ee);

            var certPath = new PkixCertPath(chain);

            var trust = new HashSet<TrustAnchor>();
            trust.Add(new TrustAnchor(ca, null));

            var validDate = DateTime.UtcNow;

            PkixParameters pkixParams = new PkixParameters(trust);
            pkixParams.AddStoreCert(certStore);
            pkixParams.AddStoreCrl(crlStore);
            pkixParams.Date = validDate;
            pkixParams.IsRevocationEnabled = true;

            var certPathValidator = new PkixCertPathValidator();
            certPathValidator.Validate(certPath, pkixParams);
        }
    }
}
