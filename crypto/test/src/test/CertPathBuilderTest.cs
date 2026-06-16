using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
    public class CertPathBuilderTest
    {
        [Test]
        public void Basic()
        {
            X509CertificateParser certParser = new X509CertificateParser();
            X509CrlParser crlParser = new X509CrlParser();

            // initialise CertStore
            X509Certificate rootCert = certParser.ReadCertificate(CertPathTest.rootCertBin);
            X509Certificate interCert = certParser.ReadCertificate(CertPathTest.interCertBin);
            X509Certificate finalCert = certParser.ReadCertificate(CertPathTest.finalCertBin);
            X509Crl rootCrl = crlParser.ReadCrl(CertPathTest.rootCrlBin);
            X509Crl interCrl = crlParser.ReadCrl(CertPathTest.interCrlBin);

            var certList =  new List<X509Certificate>();
            certList.Add(rootCert);
            certList.Add(interCert);
            certList.Add(finalCert);

            var crlList = new List<X509Crl>();
            crlList.Add(rootCrl);
            crlList.Add(interCrl);

            IStore<X509Certificate> x509CertStore = CollectionUtilities.CreateStore(certList);
            IStore<X509Crl> x509CrlStore = CollectionUtilities.CreateStore(crlList);

            // NB: Month is 1-based in .NET
            //DateTime validDate = new DateTime(2008, 9, 4, 14, 49, 10).ToUniversalTime();
            DateTime validDate = new DateTime(2008, 9, 4, 5, 49, 10);

            //Searching for rootCert by subjectDN without CRL
            var trust = new HashSet<TrustAnchor>();
            trust.Add(new TrustAnchor(rootCert, null));

            PkixCertPathBuilder cpb = new PkixCertPathBuilder();
            X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
            targetConstraints.Subject = finalCert.SubjectDN;
            PkixBuilderParameters parameters = new PkixBuilderParameters(trust, targetConstraints);
            parameters.AddStoreCert(x509CertStore);
            parameters.AddStoreCrl(x509CrlStore);
            parameters.Date = validDate;
            PkixCertPathBuilderResult result = cpb.Build(parameters);
            PkixCertPath path = result.CertPath;

            Assert.AreEqual(2, path.Certificates.Count, "wrong number of certs in " + nameof(Basic));
        }

        [Test]
        public void ManyTrustAnchorsAkiNarrowingPerfTest()
        {
            /*
             * github bc-java #2291 follow-up: with the recursion guard alone, runtime grows O(N^depth) when N trust
             * anchors share the issuer DN — every CRL check fans out across all candidate signers.
             * Rfc3280CertPathUtilities.ProcessCrlF narrows the candidate set by the CRL's AuthorityKeyIdentifier
             * (RFC 5280 sec. 5.2.1) when present. With seven roots sharing a Subject DN this test completes in
             * milliseconds; without the AKI narrowing it took many seconds.
             */

            // Real signer + 6 decoy roots, all sharing the same Subject DN, each
            // with a distinct key (so each cert ends up with a distinct SKI).
            int decoyCount = 6;
            X509Name rootDN = new X509Name("CN=Test CA Certificate");

            var realRootPair = TestUtilities.GenerateRsaKeyPair();
            var realRootSki = ComputeSki(realRootPair.Public);
            var realRootCert = SelfSignedV3CACert(realRootPair, rootDN, realRootSki);

            var trustCerts = new List<X509Certificate>();
            trustCerts.Add(realRootCert);
            for (int i = 0; i < decoyCount; i++)
            {
                var decoyPair = TestUtilities.GenerateRsaKeyPair();
                var decoySki = ComputeSki(decoyPair.Public);
                trustCerts.Add(SelfSignedV3CACert(decoyPair, rootDN, decoySki));
            }

            var interPair = TestUtilities.GenerateRsaKeyPair();
            var interSki = ComputeSki(interPair.Public);
            var interCert = SubordinateV3Cert(new X509Name("CN=Test Intermediate Certificate"), interPair.Public,
                interSki, realRootPair.Private, rootDN, realRootSki, true);

            var endPair = TestUtilities.GenerateRsaKeyPair();
            var endCert = SubordinateV3Cert(new X509Name("CN=Test End Certificate"), endPair.Public,
                ComputeSki(endPair.Public), interPair.Private, new X509Name("CN=Test Intermediate Certificate"),
                interSki, false);

            BigInteger revokedSerial = BigInteger.ValueOf(99999);
            // CRL signed by the real root, AKI keyIdentifier = real root's SKI.
            var rootCrl = CrlWithKeyIDAki(realRootCert, realRootPair.Private, revokedSerial, realRootSki);
            // CRL signed by intermediate, AKI keyIdentifier = intermediate's SKI.
            var interCrl = CrlWithKeyIDAki(interCert, interPair.Private, revokedSerial, interSki);

            var certList = new List<X509Certificate>();
            certList.AddRange(trustCerts);
            certList.Add(interCert);
            certList.Add(endCert);

            var crlList = new List<X509Crl>();
            crlList.Add(rootCrl);
            crlList.Add(interCrl);

            IStore<X509Certificate> x509CertStore = CollectionUtilities.CreateStore(certList);
            IStore<X509Crl> x509CrlStore = CollectionUtilities.CreateStore(crlList);

            var anchors = new HashSet<TrustAnchor>();
            foreach (var trustCert in trustCerts)
            {
                anchors.Add(new TrustAnchor(trustCert, null));
            }

            X509CertStoreSelector pathConstraints = new X509CertStoreSelector();
            pathConstraints.Subject = endCert.SubjectDN;

            PkixBuilderParameters buildParams = new PkixBuilderParameters(anchors, pathConstraints);
            buildParams.AddStoreCert(x509CertStore);
            buildParams.AddStoreCrl(x509CrlStore);
            buildParams.Date = DateTime.UtcNow;
            buildParams.IsRevocationEnabled = true;

            long startMs = DateTimeUtilities.CurrentUnixMs();

            PkixCertPathBuilder builder = new PkixCertPathBuilder();
            PkixCertPathBuilderResult result = builder.Build(buildParams);

            long elapsedMs = DateTimeUtilities.CurrentUnixMs() - startMs;

            PkixCertPath path = result.CertPath;

            Assert.AreEqual(2, path.Certificates.Count,
                $"wrong number of certs in {nameof(ManyTrustAnchorsAkiNarrowingPerfTest)}: {path.Certificates.Count}");

            // Sanity: with the fix, this typically completes in tens or hundreds of milliseconds. A several-second
            // result would suggest the AKI narrowing isn't taking effect for some reason.
            if (elapsedMs > 5000L)
            {
                Assert.Fail("CertPath build with " + trustCerts.Count + " trust anchors took " + elapsedMs +
                    " ms (expected sub-second)");
            }
        }

        [Test]
        public void MultipleTrustAnchorsWithCrl()
        {
            // github bc-java #2291: with CRL revocation enabled and multiple trust anchors whose subjects match the
            // CRL issuer name, the previous code recursed into a fresh PkixCertPathBuilder build for every candidate
            // signer, and that recursive build re-entered CRL processing on the same CRL. The fix short-circuits when
            // the candidate signer is itself a trust anchor.
            var rootPair = TestUtilities.GenerateRsaKeyPair();
            var otherRootPair = TestUtilities.GenerateRsaKeyPair();
            var interPair = TestUtilities.GenerateRsaKeyPair();
            var endPair = TestUtilities.GenerateRsaKeyPair();

            X509Name rootDN = new X509Name("CN=Test CA Certificate");

            // Two self-signed roots sharing the same Subject DN — different keys.
            var rootCert = TestUtilities.GenerateRootCert(rootPair, rootDN);
            var otherRootCert = TestUtilities.GenerateRootCert(otherRootPair, rootDN);

            var interCert = TestUtilities.GenerateIntermediateCert(interPair.Public, rootPair.Private, rootCert);
            var endCert = TestUtilities.GenerateEndEntityCert(endPair.Public, interPair.Private, interCert);

            BigInteger revokedSerial = BigInteger.Two;
            var rootCrl = TestUtilities.CreateCrl(rootCert, rootPair.Private, revokedSerial);
            var interCrl = TestUtilities.CreateCrl(interCert, interPair.Private, revokedSerial);

            var certList = new List<X509Certificate>();
            certList.Add(rootCert);
            certList.Add(otherRootCert);
            certList.Add(interCert);
            certList.Add(endCert);

            var crlList = new List<X509Crl>();
            crlList.Add(rootCrl);
            crlList.Add(interCrl);

            IStore<X509Certificate> x509CertStore = CollectionUtilities.CreateStore(certList);
            IStore<X509Crl> x509CrlStore = CollectionUtilities.CreateStore(crlList);

            var anchors = new HashSet<TrustAnchor>();
            anchors.Add(new TrustAnchor(rootCert, null));
            anchors.Add(new TrustAnchor(otherRootCert, null));

            X509CertStoreSelector pathConstraints = new X509CertStoreSelector();
            pathConstraints.Subject = endCert.SubjectDN;

            PkixBuilderParameters buildParams = new PkixBuilderParameters(anchors, pathConstraints);
            buildParams.AddStoreCert(x509CertStore);
            buildParams.AddStoreCrl(x509CrlStore);
            buildParams.Date = DateTime.UtcNow;
            buildParams.IsRevocationEnabled = true;

            PkixCertPathBuilder builder = new PkixCertPathBuilder();
            PkixCertPathBuilderResult result = builder.Build(buildParams);
            PkixCertPath path = result.CertPath;

            Assert.AreEqual(2, path.Certificates.Count,
                $"wrong number of certs in {nameof(MultipleTrustAnchorsWithCrl)}: {path.Certificates.Count}");
        }

        [Test]
        public void V0Test()
        {
            // create certificates and CRLs
            AsymmetricCipherKeyPair rootPair = TestUtilities.GenerateRsaKeyPair();
            AsymmetricCipherKeyPair interPair = TestUtilities.GenerateRsaKeyPair();
            AsymmetricCipherKeyPair endPair = TestUtilities.GenerateRsaKeyPair();

            X509Certificate rootCert = TestUtilities.GenerateRootCert(rootPair);
            X509Certificate interCert = TestUtilities.GenerateIntermediateCert(interPair.Public, rootPair.Private, rootCert);
            X509Certificate endCert = TestUtilities.GenerateEndEntityCert(endPair.Public, interPair.Private, interCert);

            BigInteger revokedSerialNumber = BigInteger.Two;
            X509Crl rootCRL = TestUtilities.CreateCrl(rootCert, rootPair.Private, revokedSerialNumber);
            X509Crl interCRL = TestUtilities.CreateCrl(interCert, interPair.Private, revokedSerialNumber);

            // create CertStore to support path building
            var certList = new List<X509Certificate>();
            certList.Add(rootCert);
            certList.Add(interCert);
            certList.Add(endCert);

            var crlList = new List<X509Crl>();
            crlList.Add(rootCRL);
            crlList.Add(interCRL);

            IStore<X509Certificate> x509CertStore = CollectionUtilities.CreateStore(certList);
            IStore<X509Crl> x509CrlStore = CollectionUtilities.CreateStore(crlList);

            var trust = new HashSet<TrustAnchor>();
            trust.Add(new TrustAnchor(rootCert, null));

            // build the path
            PkixCertPathBuilder builder = new PkixCertPathBuilder();
            X509CertStoreSelector pathConstraints = new X509CertStoreSelector();

            pathConstraints.Subject = endCert.SubjectDN;

            PkixBuilderParameters buildParams = new PkixBuilderParameters(trust, pathConstraints);
            buildParams.AddStoreCert(x509CertStore);
            buildParams.AddStoreCrl(x509CrlStore);

            buildParams.Date = DateTime.UtcNow;

            PkixCertPathBuilderResult result = builder.Build(buildParams);
            PkixCertPath path = result.CertPath;

            Assert.AreEqual(2, path.Certificates.Count, "wrong number of certs in " + nameof(V0Test));
        }

        private static SubjectKeyIdentifier ComputeSki(AsymmetricKeyParameter publicKey) =>
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(publicKey);

        private static X509Crl CrlWithKeyIDAki(X509Certificate caCert, AsymmetricKeyParameter caKey,
            BigInteger revokedSerial, SubjectKeyIdentifier caSki)
        {
            DateTime now = DateTime.UtcNow;
            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(caCert.SubjectDN);
            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(now.AddSeconds(100));
            crlGen.AddCrlEntry(revokedSerial, revocationDate: now, CrlReason.PrivilegeWithdrawn);
            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caSki));
            crlGen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));
            return crlGen.Generate(new Asn1SignatureFactory("SHA256withRSA", caKey));
        }

        private static X509Certificate SelfSignedV3CACert(AsymmetricCipherKeyPair pair, X509Name dn,
            SubjectKeyIdentifier ski)
        {
            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(cA: true));
            extGen.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            extGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, ski);
            return SignV3Cert(dn, pair.Private, dn, pair.Public, extGen);
        }

        private static X509Certificate SignV3Cert(X509Name subjectDN, AsymmetricKeyParameter issuerKey,
            X509Name issuerDN, AsymmetricKeyParameter subjectKey, X509ExtensionsGenerator extGen)
        {
            DateTime now = DateTime.UtcNow;
            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(DerInteger.ValueOf(TestUtilities.NextSerialNumber()));
            certGen.SetIssuerDN(issuerDN);
            certGen.SetSubjectDN(subjectDN);
            certGen.SetNotBefore(now.AddSeconds(-5));
            certGen.SetNotAfter(now.AddMinutes(30));
            certGen.SetPublicKey(subjectKey);
            certGen.AddExtensions(extGen.Generate());
            return certGen.Generate(new Asn1SignatureFactory("SHA256withRSA", issuerKey));
        }

        private static X509Certificate SubordinateV3Cert(X509Name subjectDN, AsymmetricKeyParameter subjectKey,
            SubjectKeyIdentifier subjectSki, AsymmetricKeyParameter issuerKey, X509Name issuerDN,
            SubjectKeyIdentifier issuerSki, bool isCA)
        {
            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.BasicConstraints, true,
                isCA ? new BasicConstraints(pathLenConstraint: 0) : new BasicConstraints(cA: false));

            int ku = KeyUsage.DigitalSignature;
            if (isCA)
            {
                ku |= KeyUsage.KeyCertSign | KeyUsage.CrlSign;
            }
            extGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(ku));
            extGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, subjectSki);
            extGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerSki));
            return SignV3Cert(subjectDN, issuerKey, issuerDN, subjectKey, extGen);
        }
    }
}
