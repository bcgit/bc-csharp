using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
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
    }
}
