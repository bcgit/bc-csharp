using System;
using System.Globalization;

using NUnit.Framework;
using NUnit.Framework.Internal;

namespace Org.BouncyCastle.Tests.Nist
{
    /// <remarks>
    /// Tests based on https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf .
    /// </remarks>
    [TestFixture]
    public class NistCertPathTest2
    {
        /// <summary>4.1.1 Valid Signatures Test1</summary>
        /// <remarks>
        /// The purpose of this test is to verify an application's ability to name chain, signature chain, and
        /// check validity dates, on certificates in a certification path.It also tests processing of the basic
        /// constraints and key usage extensions in intermediate certificates.
        /// </remarks>
        [Test]
        public void Test4_1_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid Certificate Path Test1 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.1.2 Invalid CA Signature Test2</summary>
        /// <remarks>
        /// The purpose of this test is to verify an application's ability to recognize an invalid signature on an
        /// intermediate certificate in a certification path.
        /// </remarks>
        [Test]
        public void Test4_1_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid CA Signature Test2 EE")
                .WithCrls("Bad Signed CA CRL")
                .WithCerts("Bad Signed CA Cert")
                .DoExceptionTest(1, "TrustAnchor found but certificate validation failed.");
        }

        /// <summary>4.1.3 Invalid EE Signature Test3</summary>
        /// <remarks>
        /// The purpose of this test is to verify an application's ability to recognize an invalid signature on an
        /// end entity certificate in a certification path.
        /// </remarks>
        [Test]
        public void Test4_1_3()
        {
            new PkitsTest()
                .WithEndEntity("Invalid EE Signature Test3 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoExceptionTest(0, "Could not validate certificate signature.");
        }

        /// <summary>4.1.4 Valid DSA Signatures Test4</summary>
        /// <remarks>
        /// The purpose of this test is to verify an application's ability to validate certificate in which DSA
        /// signatures are used. The intermediate CA and the end entity have DSA key pairs.
        /// </remarks>
        [Test]
        public void Test4_1_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid DSA Signatures Test4 EE")
                .WithCrls("DSA CA CRL")
                .WithCerts("DSA CA Cert")
                .DoTest();
        }

        /// <summary>4.1.5 Valid DSA Parameter Inheritance Test5</summary>
        /// <remarks>
        /// The purpose of this test is to verify an application's ability to validate DSA signatures when the
        /// DSA parameters are not included in a certificate and need to be inherited from a previous
        /// certificate in the path. The intermediate CAs and the end entity have DSA key pairs.
        /// </remarks>
        [Test]
        public void Test4_1_5()
        {
            new PkitsTest()
                .WithEndEntity("Valid DSA Parameter Inheritance Test5 EE")
                .WithCrls("DSA Parameters Inherited CA CRL", "DSA CA CRL")
                .WithCerts("DSA Parameters Inherited CA Cert", "DSA CA Cert")
                .DoTest();
        }

        /// <summary>4.1.6 Invalid DSA Signature Test6</summary>
        /// <remarks>
        /// The purpose of this test is to verify an application's ability to determine when a DSA signature is
        /// invalid. The intermediate CA and the end entity have DSA key pairs.
        /// </remarks>
        [Test]
        public void Test4_1_6()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DSA Signature Test6 EE")
                .WithCrls("DSA CA CRL")
                .WithCerts("DSA CA Cert")
                .DoExceptionTest(0, "Could not validate certificate signature.");
        }

        /// <summary>4.2.1 Invalid CA notBefore Date Test1</summary>
        /// <remarks>
        /// In this test, the intermediate certificate's notBefore date is after the current date.
        /// </remarks>
        [Test]
        public void Test4_2_1()
        {
            var expectedDate = FormatValidityDate(2047, 1, 1, 12, 1, 0);
            new PkitsTest()
                .WithEndEntity("Invalid CA notBefore Date Test1 EE")
                .WithCrls("Bad notBefore Date CA CRL")
                .WithCerts("Bad notBefore Date CA Cert")
                .DoExceptionTest(1, $"Could not validate certificate: certificate not valid until {expectedDate}");
        }

        /// <summary>4.2.2 Invalid EE notBefore Date Test2</summary>
        /// <remarks>
        /// In this test, the end entity certificate's notBefore date is after the current date.
        /// </remarks>
        [Test]
        public void Test4_2_2()
        {
            var expectedDate = FormatValidityDate(2047, 1, 1, 12, 1, 0);
            new PkitsTest()
                .WithEndEntity("Invalid EE notBefore Date Test2 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoExceptionTest(0, $"Could not validate certificate: certificate not valid until {expectedDate}");
        }

        /// <summary>4.2.3 Valid pre2000 UTC notBefore Date Test3</summary>
        /// <remarks>
        /// In this test, the end entity certificate's notBefore date is set to 1950 and is encoded in UTCTime.
        /// </remarks>
        [Test]
        public void Test4_2_3()
        {
            new PkitsTest()
                .WithEndEntity("Valid pre2000 UTC notBefore Date Test3 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.2.4 Valid GeneralizedTime notBefore Date Test4</summary>
        /// <remarks>
        /// In this test, the end entity certificate's notBefore date is specified in GeneralizedTime.
        /// </remarks>
        [Test]
        public void Test4_2_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid GeneralizedTime notBefore Date Test4 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.2.5 Invalid CA notAfter Date Test5</summary>
        /// <remarks>
        /// In this test, the intermediate certificate's notAfter date is before the current date.
        /// </remarks>
        [Test]
        public void Test4_2_5()
        {
            var expectedDate = FormatValidityDate(2002, 1, 1, 12, 1, 0);
            new PkitsTest()
                .WithEndEntity("Invalid CA notAfter Date Test5 EE")
                .WithCrls("Bad notAfter Date CA CRL")
                .WithCerts("Bad notAfter Date CA Cert")
                .DoExceptionTest(1, $"Could not validate certificate: certificate expired on {expectedDate}");
        }

        /// <summary>4.2.6 Invalid EE notAfter Date Test6</summary>
        /// <remarks>
        /// In this test, the end entity certificate's notAfter date is before the current date.
        /// </remarks>
        [Test]
        public void Test4_2_6()
        {
            var expectedDate = FormatValidityDate(2002, 1, 1, 12, 1, 0);
            new PkitsTest()
                .WithEndEntity("Invalid EE notAfter Date Test6 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoExceptionTest(0, $"Could not validate certificate: certificate expired on {expectedDate}");
        }

        /// <summary>4.2.7 Invalid pre2000 UTC EE notAfter Date Test7</summary>
        /// <remarks>
        /// In this test, the end entity certificate's notAfter date is 1999 and is encoded in UTCTime.
        /// </remarks>
        [Test]
        public void Test4_2_7()
        {
            var expectedDate = FormatValidityDate(1999, 1, 1, 12, 1, 0);
            new PkitsTest()
                .WithEndEntity("Invalid pre2000 UTC EE notAfter Date Test7 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoExceptionTest(0, $"Could not validate certificate: certificate expired on {expectedDate}");
        }

        /// <summary>4.2.8 Valid GeneralizedTime notAfter Date Test8</summary>
        /// <remarks>
        /// In this test, the end entity certificate's notAfter date is 2050 and is encoded in GeneralizedTime.
        /// </remarks>
        [Test]
        public void Test4_2_8()
        {
            new PkitsTest()
                .WithEndEntity("Valid GeneralizedTime notAfter Date Test8 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.3.1 Invalid Name Chaining EE Test1</summary>
        /// <remarks>
        /// In this test, the common name (cn=) portion of the issuer's name in the end entity certificate does
        /// not match the common name portion of the subject's name in the preceding intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_3_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Name Chaining Test1 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=Good CA Root,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.3.2 Invalid Name Chaining Order Test2</summary>
        /// <remarks>
        /// In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
        /// intermediate certificate contain the same relative distinguished names (RDNs), but their ordering is
        /// different.
        /// </remarks>
        [Test]
        public void Test4_3_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Name Chaining Order Test2 EE")
                .WithCrls("Name Order CA CRL")
                .WithCerts("Name Ordering CA Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=Name Ordering CA,ou=Organizational Unit Name 1,ou=Organizational Unit Name 2,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.3.3 Valid Name Chaining Whitespace Test3</summary>
        /// <remarks>
        /// In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
        /// intermediate certificate differ in internal whitespace, but match once the internal whitespace is
        /// compressed.
        /// </remarks>
        [Test]
        public void Test4_3_3()
        {
            new PkitsTest()
                .WithEndEntity("Valid Name Chaining Whitespace Test3 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.3.4 Valid Name Chaining Whitespace Test4</summary>
        /// <remarks>
        /// In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
        /// intermediate certificate differ in leading and trailing whitespace, but match once all leading and
        /// trailing whitespace is removed.
        /// </remarks>
        [Test]
        public void Test4_3_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid Name Chaining Whitespace Test4 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.3.5 Valid Name Chaining Capitalization Test5</summary>
        /// <remarks>
        /// In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
        /// intermediate certificate differ in capitalization, but match when a case insensitive match is
        /// performed.
        /// </remarks>
        [Test]
        public void Test4_3_5()
        {
            new PkitsTest()
                .WithEndEntity("Valid Name Chaining Capitalization Test5 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.3.6 Valid Name Chaining UIDs Test6</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a subjectUniqueID and the end entity certificate
        /// includes a matching issuerUniqueID.
        /// </remarks>
        [Test]
        public void Test4_3_6()
        {
            new PkitsTest()
                .WithEndEntity("Valid Name UIDs Test6 EE")
                .WithCrls("UID CA CRL")
                .WithCerts("UID CA Cert")
                .DoTest();
        }

        /// <summary>4.3.7 Valid RFC3280 Mandatory Attribute Types Test7</summary>
        /// <remarks>
        /// In this test, this intermediate certificate includes a subject name that includes the attribute types
        /// distinguished name qualifier, state or province name, serial number, domain component,
        /// organization, and country.
        /// </remarks>
        [Test]
        public void Test4_3_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid RFC3280 Mandatory Attribute Types Test7 EE")
                .WithCrls("RFC3280 Mandatory AttributeTypes CA CRL")
                .WithCerts("RFC3280 Mandatory Attribute Types CA Cert")
                .DoTest();
        }

        /// <summary>4.3.8 Valid RFC3280 Optional Attribute Types Test8</summary>
        /// <remarks>
        /// In this test, this intermediate certificate includes a subject name that includes the attribute types
        /// locality, title, surname, given name, initials, pseudonym, generation qualifier, organization, and
        /// country.
        /// </remarks>
        [Test]
        public void Test4_3_8()
        {
            new PkitsTest()
                .WithEndEntity("Valid RFC3280 Optional Attribute Types Test8 EE")
                .WithCrls("RFC3280 Optional AttributeTypes CA CRL")
                .WithCerts("RFC3280 Optional Attribute Types CA Cert")
                .DoTest();
        }

        /// <summary>4.3.9 Valid UTF8String Encoded Names Test9</summary>
        /// <remarks>
        /// In this test, the attribute values for the common name and organization attribute types in the
        /// subject fields of the intermediate and end certificates and the issuer fields of the end certificate
        /// and the intermediate certificate's CRL are encoded in UTF8String.
        /// </remarks>
        [Test]
        public void Test4_3_9()
        {
            new PkitsTest()
                .WithEndEntity("Valid UTF8String Encoded Names Test9 EE")
                .WithCrls("UTF8String Encoded Names CA CRL")
                .WithCerts("UTF8String Encoded Names CA Cert")
                .DoTest();
        }

        /// <summary>4.3.10 Valid Rollover from PrintableString to UTF8String Test10</summary>
        /// <remarks>
        /// In this test, the attribute values for the common name and organization attribute types in the issuer
        /// and subject fields of the end certificate and the issuer field of the intermediate certificate's CRL
        /// are encoded in UTF8String. However, these attribute types are encoded in PrintableString in the
        /// subject field of the intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_3_10()
        {
            new PkitsTest()
                .WithEndEntity("Valid Rollover from PrintableString to UTF8String Test10 EE")
                .WithCrls("Rollover fromPrintableString to UTF8String CA CRL")
                .WithCerts("Rollover from PrintableString to UTF8String CA Cert")
                .DoTest();
        }

        /// <summary>4.3.11 Valid UTF8String Case Insensitive Match Test11</summary>
        /// <remarks>
        /// In this test, the attribute values for the common name and organization attribute types in the
        /// subject fields of the intermediate and end certificates and the issuer fields of the end certificate
        /// and the intermediate certificate's CRL are encoded in UTF8String. The subject of the
        /// intermediate certificate and the issuer of the end certificate differ in capitalization and whitespace,
        /// but match when a case insensitive match is performed.
        /// </remarks>
        [Test]
        public void Test4_3_11()
        {
            new PkitsTest()
                .WithEndEntity("Valid UTF8String Case Insensitive Match Test11 EE")
                .WithCrls("UTF8String Case InsensitiveMatch CA CRL")
                .WithCerts("UTF8String Case Insensitive Match CA Cert")
                .DoTest();
        }

        /// <summary>4.4.1 Missing CRL Test1</summary>
        /// <remarks>
        /// In this test, there is no revocation information available from the intermediate CA, making it
        /// impossible to determine the status of the end certificate.
        /// </remarks>
        [Test]
        public void Test4_4_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Missing CRL Test1 EE")
                .WithCerts("No CRL CA Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=No CRL CA,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.4.2 Invalid Revoked CA Test2</summary>
        /// <remarks>
        /// In this test, the CRL issued by the first intermediate CA indicates that the second intermediate
        /// certificate in the path has been revoked.
        /// </remarks>
        [Test]
        public void Test4_4_2()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid Revoked CA Test2 EE")
                .WithCrls("Revoked subCA CRL", "Good CA CRL")
                .WithCerts("Revoked subCA Cert", "Good CA Cert")
                .DoExceptionTest(1, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.4.3 Invalid Revoked EE Test3</summary>
        /// <remarks>
        /// In this test, the CRL issued by the intermediate CA indicates that the end entity certificate has been
        /// revoked.
        /// </remarks>
        [Test]
        public void Test4_4_3()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid Revoked EE Test3 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.4.4 Invalid Bad CRL Signature Test4</summary>
        /// <remarks>
        /// In this test, the signature on the CRL issued by the intermediate CA is invalid.
        /// </remarks>
        [Test]
        public void Test4_4_4()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Bad CRL Signature Test4 EE")
                .WithCrls("Bad CRL Signature CA CRL")
                .WithCerts("Bad CRL Signature CA Cert")
                .DoExceptionTest(0, "Cannot verify CRL.");
        }

        /// <summary>4.4.5 Invalid Bad CRL Issuer Name Test5</summary>
        /// <remarks>
        /// In this test, the issuer name in the CRL signed by the intermediate CA does not match the issuer
        /// name in the end entity's certificate.
        /// </remarks>
        [Test]
        public void Test4_4_5()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Bad CRL Issuer Name Test5 EE")
                .WithCrls("Bad CRL Issuer Name CA CRL")
                .WithCerts("Bad CRL Issuer Name CA Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=Bad CRL Issuer Name CA,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.4.6 Invalid Wrong CRL Test6</summary>
        /// <remarks>
        /// In this test, the wrong CRL is in the intermediate certificate's directory entry. There is no CRL
        /// available from the intermediate CA making it impossible to determine the status of the end entity's
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_4_6()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Wrong CRL Test6 EE")
                .WithCrls("Wrong CRL CA CRL")
                .WithCerts("Wrong CRL CA Cert")
                // TODO[pkix]
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=Wrong CRL CA,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.4.7 Valid Two CRLs Test7</summary>
        /// <remarks>
        /// In this test, there are two CRLs in the intermediate CAs directory entry, one that is correct and one
        /// that contains the wrong issuer name. The correct CRL does not list any certificates as revoked.
        /// The incorrect CRL includes the serial number of the end entity's certificate on its list of revoked
        /// certificates.
        /// </remarks>
        [Test]
        public void Test4_4_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid Two CRLs Test7 EE")
                .WithCrls("Two CRLs CA Bad CRL", "Two CRLs CA Good CRL")
                .WithCerts("Two CRLs CA Cert")
                .DoTest();
        }

        /// <summary>4.4.8 Invalid Unknown CRL Entry Extension Test8</summary>
        /// <remarks>
        /// In this test, the end entity's certificate has been revoked. In the intermediate CA's CRL, there is a
        /// made up critical crlEntryExtension associated with the end entity certificate's serial number.
        /// [X.509 7.3] When an implementation processing a CRL encounters the serial number of the
        /// certificate of interest in a CRL entry, but does not recognize a critical extension in the
        /// crlEntryExtensions field from that CRL entry, that CRL cannot be used to determine the status of
        /// the certificate.
        /// </remarks>
        [Test]
        public void Test4_4_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Unknown CRL Entry Extension Test8 EE")
                .WithCrls("Unknown CRL Entry Extension CACRL")
                .WithCerts("Unknown CRL Entry Extension CA Cert")
                .DoExceptionTest(0, "CRL entry has unsupported critical extensions.");
        }

        /// <summary>4.4.9 Invalid Unknown CRL Extension Test9</summary>
        /// <remarks>
        /// In this test, the end entity's certificate has been revoked. In the intermediate CA's CRL, there is a
        /// made up critical extension in the crlExtensions field.
        /// [X.509 7.3] When an implementation does not recognize a critical extension in the crlExtensions
        /// field, that CRL cannot be used to determine the status of the certificate, regardless of whether the
        /// serial number of the certificate of interest appears in that CRL or not.
        /// </remarks>
        [Test]
        public void Test4_4_9()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Unknown CRL Extension Test9 EE")
                .WithCrls("Unknown CRL Extension CA CRL")
                .WithCerts("Unknown CRL Extension CA Cert")
                .DoExceptionTest(0, "CRL contains unsupported critical extensions.");
        }

        /// <summary>4.4.10 Invalid Unknown CRL Extension Test10</summary>
        /// <remarks>
        /// In this test the intermediate CA's CRL contains a made up critical extension in the crlExtensions
        /// field. The end entity certificate's serial number is not listed on the CRL, however, due to the
        /// presence of an unknown critical CRL extension, the relying party can not be sure that the list of
        /// serial numbers on the revokedCertificates list includes all certificates that have been revoked by
        /// the intermediate CA. As a result, the relying party can not verify that the end entity's certificate
        /// has not been revoked.
        /// </remarks>
        [Test]
        public void Test4_4_10()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Unknown CRL Extension Test10 EE")
                .WithCrls("Unknown CRL Extension CA CRL")
                .WithCerts("Unknown CRL Extension CA Cert")
                .DoExceptionTest(0, "CRL contains unsupported critical extensions.");
        }

        /// <summary>4.4.11 Invalid Old CRL nextUpdate Test11</summary>
        /// <remarks>
        /// In this test the intermediate CA's CRL has a nextUpdate time that is far in the past (January
        /// 2010), indicating that the CA has already issued updated revocation information. Since the
        /// information in the CRL is out-of-date and a more up-to-date CRL (that should have already been
        /// issued) can not be obtained, the certification path should be treated as if the status of the end entity
        /// certificate can not be determined.
        /// </remarks>
        [Test]
        public void Test4_4_11()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Old CRL nextUpdate Test11 EE")
                .WithCrls("Old CRL nextUpdate CA CRL")
                .WithCerts("Old CRL nextUpdate CA Cert")
                // TODO[pkix]
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=Old CRL nextUpdate CA,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.4.12 Invalid pre2000 CRL nextUpdate Test12</summary>
        /// <remarks>
        /// In this test the intermediate CA's CRL has a nextUpdate time that is in 1999 indicating that the
        /// CA has already issued updated revocation information. Since the information in the CRL is out-of-date
        /// and a more up-to-date CRL (that should have already been issued) can not be obtained, the
        /// certification path should be treated as if the status of the end entity certificate can not be
        /// determined.
        /// </remarks>
        [Test]
        public void Test4_4_12()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pre2000 CRL nextUpdate Test12 EE")
                .WithCrls("pre2000 CRL nextUpdate CA CRL")
                .WithCerts("pre2000 CRL nextUpdate CA Cert")
                // TODO[pkix]
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=pre2000 CRL nextUpdate CA,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.4.13 Valid GeneralizedTime CRL nextUpdate Test13</summary>
        /// <remarks>
        /// In this test the intermediate CA's CRL has a nextUpdate time that is in 2050. Since the
        /// nextUpdate time is in the future, this CRL may contain the most up-to-date certificate status
        /// information that is available from the intermediate CA and so the relying party may use this CRL
        /// to determine the status of the end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_4_13()
        {
            new PkitsTest()
                .WithEndEntity("Valid GeneralizedTime CRL nextUpdate Test13 EE")
                .WithCrls("GeneralizedTime CRL nextUpdateCA CRL")
                .WithCerts("GeneralizedTime CRL nextUpdate CA Cert")
                .DoTest();
        }

        /// <summary>4.4.14 Valid Negative Serial Number Test14</summary>
        /// <remarks>
        /// RFC 3280 mandates that certificate serial numbers be positive integers, but states that relying
        /// parties should be prepared to gracefully handle certificates with serial numbers that are negative,
        /// or zero. In this test, the end entity's certificate has a serial number of 255 (DER encoded as "00
        /// FF") and the corresponding CRL lists the certificate with serial number -1 (DER encoded as "FF")
        /// as revoked.
        /// </remarks>
        [Test]
        public void Test4_4_14()
        {
            new PkitsTest()
                .WithEndEntity("Valid Negative Serial Number Test14 EE")
                .WithCrls("Negative Serial Number CA CRL")
                .WithCerts("Negative Serial Number CA Cert")
                .DoTest();
        }

        /// <summary>4.4.15 Invalid Negative Serial Number Test15</summary>
        /// <remarks>
        /// RFC 3280 mandates that certificate serial numbers be positive integers, but states that relying
        /// parties should be prepared to gracefully handle certificates with serial numbers that are negative,
        /// or zero. In this test, the end entity's certificate has a serial number of -1 (DER encoded as "FF")
        /// and the corresponding CRL lists this certificate as revoked.
        /// </remarks>
        [Test]
        public void Test4_4_15()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid Negative Serial Number Test15 EE")
                .WithCrls("Negative Serial Number CA CRL")
                .WithCerts("Negative Serial Number CA Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.4.16 Valid Long Serial Number Test16</summary>
        /// <remarks>
        /// RFC 3280 mandates that certificate users be able to handle serial number values up to 20 octets
        /// long. In this test, the end entity's certificate has a 20 octet serial number that is not listed on the
        /// corresponding CRL, but the serial number matches the serial number listed on the CRL in all but
        /// the least significant octet.
        /// </remarks>
        [Test]
        public void Test4_4_16()
        {
            new PkitsTest()
                .WithEndEntity("Valid Long Serial Number Test16 EE")
                .WithCrls("Long Serial Number CA CRL")
                .WithCerts("Long Serial Number CA Cert")
                .DoTest();
        }

        /// <summary>4.4.17 Valid Long Serial Number Test17</summary>
        /// <remarks>
        /// RFC 3280 mandates that certificate users be able to handle serial number values up to 20 octets
        /// long. In this test, the end entity's certificate has a 20 octet serial number that is not listed on the
        /// corresponding CRL, but the serial number matches the serial number listed on the CRL in all but
        /// the most significant octet.
        /// </remarks>
        [Test]
        public void Test4_4_17()
        {
            new PkitsTest()
                .WithEndEntity("Valid Long Serial Number Test17 EE")
                .WithCrls("Long Serial Number CA CRL")
                .WithCerts("Long Serial Number CA Cert")
                .DoTest();
        }

        /// <summary>4.4.18 Invalid Long Serial Number Test18</summary>
        /// <remarks>
        /// RFC 3280 mandates that certificate users be able to handle serial number values up to 20 octets
        /// long. In this test, the end entity's certificate has a 20 octet serial number and the certificate's serial
        /// number is listed on the corresponding CRL.
        /// </remarks>
        [Test]
        public void Test4_4_18()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid Long Serial Number Test18 EE")
                .WithCrls("Long Serial Number CA CRL")
                .WithCerts("Long Serial Number CA Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.4.19 Valid Separate Certificate and CRL Keys Test19</summary>
        /// <remarks>
        /// In this test, the intermediate CA uses different keys to sign certificates and CRLs. The Trust
        /// Anchor CA has issued two certificates to the intermediate CA, one for each key. The end entity's
        /// certificate was signed using the intermediate CA's certificate signing key.
        /// </remarks>
        [Test, Ignore("CHECK -- \"Trust anchor for certification path not found.\"")]
        public void Test4_4_19()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid Separate Certificate and CRL Keys Test19 EE")
                .WithCrls("Separate Certificate and CRLKeys CRL")
                .WithCerts("SeparateCertificate and CRL Keys CRL Signing Cert",
                    "Separate Certificate and CRL Keys Certificate Signing CA Cert")
                .DoTest();
        }

        /// <summary>4.4.20 Invalid Separate Certificate and CRL Keys Test20</summary>
        /// <remarks>
        /// In this test, the intermediate CA uses different keys to sign certificates and CRLs. The Trust
        /// Anchor CA has issued two certificates to the intermediate CA, one for each key. The end entity's
        /// certificate was signed using the intermediate CA's certificate signing key. The CRL issued by the
        /// intermediate CA lists the end entity's certificate as revoked.
        /// </remarks>
        [Test, Ignore("CHECK getting \"Trust anchor for certification path not found.\"")]
        public void Test4_4_20()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Invalid Separate Certificate and CRL Keys Test20 EE")
                .WithCrls("Separate Certificate and CRLKeys CRL")
                .WithCerts("SeparateCertificate and CRL Keys CRL Signing Cert",
                    "Separate Certificate and CRL Keys Certificate Signing CA Cert")
                .DoExceptionTest(1, "--");
        }

        /// <summary>4.4.21 Invalid Separate Certificate and CRL Keys Test21</summary>
        /// <remarks>
        /// In this test, the intermediate CA uses different keys to sign certificates and CRLs. The Trust
        /// Anchor CA has issued two certificates to the intermediate CA, one for each key. The certificate
        /// issued to the intermediate CA's CRL verification key has been revoked. The end entity's certificate
        /// was signed using the intermediate CA's certificate signing key.
        /// </remarks>
        [Test, Ignore("CHECK -- Got: Trust anchor for certification path not found.")]
        public void Test4_4_21()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Invalid Separate Certificate and CRL Keys Test21 EE")
                .WithCrls("Separate Certificate and CRLKeys CA2 CRL")
                .WithCerts("SeparateCertificate and CRL Keys CA2 CRL Signing Cert",
                    "Separate Certificate and CRL Keys CA2 Certificate Signing CA Cert")
                .DoExceptionTest(1, "--");
        }

        /// <summary>4.5.1 Valid Basic Self-Issued Old With New Test1</summary>
        /// <remarks>
        /// In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
        /// intermediate CA's new public key. The end entity's certificate was signed using the intermediate
        /// CA's old private key, requiring the relying party to use the CA's old-signed-with-new self-issued
        /// certificate in order to validate the end entity's certificate. The intermediate CA issues one CRL,
        /// signed with its new private key, that covers all of the unexpired certificates that it has issued.
        /// </remarks>
        [Test]
        public void Test4_5_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid Basic SelfIssued Old With New Test1 EE")
                .WithCerts("Basic SelfIssued New Key OldWithNew CA Cert", "Basic SelfIssued New Key CA Cert")
                .WithCrls("Basic SelfIssued New Key CA CRL")
                .DoTest();
        }

        /// <summary>4.5.2 Invalid Basic Self-Issued Old With New Test2</summary>
        /// <remarks>
        /// In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
        /// intermediate CA's new public key. The end entity's certificate was signed using the intermediate
        /// CA's old private key, requiring the relying party to use the CA's old-signed-with-new self-issued
        /// certificate in order to validate the end entity's certificate. The intermediate CA issues one CRL,
        /// signed with its new private key, that covers all of the unexpired certificates that it has issued. This
        /// CRL indicates that the end entity's certificate has been revoked.
        /// </remarks>
        [Test]
        public void Test4_5_2()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid Basic SelfIssued Old With New Test2 EE")
                .WithCerts("Basic SelfIssued New Key OldWithNew CA Cert", "Basic SelfIssued New Key CA Cert")
                .WithCrls("Basic SelfIssued New Key CA CRL")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.5.3 Valid Basic Self-Issued New With Old Test3</summary>
        /// <remarks>
        /// In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
        /// intermediate CA's old public key. The end entity's certificate and a CRL covering all certificates
        /// issued by the intermediate CA was signed using the intermediate CA's new private key, requiring
        /// the relying party to use the CA's new-signed-with-old self-issued certificate in order to validate
        /// both the end entity's certificate and the intermediate CA's CRL. There is a second CRL, signed
        /// using the intermediate CA's old private key that only covers the new-signed-with-old self-issued
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_5_3()
        {
            new PkitsTest()
                .WithEndEntity("Valid Basic SelfIssued New With Old Test3 EE")
                .WithCrls("Basic SelfIssued Old Key CACRL", "Basic SelfIssued Old Key SelfIssued CertCRL")
                .WithCerts("Basic SelfIssued Old Key NewWithOld CA Cert", "Basic SelfIssued Old Key CA Cert")
                .DoTest();
        }

        /// <summary>4.5.4 Valid Basic Self-Issued New With Old Test4</summary>
        /// <remarks>
        /// In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
        /// intermediate CA's old public key. The end entity's certificate was signed using the intermediate
        /// CA's old private key, so there is no need to use a self-issued certificate to create a certification path
        /// from the Trust Anchor to the end entity. However, the CRL covering all certificates issued by the
        /// intermediate CA was signed using the intermediate CA's new private key, requiring the relying
        /// party to use the CA's new-signed-with-old self-issued certificate in order to validate the
        /// intermediate CA's CRL. This CRL must be validated in order to determine the status of the end
        /// entity's certificate. There is a second CRL, signed using the intermediate CA's old private key that
        /// only covers the new-signed-with-old self-issued certificate.
        /// </remarks>
        [Test, Ignore("CHECK I think it is not using the new-signed-with-old")]
        public void Test4_5_4()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid Basic SelfIssued New With Old Test4 EE")
                .WithCrls("Basic SelfIssued Old Key CACRL", "Basic SelfIssued Old Key SelfIssued CertCRL")
                .WithCerts("Basic SelfIssued Old Key NewWithOld CA Cert", "Basic SelfIssued Old Key CA Cert")
                .DoTest();
        }

        /// <summary>4.5.5 Invalid Basic Self-Issued New With Old Test5</summary>
        /// <remarks>
        /// In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
        /// intermediate CA's old public key. The end entity's certificate was signed using the intermediate
        /// CA's old private key, so there is no need to use a self-issued certificate to create a certification path
        /// from the Trust Anchor to the end entity. However, the CRL covering all certificates issued by the
        /// intermediate CA was signed using the intermediate CA's new private key, requiring the relying
        /// party to use the CA's new-signed-with-old self-issued certificate in order to validate the
        /// intermediate CA's CRL. This CRL must be validated in order to determine the status of the end
        /// entity's certificate. There is a second CRL, signed using the intermediate CA's old private key that
        /// only covers the new-signed-with-old self-issued certificate. The end entity's certificate has been
        /// revoked.
        /// </remarks>
        [Test, Ignore("CHECK I think it is not using the new-signed-with-old")]
        public void Test4_5_5()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Invalid Basic SelfIssued New With Old Test5 EE")
                .WithCrls("Basic SelfIssued Old Key CACRL", "Basic SelfIssued Old Key SelfIssued CertCRL")
                .WithCerts("Basic SelfIssued Old Key NewWithOld CA Cert", "Basic SelfIssued Old Key CA Cert")
                .DoExceptionTest(0, "--");
        }

        /// <summary>4.5.6 Valid Basic Self-Issued CRL Signing Key Test6</summary>
        /// <remarks>
        /// In this test, the intermediate CA maintains two key pairs, one for signing certificates and the other
        /// for signing CRLs. The Trust Anchor CA has issued a certificate to the intermediate CA that
        /// contains the intermediate CA's certificate verification public key, and the intermediate CA has
        /// issued a self-issued certificate that contains its CRL verification key. The intermediate CA's
        /// certificate signing private key has been used to sign a CRL that only covers the self-issued
        /// certificate.
        /// </remarks>
        [Test, Ignore("CHECK we may be too strict here, \"Intermediate certificate lacks BasicConstraints\"")]
        public void Test4_5_6()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid Basic SelfIssued CRL Signing Key Test6 EE")
                .WithCrls("Basic SelfIssued CRL SigningKey CA CRL")
                .WithCerts("Basic SelfIssued CRL Signing Key CRL Cert")
                .WithCrls("Basic SelfIssued CRL SigningKey CRL Cert CRL")
                .WithCerts("Basic SelfIssued CRL Signing Key CA Cert")
                .DoTest();
        }

        /// <summary>4.5.7 Invalid Basic Self-Issued CRL Signing Key Test7</summary>
        /// <remarks>
        /// In this test, the intermediate CA maintains two key pairs, one for signing certificates and the other
        /// for signing CRLs. The Trust Anchor CA has issued a certificate to the intermediate CA that
        /// contains the intermediate CA's certificate verification public key, and the intermediate CA has
        /// issued a self-issued certificate that contains its CRL verification key. The intermediate CA's
        /// certificate signing private key has been used to sign a CRL that only covers the self-issued
        /// certificate. The end entity's certificate has been revoked.
        /// </remarks>
        [Test, Ignore("CHECK we may be too strict here, \"Intermediate certificate lacks BasicConstraints\"")]
        public void Test4_5_7()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Invalid Basic SelfIssued CRL Signing Key Test7 EE")
                .WithCrls("Basic SelfIssued CRL SigningKey CA CRL", "Basic SelfIssued CRL SigningKey CRL Cert CRL")
                .WithCerts("Basic SelfIssued CRL Signing Key CRL Cert", "Basic SelfIssued CRL Signing Key CA Cert")
                .DoExceptionTest(1, "--");
        }

        /// <summary>4.5.8 Invalid Basic Self-Issued CRL Signing Key Test7</summary>
        /// <remarks>
        /// In this test, the intermediate CA maintains two key pairs, one for signing certificates and the other
        /// for signing CRLs. The Trust Anchor CA has issued a certificate to the intermediate CA that
        /// contains the intermediate CA's certificate verification public key, and the intermediate CA has
        /// issued a self-issued certificate that contains its CRL verification key. The intermediate CA's
        /// certificate signing private key has been used to sign a CRL that only covers the self-issued
        /// certificate. The end entity's certificate was signed using the CRL signing key.
        /// </remarks>
        [Test]
        public void Test4_5_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Basic SelfIssued CRL Signing Key Test8 EE")
                .WithCrls("Basic SelfIssued CRL SigningKey CA CRL")
                .WithCerts("Basic SelfIssued CRL Signing Key CRL Cert")
                .WithCrls("Basic SelfIssued CRL SigningKey CRL Cert CRL")
                .WithCerts("Basic SelfIssued CRL Signing Key CA Cert")
                .DoExceptionTest(1, "Intermediate certificate lacks BasicConstraints");
        }

        /// <summary>4.6.1 Invalid Missing basicConstraints Test1</summary>
        /// <remarks>
        /// In this test, the intermediate certificate does not have a basicConstraints extension.
        /// </remarks>
        [Test]
        public void Test4_6_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Missing basicConstraints Test1 EE")
                .WithCrls("Missing basicConstraints CA CRL")
                .WithCerts("Missing basicConstraints CA Cert")
                .DoExceptionTest(1, "Intermediate certificate lacks BasicConstraints");
        }

        /// <summary>4.6.2 Invalid cA False Test2</summary>
        /// <remarks>
        /// In this test, the basicConstraints extension is present in the intermediate certificate and is marked
        /// critical, but the cA component is false, indicating that the subject public key may not be used to
        /// verify signatures on certificates.
        /// </remarks>
        [Test]
        public void Test4_6_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid cA False Test2 EE")
                .WithCrls("basicConstraints Critical cA FalseCA CRL")
                .WithCerts("basicConstraints Critical cA False CA Cert")
                .DoExceptionTest(1, "Not a CA certificate");
        }

        /// <summary>4.6.3 Invalid cA False Test3</summary>
        /// <remarks>
        /// In this test, the basicConstraints extension is present in the intermediate certificate and is marked
        /// not critical, but the cA component is false, indicating that the subject public key may not be used to
        /// verify signatures on certificates.As specified in section 8.4.2.1 of X.509, the application must
        /// reject the path either because the application does not recognize the basicConstraints extension or
        /// because cA is set to false.
        /// </remarks>
        [Test]
        public void Test4_6_3()
        {
            new PkitsTest()
                .WithEndEntity("Invalid cA False Test3 EE")
                .WithCrls("basicConstraints Not CriticalcA False CA CRL")
                .WithCerts("basicConstraints Not Critical cA False CA Cert")
                .DoExceptionTest(1, "Not a CA certificate");
        }

        /// <summary>4.6.4 Valid basicConstraints Not Critical Test4</summary>
        /// <remarks>
        /// In this test, the basicConstraints extension is present in the intermediate certificate and the cA
        /// component is true, but the extension is marked not critical.
        /// </remarks>
        [Test]
        public void Test4_6_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid basicConstraints Not Critical Test4 EE")
                .WithCrls("basicConstraints Not Critical CA CRL")
                .WithCerts("basicConstraints Not Critical CA Cert")
                .DoTest();
        }

        /// <summary>4.6.5 Invalid pathLenConstraint Test5</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
        /// followed by a second intermediate certificate and a end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_5()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pathLenConstraint Test5 EE")
                .WithCrls("pathLenConstraint0 subCA CRL", "pathLenConstraint0 CA CRL")
                .WithCerts("pathLenConstraint0 subCA Cert", "pathLenConstraint0 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.6 Invalid pathLenConstraint Test6</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
        /// followed by two more CA certificates, the second of which is the end certificate in the path.
        /// </remarks>
        [Test]
        public void Test4_6_6()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pathLenConstraint Test6 EE")
                .WithCrls("pathLenConstraint0 subCA CRL", "pathLenConstraint0 CA CRL")
                .WithCerts("pathLenConstraint0 subCA Cert", "pathLenConstraint0 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.7 Valid pathLenConstraint Test7</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
        /// followed by the end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid pathLenConstraint Test7 EE")
                .WithCrls("pathLenConstraint0 CA CRL")
                .WithCerts("pathLenConstraint0 CA Cert")
                .DoTest();
        }

        /// <summary>4.6.8 Valid pathLenConstraint Test8</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
        /// followed by the end entity certificate, which is a CA certificate.
        /// </remarks>
        [Test]
        public void Test4_6_8()
        {
            new PkitsTest()
                .WithEndEntity("Valid pathLenConstraint Test8 EE")
                .WithCrls("pathLenConstraint0 CA CRL")
                .WithCerts("pathLenConstraint0 CA Cert")
                .DoTest();
        }

        /// <summary>4.6.9 Invalid pathLenConstraint Test9</summary>
        /// <remarks>
        /// This test consists of a certification path of length 4. The first certificate in the path includes a
        /// pathLenConstraint of 6, the second a pathLenConstraint of 0, and the third a
        /// pathLenConstraint of 0. The fourth certificate is an end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_9()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pathLenConstraint Test9 EE")
                .WithCrls("pathLenConstraint6 subsubCA00 CRL", "pathLenConstraint6 subCA0 CRL",
                    "pathLenConstraint6 CA CRL")
                .WithCerts("pathLenConstraint6 subsubCA00 Cert", "pathLenConstraint6 subCA0 Cert",
                    "pathLenConstraint6 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.10 Invalid pathLenConstraint Test10</summary>
        /// <remarks>
        /// This test consists of a certification path of length 4. The first certificate in the path includes a
        /// pathLenConstraint of 6, the second a pathLenConstraint of 0, and the third a
        /// pathLenConstraint of 0. The end entity certificate is a CA certificate.
        /// </remarks>
        [Test]
        public void Test4_6_10()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pathLenConstraint Test10 EE")
                .WithCrls("pathLenConstraint6 subsubCA00 CRL", "pathLenConstraint6 subCA0 CRL",
                    "pathLenConstraint6 CA CRL")
                .WithCerts("pathLenConstraint6 subsubCA00 Cert", "pathLenConstraint6 subCA0 Cert",
                    "pathLenConstraint6 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.11 Invalid pathLenConstraint Test11</summary>
        /// <remarks>
        /// This test consists of a certification path of length 5. The first certificate in the path includes a
        /// pathLenConstraint of 6, the second a pathLenConstraint of 1, and the third a
        /// pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The fifth
        /// certificate is an end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_11()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pathLenConstraint Test11 EE")
                .WithCrls("pathLenConstraint6subsubsubCA11X CRL", "pathLenConstraint6 subsubCA11 CRL",
                    "pathLenConstraint6 subCA1 CRL", "pathLenConstraint6 CA CRL")
                .WithCerts("pathLenConstraint6 subsubsubCA11X Cert", "pathLenConstraint6 subsubCA11 Cert",
                    "pathLenConstraint6 subCA1 Cert", "pathLenConstraint6 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.12 Invalid pathLenConstraint Test12</summary>
        /// <remarks>
        /// This test consists of a certification path of length 5. The first certificate in the path includes a
        /// pathLenConstraint of 6, the second a pathLenConstraint of 1, and the third a
        /// pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The end
        /// entity certificate is a CA certificate.
        /// </remarks>
        [Test]
        public void Test4_6_12()
        {
            new PkitsTest()
                .WithEndEntity("Invalid pathLenConstraint Test12 EE")
                .WithCrls("pathLenConstraint6subsubsubCA11X CRL", "pathLenConstraint6 subsubCA11 CRL",
                    "pathLenConstraint6 subCA1 CRL", "pathLenConstraint6 CA CRL")
                .WithCerts("pathLenConstraint6 subsubsubCA11X Cert", "pathLenConstraint6 subsubCA11 Cert",
                    "pathLenConstraint6 subCA1 Cert", "pathLenConstraint6 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.13 Valid pathLenConstraint Test13</summary>
        /// <remarks>
        /// This test consists of a certification path of length 5. The first certificate in the path includes a
        /// pathLenConstraint of 6, the second a pathLenConstraint of 4, and the third a
        /// pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The fifth
        /// certificate is an end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_13()
        {
            new PkitsTest()
                .WithEndEntity("Valid pathLenConstraint Test13 EE")
                .WithCrls("pathLenConstraint6subsubsubCA41X CRL", "pathLenConstraint6 subsubCA41 CRL",
                    "pathLenConstraint6 subCA4 CRL", "pathLenConstraint6 CA CRL")
                .WithCerts("pathLenConstraint6 subsubsubCA41X Cert", "pathLenConstraint6 subsubCA41 Cert",
                    "pathLenConstraint6 subCA4 Cert", "pathLenConstraint6 CA Cert")
                .DoTest();
        }

        /// <summary>4.6.14 Valid pathLenConstraint Test14</summary>
        /// <remarks>
        /// This test consists of a certification path of length 5. The first certificate in the path includes a
        /// pathLenConstraint of 6, the second a pathLenConstraint of 4, and the third a
        /// pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The end
        /// entity certificate is a CA certificate.
        /// </remarks>
        [Test]
        public void Test4_6_14()
        {
            new PkitsTest()
                .WithEndEntity("Valid pathLenConstraint Test14 EE")
                .WithCrls("pathLenConstraint6subsubsubCA41X CRL", "pathLenConstraint6 subsubCA41 CRL",
                    "pathLenConstraint6 subCA4 CRL", "pathLenConstraint6 CA CRL")
                .WithCerts("pathLenConstraint6 subsubsubCA41X Cert", "pathLenConstraint6 subsubCA41 Cert",
                    "pathLenConstraint6 subCA4 Cert", "pathLenConstraint6 CA Cert")
                .DoTest();
        }

        /// <summary>4.6.15 Valid Self-Issued pathLenConstraint Test15</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 0 (allowing 0 additional non-self-issued intermediate certificates in the
        /// path). This is followed by a self-issued certificate and the end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_15()
        {
            new PkitsTest()
                .WithEndEntity("Valid SelfIssued pathLenConstraint Test15 EE")
                .WithCerts("pathLenConstraint0 SelfIssued CA Cert", "pathLenConstraint0 CA Cert")
                .WithCrls("pathLenConstraint0 CA CRL")
                .DoTest();
        }

        /// <summary>4.6.16 Invalid Self-Issued pathLenConstraint Test16</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 0 (allowing 0 additional non-self-issued intermediate certificates in the
        /// path). This is followed by a self-issued certificate, an non-self-issued certificate, and the end entity
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_6_16()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued pathLenConstraint Test16 EE")
                .WithCrls("pathLenConstraint0 subCA2 CRL", "pathLenConstraint0 CA CRL")
                .WithCerts("pathLenConstraint0 subCA2 Cert", "pathLenConstraint0 SelfIssued CA Cert",
                    "pathLenConstraint0 CA Cert")
                .DoExceptionTest(1, "Max path length not greater than zero");
        }

        /// <summary>4.6.17 Valid Self-Issued pathLenConstraint Test17</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a basicConstraints extension with a
        /// pathLenConstraint of 1 (allowing 1 additional non-self-issued intermediate certificate in the
        /// path). This is followed by a self-issued certificate, a non-self-issued certificate, another self-issued
        /// certificate, and the end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_6_17()
        {
            new PkitsTest()
                .WithEndEntity("Valid SelfIssued pathLenConstraint Test17 EE")
                .WithCerts("pathLenConstraint1 SelfIssued subCA Cert", "pathLenConstraint1 subCA Cert",
                    "pathLenConstraint1 SelfIssued CA Cert", "pathLenConstraint1 CA Cert")
                .WithCrls("pathLenConstraint1 subCA CRL", "pathLenConstraint1 CA CRL")
                .DoTest();
        }

        /// <summary>4.7.1 Invalid keyUsage Critical keyCertSign False Test1</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a critical keyUsage extension in which
        /// keyCertSign is false.
        /// </remarks>
        [Test]
        public void Test4_7_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid keyUsage Critical keyCertSign False Test1 EE")
                .WithCrls("keyUsage Critical keyCertSignFalse CA CRL")
                .WithCerts("keyUsage Critical keyCertSign False CA Cert")
                .DoExceptionTest(1, "Issuer certificate keyusage extension is critical and does not permit key signing.");
        }

        /// <summary>4.7.2 Invalid keyUsage Not Critical keyCertSign False Test2</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a non-critical keyUsage extension in which
        /// keyCertSign is false.
        /// </remarks>
        [Test]
        public void Test4_7_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid keyUsage Not Critical keyCertSign False Test2 EE")
                .WithCrls("keyUsage Not CriticalkeyCertSign False CA CRL")
                .WithCerts("keyUsage Not Critical keyCertSign False CA Cert")
                .DoExceptionTest(1, "Issuer certificate keyusage extension is critical and does not permit key signing.");
        }

        /// <summary>4.7.3 Valid keyUsage Not Critical Test3</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a non-critical keyUsage extension.
        /// </remarks>
        [Test]
        public void Test4_7_3()
        {
            new PkitsTest()
                .WithEndEntity("Valid keyUsage Not Critical Test3 EE")
                .WithCrls("keyUsage Not Critical CA CRL")
                .WithCerts("keyUsage Not Critical CA Cert")
                .DoTest();
        }

        /// <summary>4.7.4 Invalid keyUsage Critical cRLSign False Test4</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a critical keyUsage extension in which cRLSign
        /// is false.
        /// </remarks>
        [Test]
        public void Test4_7_4()
        {
            new PkitsTest()
                .WithEndEntity("Invalid keyUsage Critical cRLSign False Test4 EE")
                .WithCrls("keyUsage Critical cRLSign False CACRL")
                .WithCerts("keyUsage Critical cRLSign False CA Cert")
                .DoExceptionTest(0, "Issuer certificate key usage extension does not permit CRL signing.");
        }

        /// <summary>4.7.5 Invalid keyUsage Not Critical cRLSign False Test5</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a non-critical keyUsage extension in which
        /// cRLSign is false.
        /// </remarks>
        [Test]
        public void Test4_7_5()
        {
            new PkitsTest()
                .WithEndEntity("Invalid keyUsage Not Critical cRLSign False Test5 EE")
                .WithCrls("keyUsage Not Critical cRLSignFalse CA CRL")
                .WithCerts("keyUsage Not Critical cRLSign False CA Cert")
                .DoExceptionTest(0, "Issuer certificate key usage extension does not permit CRL signing.");
        }

        /// <summary>4.8.1 All Certificates Same Policy Test1</summary>
        /// <remarks>
        /// In this test, every certificate in the path asserts the same policy, NIST-test-policy-1. The
        /// certification path in this test is the same certification path as in Valid Signatures Test1. If
        /// possible, it is recommended that the certification path in this test be validated using the following
        /// inputs:
        /// 1. default settings, but with initial-explicit-policy set. The path should validate
        /// successfully.
        /// 2. default settings, but with initial-explicit-policy set and initial-policy-set =
        /// {NIST-test-policy-1}. The path should validate successfully.
        /// 3. default settings, but with initial-explicit-policy set and initial-policy-set =
        /// {NIST-test-policy-2}. The path should not validate successfully.
        /// 4. default settings, but with initial-explicit-policy set and initial-policy-set =
        /// {NIST-test-policy-1, NIST-test-policy-2}. The path should validate
        /// successfully.
        /// </remarks>
        [Test]
        public void Test4_8_1()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("Valid Certificate Path Test1 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .WithExplicitPolicyRequired(true)
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("Valid Certificate Path Test1 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .WithExplicitPolicyRequired(true)
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            // 3
            new PkitsTest()
                .WithEndEntity("Valid Certificate Path Test1 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .WithExplicitPolicyRequired(true)
                .WithPoliciesByName("NIST-test-policy-2")
                .DoExceptionTest(-1, "Path processing failed on policy.");

            // 4
            new PkitsTest()
                .WithEndEntity("Valid Certificate Path Test1 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .WithExplicitPolicyRequired(true)
                .WithPoliciesByName("NIST-test-policy-1", "NIST-test-policy-2")
                .DoTest();
        }

        /// <summary>4.8.2 All Certificates No Policies Test2</summary>
        /// <remarks>
        /// In this test, the certificatePolicies extension is omitted from every certificate in the path. If
        /// possible, it is recommended that the certification path in this test be validated using the following
        /// inputs:
        /// 1. default settings.The path should validate successfully.
        /// 2. default settings, but with initial-explicit-policy set . The path should not validate
        /// successfully.
        /// </remarks>
        [Test]
        public void Test4_8_2()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("All Certificates No Policies Test2 EE")
                .WithCrls("No Policies CA CRL")
                .WithCerts("No Policies CA Cert")
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("All Certificates No Policies Test2 EE")
                .WithCrls("No Policies CA CRL")
                .WithCerts("No Policies CA Cert")
                .WithExplicitPolicyRequired(true)
                .DoExceptionTest(1, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.3 Different Policies Test3</summary>
        /// <remarks>
        /// In this test, every certificate in the path asserts the same certificate policy except the first certificate
        /// in the path. If possible, it is recommended that the certification path in this test be validated using
        /// the following inputs:
        /// 1. default settings. The path should validate successfully.
        /// 2. default settings, but with initial-explicit-policy set . The path should not validate
        /// successfully.
        /// 3. default settings, but with initial-explicit-policy set and initial-policy-set =
        /// {NIST-test-policy-1, NIST-test-policy-2}. The path should not validate
        /// successfully.
        /// </remarks>
        [Test]
        public void Test4_8_3()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test3 EE")
                .WithCrls("Policies P2 subCA CRL", "Good CA CRL")
                .WithCerts("Policies P2 subCA Cert", "Good CA Cert")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("Different Policies Test3 EE")
                .WithCrls("Policies P2 subCA CRL", "Good CA CRL")
                .WithCerts("Policies P2 subCA Cert", "Good CA Cert")
                .WithExplicitPolicyRequired(true)
                .DoExceptionTest(1, "No valid policy tree found when one expected.");

            new PkitsTest()
                .WithEndEntity("Different Policies Test3 EE")
                .WithCrls("Policies P2 subCA CRL", "Good CA CRL")
                .WithCerts("Policies P2 subCA Cert", "Good CA Cert")
                .WithExplicitPolicyRequired(true)
                .WithPoliciesByName("NIST-test-policy-1", "NIST-test-policy-2")
                .DoExceptionTest(1, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.4 Different Policies Test4</summary>
        /// <remarks>
        /// In this test, every certificate in the path asserts the same certificate policy except the end entity
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_8_4()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test4 EE")
                .WithCrls("Good subCA CRL", "Good CA CRL")
                .WithCerts("Good subCA Cert", "Good CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.5 Different Policies Test5</summary>
        /// <remarks>
        /// In this test, every certificate in the path except the second certificate asserts the same policy.
        /// </remarks>
        [Test]
        public void Test4_8_5()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test5 EE")
                .WithCrls("Policies P2 subCA2 CRL", "Good CA CRL")
                .WithCerts("Policies P2 subCA2 Cert", "Good CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.6 Overlapping Policies Test6</summary>
        /// <remarks>
        /// The following path is such that the intersection of certificate policies among all the certificates has
        /// exactly one policy, NIST-test-policy-1. The final certificate in the path is a CA certificate. If
        /// possible, it is recommended that the certification path in this test be validated using the following
        /// inputs:
        /// 1. default settings. The path should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 3. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should not validate successfully.
        /// </remarks>
        [Test]
        public void Test4_8_6()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("Overlapping Policies Test6 EE")
                .WithCrls("Policies P1234 subsubCAP123P12CRL", "Policies P1234 subCAP123 CRL", "Policies P1234 CA CRL")
                .WithCerts("Policies P1234 subsubCAP123P12 Cert", "Policies P1234 subCAP123 Cert",
                    "Policies P1234 CA Cert")
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("Overlapping Policies Test6 EE")
                .WithCrls("Policies P1234 subsubCAP123P12CRL", "Policies P1234 subCAP123 CRL", "Policies P1234 CA CRL")
                .WithCerts("Policies P1234 subsubCAP123P12 Cert", "Policies P1234 subCAP123 Cert",
                    "Policies P1234 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            // 3
            new PkitsTest()
                .WithEndEntity("Overlapping Policies Test6 EE")
                .WithCrls("Policies P1234 subsubCAP123P12CRL", "Policies P1234 subCAP123 CRL", "Policies P1234 CA CRL")
                .WithCerts("Policies P1234 subsubCAP123P12 Cert", "Policies P1234 subCAP123 Cert",
                    "Policies P1234 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.8.7 Different Policies Test7</summary>
        /// <remarks>
        /// The following path is such that the intersection of certificate policies among all the certificates is
        /// empty. The final certificate in the path is a CA certificate.
        /// </remarks>
        [Test]
        public void Test4_8_7()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test7 EE")
                .WithCrls("Policies P123 subsubCAP12P1 CRL", "Policies P123 subCAP12 CRL", "Policies P123 CA CRL")
                .WithCerts("Policies P123 subsubCAP12P1 Cert", "Policies P123 subCAP12 Cert", "Policies P123 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.8 Different Policies Test8</summary>
        /// <remarks>
        /// The following path is such that the intersection of certificate policies among all the certificates is
        /// empty. The final certificate in the path is a CA certificate.
        /// </remarks>
        [Test]
        public void Test4_8_8()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test8 EE")
                .WithCrls("Policies P12 subsubCAP1P2 CRL", "Policies P12 subCAP1 CRL", "Policies P12 CA CRL")
                .WithCerts("Policies P12 subsubCAP1P2 Cert", "Policies P12 subCAP1 Cert", "Policies P12 CA Cert")
                .DoExceptionTest(1, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.9 Different Policies Test9</summary>
        /// <remarks>
        /// The following path is such that the intersection of certificate policies among all the certificates is
        /// empty.
        /// </remarks>
        [Test]
        public void Test4_8_9()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test9 EE")
                .WithCrls("Policies P123subsubsubCAP12P2P1 CRL", "Policies P123 subsubCAP2P2 CRL",
                    "Policies P123 subCAP12 CRL", "Policies P123 CA CRL")
                .WithCerts("Policies P123 subsubsubCAP12P2P1 Cert", "Policies P123 subsubCAP12P2 Cert",
                    "Policies P123 subCAP12 Cert", "Policies P123 CA Cert")
                .DoExceptionTest(1, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.10 All Certificates Same Policies Test10</summary>
        /// <remarks>
        /// In this test, every certificate in the path asserts the same policies, NIST-test-policy-1 and NIST-test-policy-2.
        /// If possible, it is recommended that the certification path in this test be validated
        /// using the following inputs:
        /// 1. default settings. The path should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 3. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should validate successfully.
        /// </remarks>
        [Test]
        public void Test4_8_10()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("All Certificates Same Policies Test10 EE")
                .WithCrls("Policies P12 CA CRL")
                .WithCerts("Policies P12 CA Cert")
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("All Certificates Same Policies Test10 EE")
                .WithCrls("Policies P12 CA CRL")
                .WithCerts("Policies P12 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            // 3
            new PkitsTest()
                .WithEndEntity("All Certificates Same Policies Test10 EE")
                .WithCrls("Policies P12 CA CRL")
                .WithCerts("Policies P12 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoTest();
        }

        /// <summary>4.8.11 All Certificates AnyPolicy Test11</summary>
        /// <remarks>
        /// In this test, every certificate in the path asserts the special policy anyPolicy. If possible, it is
        /// recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings. The path should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// </remarks>
        [Test]
        public void Test4_8_11()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("All Certificates anyPolicy Test11 EE")
                .WithCrls("anyPolicy CA CRL")
                .WithCerts("anyPolicy CA Cert")
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("All Certificates anyPolicy Test11 EE")
                .WithCrls("anyPolicy CA CRL")
                .WithCerts("anyPolicy CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();
        }

        /// <summary>4.8.12 Different Policies Test12</summary>
        /// <remarks>
        /// In this test, the path consists of two certificates, each of which asserts a different certificate policy.
        /// </remarks>
        [Test]
        public void Test4_8_12()
        {
            new PkitsTest()
                .WithEndEntity("Different Policies Test12 EE")
                .WithCrls("Policies P3 CA CRL")
                .WithCerts("Policies P3 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.8.13 All Certificates Same Policies Test13</summary>
        /// <remarks>
        /// In this test, every certificate in the path asserts the same policies, NIST-test-policy-1, NIST-testpolicy-2,
        /// and NIST-test-policy-3. If possible, it is recommended that the certification path in this
        /// test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should validate successfully.
        /// 3. default settings, but with initial-policy-set = {NIST-test-policy-3}. The path
        /// should validate successfully.
        /// </remarks>
        [Test]
        public void Test4_8_13()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("All Certificates Same Policies Test13 EE")
                .WithCrls("Policies P123 CA CRL")
                .WithCerts("Policies P123 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("All Certificates Same Policies Test13 EE")
                .WithCrls("Policies P123 CA CRL")
                .WithCerts("Policies P123 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoTest();

            // 3
            new PkitsTest()
                .WithEndEntity("All Certificates Same Policies Test13 EE")
                .WithCrls("Policies P123 CA CRL")
                .WithCerts("Policies P123 CA Cert")
                .WithPoliciesByName("NIST-test-policy-3")
                .DoTest();
        }

        /// <summary>4.8.14 AnyPolicy Test14</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts anyPolicy and the end entity certificate asserts
        /// NIST-test-policy-1. If possible, it is recommended that the certification path in this test be
        /// validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should not validate successfully.
        /// </remarks>
        [Test]
        public void Test4_8_14()
        {
            // 1
            new PkitsTest()
                .WithEndEntity("AnyPolicy Test14 EE")
                .WithCrls("anyPolicy CA CRL")
                .WithCerts("anyPolicy CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            // 2
            new PkitsTest()
                .WithEndEntity("AnyPolicy Test14 EE")
                .WithCrls("anyPolicy CA CRL")
                .WithCerts("anyPolicy CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.8.15 User Notice Qualifier Test15</summary>
        /// <remarks>
        /// In this test, the path consists of a single certificate. The certificate asserts the policy NIST-testpolicy-1
        /// and includes a user notice policy qualifier.
        /// <para>
        /// Display of user notice beyond CertPath API at the moment.
        /// </para>
        /// </remarks>
        [Test]
        public void Test4_8_15()
        {
            new PkitsTest()
                .WithEndEntity("User Notice Qualifier Test15 EE")
                .DoTest();

            new PkitsTest()
                .WithPoliciesByName("NIST-test-policy-2")
                .WithEndEntity("User Notice Qualifier Test15 EE")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.8.16 User Notice Qualifier Test16</summary>
        /// <remarks>
        /// In this test, the path consists of an intermediate certificate and an end entity certificate. The
        /// intermediate certificate asserts the policy NIST-test-policy-1. The end entity certificate asserts
        /// both NIST-test-policy-1 and NIST-test-policy-2. Each policy in the end entity certificate has a
        /// different user notice qualifier associated with it.
        /// <para>
        /// Display of user notice beyond CertPath API at the moment.
        /// </para>
        /// </remarks>
        [Test]
        public void Test4_8_16()
        {
            new PkitsTest()
                .WithEndEntity("User Notice Qualifier Test16 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();
        }

        /// <summary>4.8.17 User Notice Qualifier Test17</summary>
        /// <remarks>
        /// In this test, the path consists of an intermediate certificate and an end entity certificate. The
        /// intermediate certificate asserts the policy NIST-test-policy-1. The end entity certificate asserts
        /// anyPolicy. There is a user notice policy qualifier associated with anyPolicy in the end entity
        /// certificate.
        /// <para>
        /// Display of user notice beyond CertPath API at the moment.
        /// </para>
        /// </remarks>
        [Test]
        public void Test4_8_17()
        {
            new PkitsTest()
                .WithEndEntity("User Notice Qualifier Test17 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();
        }

        /// <summary>4.8.18 User Notice Qualifier Test18</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts policies NIST-test-policy-1 and NIST-test-policy-2.
        /// The end certificate asserts NIST-test-policy-1 and anyPolicy. Each of the policies in the end
        /// entity certificate asserts a different user notice policy qualifier. If possible, it is recommended that
        /// the certification path in this test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully and the qualifier associated with NIST-test-policy-1
        /// in the end entity certificate should be displayed.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should validate successfully and the qualifier associated with anyPolicy in the
        /// end entity certificate should be displayed.
        /// <para>
        /// Display of policy messages beyond CertPath API at the moment.
        /// </para>
        /// </remarks>
        [Test]
        public void Test4_8_18()
        {
            new PkitsTest()
                .WithEndEntity("User Notice Qualifier Test18 EE")
                .WithCrls("Policies P12 CA CRL")
                .WithCerts("Policies P12 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("User Notice Qualifier Test18 EE")
                .WithCrls("Policies P12 CA CRL")
                .WithCerts("Policies P12 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoTest();
        }

        /// <summary>4.8.19 User Notice Qualifier Test19</summary>
        /// <remarks>
        /// In this test, the path consists of a single certificate. The certificate asserts the policy NIST-testpolicy-1
        /// and includes a user notice policy qualifier. The user notice qualifier contains explicit text
        /// that is longer than 200 bytes.
        /// [RFC 3280 4.2.1.5] Note: While the explicitText has a maximum size of 200 characters,
        /// some non-conforming CAs exceed this limit. Therefore, certificate users SHOULD
        /// gracefully handle explicitText with more than 200 characters.
        /// </remarks>
        [Test]
        public void Test4_8_19()
        {
            new PkitsTest()
                .WithEndEntity("User Notice Qualifier Test19 EE")
                .DoTest();
        }

        /// <summary>4.8.20 CPS Pointer Qualifier Test20</summary>
        /// <remarks>
        /// In this test, the path consists of an intermediate certificate and an end entity certificate, both of
        /// which assert the policy NIST-test-policy-1. There is a CPS pointer policy qualifier associated with
        /// NIST-test-policy-1 in the end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_8_20()
        {
            new PkitsTest()
                .WithEndEntity("CPS Pointer Qualifier Test20 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert")
                .DoTest();
        }

        /// <summary>4.9.1 Valid RequireExplicitPolicy Test1</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 10. This is followed by three more intermediate certificates and an
        /// end entity certificate. The end entity certificate does not include a certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid requireExplicitPolicy Test1 EE")
                .WithCrls("requireExplicitPolicy10subsubsubCA CRL", "requireExplicitPolicy10 subsubCACRL",
                    "requireExplicitPolicy10 subCA CRL", "requireExplicitPolicy10 CA CRL")
                .WithCerts("requireExplicitPolicy10 subsubsubCA Cert", "requireExplicitPolicy10 subsubCA Cert",
                    "requireExplicitPolicy10 subCA Cert", "requireExplicitPolicy10 CA Cert")
                .DoTest();
        }

        /// <summary>4.9.2 Valid RequireExplicitPolicy Test2</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 5. This is followed by three more intermediate certificates and an end
        /// entity certificate. The end entity certificate does not include a certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_2()
        {
            new PkitsTest()
                .WithEndEntity("Valid requireExplicitPolicy Test2 EE")
                .WithCrls("requireExplicitPolicy5 subsubsubCACRL", "requireExplicitPolicy5 subsubCA CRL",
                    "requireExplicitPolicy5 subCA CRL", "requireExplicitPolicy5 CA CRL")
                .WithCerts("requireExplicitPolicy5 subsubsubCA Cert", "requireExplicitPolicy5 subsubCA Cert",
                    "requireExplicitPolicy5 subCA Cert", "requireExplicitPolicy5 CA Cert")
                .DoTest();
        }

        /// <summary>4.9.3 Invalid RequireExplicitPolicy Test3</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 4. This is followed by three more intermediate certificates and an end
        /// entity certificate. The end entity certificate does not include a certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_3()
        {
            new PkitsTest()
                .WithEndEntity("Invalid requireExplicitPolicy Test3 EE")
                .WithCrls("requireExplicitPolicy4 subsubsubCACRL", "requireExplicitPolicy4 subsubCA CRL",
                    "requireExplicitPolicy4 subCA CRL", "requireExplicitPolicy4 CA CRL")
                .WithCerts("requireExplicitPolicy4 subsubsubCA Cert", "requireExplicitPolicy4 subsubCA Cert",
                    "requireExplicitPolicy4 subCA Cert", "requireExplicitPolicy4 CA Cert")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.9.4 Valid RequireExplicitPolicy Test4</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 0. This is followed by three more intermediate certificates and an end
        /// entity certificate.
        /// </remarks>
        [Test]
        public void Test4_9_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid requireExplicitPolicy Test4 EE")
                .WithCrls("requireExplicitPolicy0 subsubsubCACRL", "requireExplicitPolicy0 subsubCA CRL",
                    "requireExplicitPolicy0 subCA CRL", "requireExplicitPolicy0 CA CRL")
                .WithCerts("requireExplicitPolicy0 subsubsubCA Cert", "requireExplicitPolicy0 subsubCA Cert",
                    "requireExplicitPolicy0 subCA Cert", "requireExplicitPolicy0 CA Cert")
                .DoTest();
        }

        /// <summary>4.9.5 Invalid RequireExplicitPolicy Test5</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 7. The second certificate in the path includes a policyConstraints
        /// extension with requireExplicitPolicy set to 2. The third certificate in the path includes a
        /// policyConstraints extension with requireExplicitPolicy set to 4. This is followed by one more
        /// intermediate certificate and an end entity certificate. The end entity certificate does not include a
        /// certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_5()
        {
            new PkitsTest()
                .WithEndEntity("Invalid requireExplicitPolicy Test5 EE")
                .WithCrls("requireExplicitPolicy7subsubsubCARE2RE4 CRL", "requireExplicitPolicy7subsubCARE2RE4 CRL",
                    "requireExplicitPolicy7 subCARE2 CRL", "requireExplicitPolicy7 CA CRL")
                .WithCerts("requireExplicitPolicy7 subsubsubCARE2RE4 Cert",
                    "requireExplicitPolicy7 subsubCARE2RE4 Cert", "requireExplicitPolicy7 subCARE2 Cert",
                    "requireExplicitPolicy7 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.9.6 Valid Self-Issued requireExplicitPolicy Test6</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 2. This is followed by a self-issued intermediate certificate and an
        /// end entity certificate. The end entity certificate does not include a certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_6()
        {
            new PkitsTest()
                .WithEndEntity("Valid SelfIssued requireExplicitPolicy Test6 EE")
                .WithCerts("requireExplicitPolicy2 SelfIssued CA Cert", "requireExplicitPolicy2 CA Cert")
                .WithCrls("requireExplicitPolicy2 CA CRL")
                .DoTest();
        }

        /// <summary>4.9.7 Invalid Self-Issued requireExplicitPolicy Test7</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 2. This is followed by a self-issued intermediate certificate, a non-self-issued
        /// intermediate certificate, and an end entity certificate. The end entity certificate does not
        /// include a certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_7()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued requireExplicitPolicy Test7 EE")
                .WithCrls("requireExplicitPolicy2 subCA CRL", "requireExplicitPolicy2 CA CRL")
                .WithCerts("requireExplicitPolicy2 subCA Cert", "requireExplicitPolicy2 SelfIssued CA Cert",
                    "requireExplicitPolicy2 CA Cert")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.9.8 Invalid Self-Issued requireExplicitPolicy Test8</summary>
        /// <remarks>
        /// In this test, the first certificate in the path includes a policyConstraints extension with
        /// requireExplicitPolicy set to 2. This is followed by a self-issued intermediate certificate, a non-self-issued
        /// intermediate certificate, a self-issued intermediate certificate, and an end entity
        /// certificate. The end entity certificate does not include a certificatePolicies extension.
        /// </remarks>
        [Test]
        public void Test4_9_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued requireExplicitPolicy Test8 EE")
                .WithCerts("requireExplicitPolicy2 SelfIssued subCA Cert", "requireExplicitPolicy2 subCA Cert",
                    "requireExplicitPolicy2 SelfIssued CA Cert", "requireExplicitPolicy2 CA Cert")
                .WithCrls("requireExplicitPolicy2 subCA CRL", "requireExplicitPolicy2 CA CRL")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.10.1 Valid Policy Mapping Test1</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to
        /// NIST-test-policy-2. The end entity certificate asserts NIST-test-policy-2. If possible, it is
        /// recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should not validate successfully.
        /// 3. default settings, but with initial-policy-mapping-inhibit set. The path should not
        /// validate successfully.
        /// </remarks>
        [Test]
        public void Test4_10_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test1 EE")
                .WithCrls("Mapping 1to2 CA CRL")
                .WithCerts("Mapping 1to2 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test1 EE")
                .WithCrls("Mapping 1to2 CA CRL")
                .WithCerts("Mapping 1to2 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoExceptionTest(-1, "Path processing failed on policy.");

            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test1 EE")
                .WithCrls("Mapping 1to2 CA CRL")
                .WithCerts("Mapping 1to2 CA Cert")
                .WithPolicyMappingInhibited(true)
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.10.2 Invalid Policy Mapping Test2</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to
        /// NIST-test-policy-2. The end entity certificate asserts NIST-test-policy-1. If possible, it is
        /// recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings. The path should not validate successfully.
        /// 2. default settings, but with initial-policy-mapping-inhibit set. The path should not
        /// validate successfully.
        /// </remarks>
        [Test]
        public void Test4_10_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Policy Mapping Test2 EE")
                .WithCrls("Mapping 1to2 CA CRL")
                .WithCerts("Mapping 1to2 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");

            new PkitsTest()
                .WithEndEntity("Invalid Policy Mapping Test2 EE")
                .WithCrls("Mapping 1to2 CA CRL")
                .WithCerts("Mapping 1to2 CA Cert")
                .WithPolicyMappingInhibited(true)
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.10.3 Valid Policy Mapping Test3</summary>
        /// <remarks>
        /// In this test, the path is valid under NIST-test-policy-2 as a result of policy mappings. If possible,
        /// it is recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should not validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should validate successfully.
        /// </remarks>
        [Test]
        public void Test4_10_3()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test3 EE")
                .WithCrls("P12 Mapping 1to3 subsubCA CRL", "P12 Mapping 1to3 subCA CRL", "P12 Mapping 1to3 CA CRL")
                .WithCerts("P12 Mapping 1to3 subsubCA Cert", "P12 Mapping 1to3 subCA Cert", "P12 Mapping 1to3 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoExceptionTest(-1, "Path processing failed on policy.");

            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test3 EE")
                .WithCrls("P12 Mapping 1to3 subsubCA CRL", "P12 Mapping 1to3 subCA CRL", "P12 Mapping 1to3 CA CRL")
                .WithCerts("P12 Mapping 1to3 subsubCA Cert", "P12 Mapping 1to3 subCA Cert", "P12 Mapping 1to3 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoTest();
        }

        /// <summary>4.10.4 Invalid Policy Mapping Test4</summary>
        /// <remarks>
        /// In this test, the policy asserted in the end entity certificate is not in the authorities-constrainedpolicy-set.
        /// </remarks>
        [Test]
        public void Test4_10_4()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Policy Mapping Test4 EE")
                .WithCrls("P12 Mapping 1to3 subsubCA CRL", "P12 Mapping 1to3 subCA CRL", "P12 Mapping 1to3 CA CRL")
                .WithCerts("P12 Mapping 1to3 subsubCA Cert", "P12 Mapping 1to3 subCA Cert", "P12 Mapping 1to3 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.10.5 Valid Policy Mapping Test5</summary>
        /// <remarks>
        /// In this test, the path is valid under NIST-test-policy-1 as a result of policy mappings. If possible,
        /// it is recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-6}. The path
        /// should not validate successfully.
        /// </remarks>
        [Test]
        public void Test4_10_5()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test5 EE")
                .WithCrls("P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL")
                .WithCerts("P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test5 EE")
                .WithCrls("P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL")
                .WithCerts("P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert")
                .WithPoliciesByName("NIST-test-policy-6")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.10.6 Valid Policy Mapping Test6</summary>
        /// <remarks>
        /// In this test, the path is valid under NIST-test-policy-1 as a result of policy mappings. If possible,
        /// it is recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-6}. The path
        /// should not validate successfully.
        /// </remarks>
        [Test]
        public void Test4_10_6()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test6 EE")
                .WithCrls("P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL")
                .WithCerts("P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test6 EE")
                .WithCrls("P1 Mapping 1to234 subCA CRL", "P1 Mapping 1to234 CA CRL")
                .WithCerts("P1 Mapping 1to234 subCA Cert", "P1 Mapping 1to234 CA Cert")
                .WithPoliciesByName("NIST-test-policy-6")
                .DoExceptionTest(-1, "Path processing failed on policy.");
        }

        /// <summary>4.10.7 Invalid Mapping From anyPolicy Test7</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a policyMappings extension that includes a
        /// mapping in which the issuerDomainPolicy is anyPolicy. The intermediate certificate also
        /// includes a critical policyConstraints extension with requireExplicitPolicy set to 0.
        /// [RFC 3280 6.1.4] (a) If a policy mapping extension is present, verify that the special
        /// value anyPolicy does not appear as an issuerDomainPolicy or a subjectDomainPolicy.
        /// </remarks>
        [Test]
        public void Test4_10_7()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Mapping From anyPolicy Test7 EE")
                .WithCrls("Mapping From anyPolicy CA CRL")
                .WithCerts("Mapping From anyPolicy CA Cert")
                .DoExceptionTest(1, "IssuerDomainPolicy is anyPolicy");
        }

        /// <summary>4.10.8 Invalid Mapping To anyPolicy Test8</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a policyMappings extension that includes a
        /// mapping in which the subjectDomainPolicy is anyPolicy. The intermediate certificate also
        /// includes a critical policyConstraints extension with requireExplicitPolicy set to 0.
        /// [RFC 3280 6.1.4] (a) If a policy mapping extension is present, verify that the special
        /// value anyPolicy does not appear as an issuerDomainPolicy or a subjectDomainPolicy.
        /// </remarks>
        [Test]
        public void Test4_10_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Mapping To anyPolicy Test8 EE")
                .WithCrls("Mapping To anyPolicy CA CRL")
                .WithCerts("Mapping To anyPolicy CA Cert")
                .DoExceptionTest(1, "SubjectDomainPolicy is anyPolicy");
        }

        /// <summary>4.10.9 Valid Policy Mapping Test9</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts anyPolicy and maps NIST-test-policy-1 to NIST-test-policy-2.
        /// The end entity certificate asserts NIST-test-policy-1.
        /// </remarks>
        [Test]
        public void Test4_10_9()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test9 EE")
                .WithCrls("PanyPolicy Mapping 1to2 CA CRL")
                .WithCerts("PanyPolicy Mapping 1to2 CA Cert")
                .DoTest();
        }

        /// <summary>4.10.10 Invalid Policy Mapping Test10</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1. The second intermediate
        /// certificate asserts anyPolicy and maps NIST-test-policy-1 to NIST-test-policy-2. The end entity
        /// certificate asserts NIST-test-policy-1.
        /// </remarks>
        [Test]
        public void Test4_10_10()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Policy Mapping Test10 EE")
                .WithCrls("Good subCA PanyPolicyMapping 1to2 CA CRL", "Good CA CRL")
                .WithCerts("Good subCA PanyPolicy Mapping 1to2 CA Cert", "Good CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.10.11 Valid Policy Mapping Test11</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1. The second intermediate
        /// certificate asserts anyPolicy and maps NIST-test-policy-1 to NIST-test-policy-2. The end entity
        /// certificate asserts NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_10_11()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test11 EE")
                .WithCrls("Good subCA PanyPolicyMapping 1to2 CA CRL", "Good CA CRL")
                .WithCerts("Good subCA PanyPolicy Mapping 1to2 CA Cert", "Good CA Cert")
                .DoTest();
        }

        /// <summary>4.10.12 Valid Policy Mapping Test12</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
        /// maps NIST-test-policy-1 to NIST-test-policy-3. The end entity certificate asserts anyPolicy and
        /// NIST-test-policy-3, each with a different user notice policy qualifier. If possible, it is
        /// recommended that the certification path in this test be validated using the following inputs:
        /// 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
        /// should validate successfully and the application should display the user notice
        /// associated with NIST-test-policy-3 in the end entity certificate.
        /// 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
        /// should validate successfully and the application should display the user notice
        /// associated with anyPolicy in the end entity certificate.
        /// </remarks>
        [Test]
        public void Test4_10_12()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test12 EE")
                .WithCrls("P12 Mapping 1to3 CA CRL")
                .WithCerts("P12 Mapping 1to3 CA Cert")
                .WithPoliciesByName("NIST-test-policy-1")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test12 EE")
                .WithCrls("P12 Mapping 1to3 CA CRL")
                .WithCerts("P12 Mapping 1to3 CA Cert")
                .WithPoliciesByName("NIST-test-policy-2")
                .DoTest();
        }

        /// <summary>4.10.13 Valid Policy Mapping Test13</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and anyPolicy and maps NIST-test-policy-1
        /// to NIST-test-policy-2. There is a user notice policy qualifier associated with each of the policies.
        /// The end entity certificate asserts NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_10_13()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test13 EE")
                .WithCrls("P1anyPolicy Mapping 1to2 CA CRL")
                .WithCerts("P1anyPolicy Mapping 1to2 CA Cert")
                .DoTest();
        }

        /// <summary>4.10.14 Valid Policy Mapping Test14</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and anyPolicy and maps NIST-test-policy-1
        /// to NIST-test-policy-2. There is a user notice policy qualifier associated with each of the policies.
        /// The end entity certificate asserts NIST-test-policy-1.
        /// </remarks>
        [Test]
        public void Test4_10_14()
        {
            new PkitsTest()
                .WithEndEntity("Valid Policy Mapping Test14 EE")
                .WithCrls("P1anyPolicy Mapping 1to2 CA CRL")
                .WithCerts("P1anyPolicy Mapping 1to2 CA Cert")
                .DoTest();
        }

        /// <summary>4.11.1 Invalid inhibitPolicyMapping Test1</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 0. The second intermediate
        /// certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The end
        /// entity certificate asserts NIST-test-policy-1 and NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_11_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitPolicyMapping Test1 EE")
                .WithCrls("inhibitPolicyMapping0 subCA CRL", "inhibitPolicyMapping0 CA CRL")
                .WithCerts("inhibitPolicyMapping0 subCA Cert", "inhibitPolicyMapping0 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.2 Valid inhibitPolicyMapping Test2</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
        /// includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate certificate
        /// asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-testpolicy-1 to NIST-test-policy-3 and
        /// NIST-test-policy-2 to NIST-test-policy-4. The end entity certificate asserts NIST-test-policy-3.
        /// </remarks>
        [Test]
        public void Test4_11_2()
        {
            new PkitsTest()
                .WithEndEntity("Valid inhibitPolicyMapping Test2 EE")
                .WithCrls("inhibitPolicyMapping1 P12 subCACRL", "inhibitPolicyMapping1 P12 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P12 subCA Cert", "inhibitPolicyMapping1 P12 CA Cert")
                .DoTest();
        }

        /// <summary>4.11.3 Invalid inhibitPolicyMapping Test3</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
        /// includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
        /// intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-testpolicy-1 to
        /// NIST-test-policy-3 and NIST-test-policy-2 to NIST-test-policy-4. The third intermediate certificate asserts
        /// NIST-test-policy-3 and NIST-test-policy-4 and maps NIST-testpolicy-3 to NIST-test-policy-5.
        /// The end entity certificate asserts NIST-test-policy-5.
        /// </remarks>
        [Test]
        public void Test4_11_3()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitPolicyMapping Test3 EE")
                .WithCrls("inhibitPolicyMapping1 P12subsubCA CRL", "inhibitPolicyMapping1 P12 subCACRL",
                    "inhibitPolicyMapping1 P12 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P12 subsubCA Cert", "inhibitPolicyMapping1 P12 subCA Cert",
                    "inhibitPolicyMapping1 P12 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.4 Valid inhibitPolicyMapping Test4</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
        /// includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
        /// intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-testpolicy-1 to
        /// NIST-test-policy-3 and NIST-test-policy-2 to NIST-test-policy-4. The third intermediate certificate asserts
        /// NIST-test-policy-3 and NIST-test-policy-4 and maps NIST-testpolicy-3 to NIST-test-policy-5.
        /// The end entity certificate asserts NIST-test-policy-4.
        /// </remarks>
        [Test]
        public void Test4_11_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid inhibitPolicyMapping Test4 EE")
                .WithCrls("inhibitPolicyMapping1 P12subsubCA CRL", "inhibitPolicyMapping1 P12 subCACRL",
                    "inhibitPolicyMapping1 P12 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P12 subsubCA Cert", "inhibitPolicyMapping1 P12 subCA Cert",
                    "inhibitPolicyMapping1 P12 CA Cert")
                .DoTest();
        }

        /// <summary>4.11.5 Invalid inhibitPolicyMapping Test5</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 5. The second intermediate
        /// certificate asserts NIST-test-policy-1 and includes a policyConstraints extension with
        /// inhibitPolicyMapping set to 1. The third intermediate certificate asserts NIST-test-policy-1. The
        /// fourth intermediate certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2.
        /// The end entity certificate asserts NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_11_5()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitPolicyMapping Test5 EE")
                .WithCrls("inhibitPolicyMapping5subsubsubCA CRL", "inhibitPolicyMapping5 subsubCA CRL",
                    "inhibitPolicyMapping5 subCA CRL", "inhibitPolicyMapping5 CA CRL")
                .WithCerts("inhibitPolicyMapping5 subsubsubCA Cert", "inhibitPolicyMapping5 subsubCA Cert",
                    "inhibitPolicyMapping5 subCA Cert", "inhibitPolicyMapping5 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.6 Invalid inhibitPolicyMapping Test6</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
        /// includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
        /// intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 5. The third intermediate
        /// certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-test-policy-1 to
        /// NIST-test-policy-3. The end entity certificate asserts NIST-test-policy-3.
        /// </remarks>
        [Test]
        public void Test4_11_6()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitPolicyMapping Test6 EE")
                .WithCrls("inhibitPolicyMapping1 P12subsubCAIPM5 CRL", "inhibitPolicyMapping1 P12subCAIPM5 CRL",
                    "inhibitPolicyMapping1 P12 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P12 subsubCAIPM5 Cert", "inhibitPolicyMapping1 P12 subCAIPM5 Cert",
                    "inhibitPolicyMapping1 P12 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.7 Valid Self-Issued inhibitPolicyMapping Test7</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
        /// certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
        /// certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The end
        /// entity certificate asserts NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_11_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid SelfIssued inhibitPolicyMapping Test7 EE")
                .WithCrls("inhibitPolicyMapping1 P1 subCA CRL", "inhibitPolicyMapping1 P1 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P1 subCA Cert", "inhibitPolicyMapping1 P1 SelfIssued CA Cert",
                    "inhibitPolicyMapping1 P1 CA Cert")
                .DoTest();
        }

        /// <summary>4.11.8 Invalid Self-Issued inhibitPolicyMapping Test8</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
        /// certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
        /// certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
        /// fourth intermediate certificate asserts NIST-test-policy-2 and maps NIST-test-policy-2 to NIST-test-policy-3.
        /// The end entity certificate asserts NIST-test-policy-3.
        /// </remarks>
        [Test]
        public void Test4_11_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued inhibitPolicyMapping Test8 EE")
                .WithCrls("inhibitPolicyMapping1 P1 subsubCACRL", "inhibitPolicyMapping1 P1 subCA CRL",
                    "inhibitPolicyMapping1 P1 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P1 subsubCA Cert", "inhibitPolicyMapping1 P1 subCA Cert",
                    "inhibitPolicyMapping1 P1 SelfIssued CA Cert", "inhibitPolicyMapping1 P1 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.9 Invalid Self-Issued inhibitPolicyMapping Test9</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
        /// certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
        /// certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
        /// fourth intermediate certificate asserts NIST-test-policy-2 and maps NIST-test-policy-2 to NIST-test-policy-3.
        /// The end entity certificate asserts NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_11_9()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued inhibitPolicyMapping Test9 EE")
                .WithCrls("inhibitPolicyMapping1 P1 subsubCACRL", "inhibitPolicyMapping1 P1 subCA CRL",
                    "inhibitPolicyMapping1 P1 CA CRL")
                .WithCerts("inhibitPolicyMapping1 P1 subsubCA Cert", "inhibitPolicyMapping1 P1 subCA Cert",
                    "inhibitPolicyMapping1 P1 SelfIssued CA Cert", "inhibitPolicyMapping1 P1 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.10 Invalid Self-Issued inhibitPolicyMapping Test10</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
        /// certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
        /// certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
        /// fourth intermediate certificate is a self-issued certificate that asserts NIST-test-policy-2 and maps
        /// NIST-test-policy-2 to NIST-test-policy-3. The end entity certificate asserts NIST-test-policy-3.
        /// </remarks>
        [Test]
        public void Test4_11_10()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued inhibitPolicyMapping Test10 EE")
                .WithCerts("inhibitPolicyMapping1 P1 SelfIssued subCA Cert", "inhibitPolicyMapping1 P1 subCA Cert",
                    "inhibitPolicyMapping1 P1 SelfIssued CA Cert", "inhibitPolicyMapping1 P1 CA Cert")
                .WithCrls("inhibitPolicyMapping1 P1 subCA CRL", "inhibitPolicyMapping1 P1 CA CRL")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.11.11 Invalid Self-Issued inhibitPolicyMapping Test11</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
        /// policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
        /// certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
        /// certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
        /// fourth intermediate certificate is a self-issued certificate that asserts NIST-test-policy-2 and maps
        /// NIST-test-policy-2 to NIST-test-policy-3. The end entity certificate asserts NIST-test-policy-2.
        /// </remarks>
        [Test]
        public void Test4_11_11()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued inhibitPolicyMapping Test11 EE")
                .WithCerts("inhibitPolicyMapping1 P1 SelfIssued subCA Cert", "inhibitPolicyMapping1 P1 subCA Cert",
                    "inhibitPolicyMapping1 P1 SelfIssued CA Cert", "inhibitPolicyMapping1 P1 CA Cert")
                .WithCrls("inhibitPolicyMapping1 P1 subCA CRL", "inhibitPolicyMapping1 P1 CA CRL")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.1 Invalid inhibitAnyPolicy Test1</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 0. The end entity certificate asserts anyPolicy.
        /// </remarks>
        [Test]
        public void Test4_12_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitAnyPolicy Test1 EE")
                .WithCrls("inhibitAnyPolicy0 CA CRL")
                .WithCerts("inhibitAnyPolicy0 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.2 Valid inhibitAnyPolicy Test2</summary>
        /// <remarks>
        /// In this test, the intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 0. The end entity certificate asserts anyPolicy and NIST-testpolicy-1.
        /// </remarks>
        [Test]
        public void Test4_12_2()
        {
            new PkitsTest()
                .WithEndEntity("Valid inhibitAnyPolicy Test2 EE")
                .WithCrls("inhibitAnyPolicy0 CA CRL")
                .WithCerts("inhibitAnyPolicy0 CA Cert")
                .DoTest();
        }

        /// <summary>4.12.3 inhibitAnyPolicy Test3</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate asserts anyPolicy. The
        /// end entity certificate asserts NIST-test-policy-1. If possible, it is recommended that the
        /// certification path in this test be validated using the following inputs:
        /// 1. default settings. The path should validate successfully.
        /// 2. default settings, but with initial-inhibit-any-policy set. The path should not
        /// validate successfully.
        /// </remarks>
        [Test]
        public void Test4_12_3()
        {
            new PkitsTest()
                .WithEndEntity("inhibitAnyPolicy Test3 EE")
                .WithCrls("inhibitAnyPolicy1 subCA1 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subCA1 Cert", "inhibitAnyPolicy1 CA Cert")
                .DoTest();

            new PkitsTest()
                .WithEndEntity("inhibitAnyPolicy Test3 EE")
                .WithCrls("inhibitAnyPolicy1 subCA1 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subCA1 Cert", "inhibitAnyPolicy1 CA Cert")
                .WithInhibitAnyPolicy(true)
                .DoExceptionTest(1, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.4 Invalid inhibitAnyPolicy Test4</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate asserts anyPolicy. The
        /// end entity certificate asserts anyPolicy.
        /// </remarks>
        [Test]
        public void Test4_12_4()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitAnyPolicy Test4 EE")
                .WithCrls("inhibitAnyPolicy1 subCA1 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subCA1 Cert", "inhibitAnyPolicy1 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.5 Invalid inhibitAnyPolicy Test5</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 5. The second intermediate certificate asserts NIST-test-policy1 and
        /// includes an inhibitAnyPolicy extension set to 1. The third intermediate certificate asserts
        /// NIST-test-policy-1 and the end entity certificate asserts anyPolicy.
        /// </remarks>
        [Test]
        public void Test4_12_5()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitAnyPolicy Test5 EE")
                .WithCrls("inhibitAnyPolicy5 subsubCA CRL", "inhibitAnyPolicy5 subCA CRL", "inhibitAnyPolicy5 CA CRL")
                .WithCerts("inhibitAnyPolicy5 subsubCA Cert", "inhibitAnyPolicy5 subCA Cert",
                    "inhibitAnyPolicy5 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.6 Invalid inhibitAnyPolicy Test6</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate asserts NIST-test-policy1 and
        /// includes an inhibitAnyPolicy extension set to 5. The end entity certificate asserts anyPolicy.
        /// </remarks>
        [Test]
        public void Test4_12_6()
        {
            new PkitsTest()
                .WithEndEntity("Invalid inhibitAnyPolicy Test6 EE")
                .WithCrls("inhibitAnyPolicy1 subCAIAP5 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subCAIAP5 Cert", "inhibitAnyPolicy1 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.7 Valid Self-Issued inhibitAnyPolicy Test7</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
        /// that asserts NIST-test-policy-1. The third intermediate certificate asserts anyPolicy and the end
        /// entity certificate asserts NIST-test-policy-1.
        /// </remarks>
        [Test]
        public void Test4_12_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid SelfIssued inhibitAnyPolicy Test7 EE")
                .WithCrls("inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subCA2 Cert", "inhibitAnyPolicy1 SelfIssued CA Cert",
                    "inhibitAnyPolicy1 CA Cert")
                .DoTest();
        }

        /// <summary>4.12.8 Invalid Self-Issued inhibitAnyPolicy Test8</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
        /// that asserts NIST-test-policy-1. The third and fourth intermediate certificates assert anyPolicy
        /// and the end entity certificate asserts NIST-test-policy-1.
        /// </remarks>
        [Test]
        public void Test4_12_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued inhibitAnyPolicy Test8 EE")
                .WithCrls("inhibitAnyPolicy1 subsubCA2 CRL", "inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subsubCA2 Cert", "inhibitAnyPolicy1 subCA2 Cert",
                    "inhibitAnyPolicy1 SelfIssued CA Cert", "inhibitAnyPolicy1 CA Cert")
                .DoExceptionTest(1, "No valid policy tree found when one expected.");
        }

        /// <summary>4.12.9 Valid Self-Issued inhibitAnyPolicy Test9</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
        /// that asserts NIST-test-policy-1. The third intermediate certificate asserts anyPolicy. The fourth
        /// intermediate certificate is a self-issued certificate that asserts anyPolicy. The end entity certificate
        /// asserts NIST-test-policy-1.
        /// </remarks>
        [Test]
        public void Test4_12_9()
        {
            new PkitsTest()
                .WithPoliciesByName("NIST-test-policy-1")
                .WithEndEntity("Valid SelfIssued inhibitAnyPolicy Test9 EE")
                .WithCerts("inhibitAnyPolicy1 SelfIssued subCA2 Cert", "inhibitAnyPolicy1 subCA2 Cert",
                    "inhibitAnyPolicy1 SelfIssued CA Cert", "inhibitAnyPolicy1 CA Cert")
                .WithCrls("inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL")
                .DoTest();
        }

        /// <summary>4.12.10 Invalid Self-Issued inhibitAnyPolicy Test10</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
        /// inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
        /// that asserts NIST-test-policy-1. The third intermediate certificate asserts anyPolicy. The end
        /// entity certificate is a self-issued CA certificate that asserts anyPolicy.
        /// </remarks>
        [Test]
        public void Test4_12_10()
        {
            new PkitsTest()
                .WithEndEntity("Invalid SelfIssued inhibitAnyPolicy Test10 EE")
                .WithCrls("inhibitAnyPolicy1 subCA2 CRL", "inhibitAnyPolicy1 CA CRL")
                .WithCerts("inhibitAnyPolicy1 subCA2 Cert", "inhibitAnyPolicy1 SelfIssued CA Cert",
                    "inhibitAnyPolicy1 CA Cert")
                .DoExceptionTest(0, "No valid policy tree found when one expected.");
        }

        /// <summary>4.13.1 Valid DN nameConstraints Test1</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subject name that falls within that
        /// subtree.
        /// </remarks>
        [Test]
        public void Test4_13_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test1 EE")
                .WithCrls("nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.2 Invalid DN nameConstraints Test2</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subject name that falls outside that
        /// subtree.
        /// </remarks>
        [Test]
        public void Test4_13_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test2 EE")
                .WithCrls("nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.3 Invalid DN nameConstraints Test3</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subject name that falls within that
        /// subtree and a subjectAltName extension with a DN that falls outside the subtree.
        /// </remarks>
        [Test]
        public void Test4_13_3()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test3 EE")
                .WithCrls("nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.4 Valid DN nameConstraints Test4</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subject name that falls within that
        /// subtree and a subjectAltName extension with an e-mail address.
        /// </remarks>
        [Test]
        public void Test4_13_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test4 EE")
                .WithCrls("nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.5 Valid DN nameConstraints Test5</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies two
        /// permitted subtrees. The end entity certificate includes a subject name that falls within one of the
        /// subtrees and a subjectAltName extension with a DN that falls within the other subtree.
        /// </remarks>
        [Test]
        public void Test4_13_5()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test5 EE")
                .WithCrls("nameConstraints DN2 CA CRL")
                .WithCerts("nameConstraints DN2 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.6 Valid DN nameConstraints Test6</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subject name that falls outside that
        /// subtree.
        /// </remarks>
        [Test]
        public void Test4_13_6()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test6 EE")
                .WithCrls("nameConstraints DN3 CA CRL")
                .WithCerts("nameConstraints DN3 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.7 Invalid DN nameConstraints Test7</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subject name that falls within that
        /// subtree.
        /// </remarks>
        [Test]
        public void Test4_13_7()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test7 EE")
                .WithCrls("nameConstraints DN3 CA CRL")
                .WithCerts("nameConstraints DN3 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.8 Invalid DN nameConstraints Test8</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies two
        /// excluded subtrees. The end entity certificate includes a subject name that falls within the first
        /// subtree.
        /// </remarks>
        [Test]
        public void Test4_13_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test8 EE")
                .WithCrls("nameConstraints DN4 CA CRL")
                .WithCerts("nameConstraints DN4 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.9 Invalid DN nameConstraints Test9</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies two
        /// excluded subtrees. The end entity certificate includes a subject name that falls within the second
        /// subtree.
        /// </remarks>
        [Test]
        public void Test4_13_9()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test9 EE")
                .WithCrls("nameConstraints DN4 CA CRL")
                .WithCerts("nameConstraints DN4 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.10 Invalid DN nameConstraints Test10</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// permitted subtree and an excluded subtree. The excluded subtree specifies a subset of the name
        /// space specified by the permitted subtree. The end entity certificate includes a subject name that
        /// falls within both the permitted and excluded subtrees.
        /// </remarks>
        [Test]
        public void Test4_13_10()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test10 EE")
                .WithCrls("nameConstraints DN5 CA CRL")
                .WithCerts("nameConstraints DN5 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.11 Valid DN nameConstraints Test11</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// permitted subtree and an excluded subtree. The excluded subtree specifies a subset of the name
        /// space specified by the permitted subtree. The end entity certificate includes a subject name that
        /// falls within the permitted subtree but falls outside the excluded subtree.
        /// </remarks>
        [Test]
        public void Test4_13_11()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test11 EE")
                .WithCrls("nameConstraints DN5 CA CRL")
                .WithCerts("nameConstraints DN5 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.12 Invalid DN nameConstraints Test12</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The second intermediate certificate includes a subject name that falls
        /// within that subtree and a nameConstraints extension that specifies a permitted subtree that is a
        /// subtree of the constraint specified in the first intermediate certificate. The end entity certificate
        /// includes a subject name that falls within the subtree specified by the first intermediate certificate
        /// but outside the subtree specified by the second intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_13_12()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test12 EE")
                .WithCrls("nameConstraints DN1 subCA1 CRL", "nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 subCA1 Cert", "nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.13 Invalid DN nameConstraints Test13</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The second intermediate certificate includes a subject name that falls
        /// within that subtree and a nameConstraints extension that specifies a permitted subtree that does
        /// not overlap with the permitted subtree specified in the first intermediate certificate. The end entity
        /// certificate includes a subject name that falls within the subtree specified by the first intermediate
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_13_13()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test13 EE")
                .WithCrls("nameConstraints DN1 subCA2 CRL", "nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 subCA2 Cert", "nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.14 Valid DN nameConstraints Test14</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The second intermediate certificate includes a subject name that falls
        /// within that subtree and a nameConstraints extension that specifies a permitted subtree that does
        /// not overlap with the permitted subtree specified in the first intermediate certificate. The end entity
        /// certificate has a null subject name (i.e., the subject name is a sequence of zero relative
        /// distinguished names) and a critical subjectAltName extension with an e-mail address.
        /// </remarks>
        [Test]
        public void Test4_13_14()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test14 EE")
                .WithCrls("nameConstraints DN1 subCA2 CRL", "nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 subCA2 Cert", "nameConstraints DN1 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.15 Invalid DN nameConstraints Test15</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The second intermediate certificate has a subject name that falls outside
        /// that subtree and includes a nameConstraints extension that specifies an excluded subtree that
        /// does not overlap with the subtree specified in the first intermediate certificate. The end entity
        /// certificate includes a subject name that falls within the subtree specified in the first intermediate
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_13_15()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test15 EE")
                .WithCrls("nameConstraints DN3 subCA1 CRL", "nameConstraints DN3 CA CRL")
                .WithCerts("nameConstraints DN3 subCA1 Cert", "nameConstraints DN3 CA Cert")
                .DoExceptionTest(00, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.16 Invalid DN nameConstraints Test16</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The second intermediate certificate has a subject name that falls outside
        /// that subtree and includes a nameConstraints extension that specifies an excluded subtree that
        /// does not overlap with the subtree specified in the first intermediate certificate. The end entity
        /// certificate includes a subject name that falls within the subtree specified in the second intermediate
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_13_16()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test16 EE")
                .WithCrls("nameConstraints DN3 subCA1 CRL", "nameConstraints DN3 CA CRL")
                .WithCerts("nameConstraints DN3 subCA1 Cert", "nameConstraints DN3 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.17 Invalid DN nameConstraints Test17</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The second intermediate certificate has a subject name that falls outside
        /// that subtree and includes a nameConstraints extension that specifies a permitted subtree that is a
        /// superset of the subtree specified in the first intermediate certificate. The end entity certificate
        /// includes a subject name that falls within the excluded subtree specified in the first intermediate
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_13_17()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test17 EE")
                .WithCrls("nameConstraints DN3 subCA2 CRL", "nameConstraints DN3 CA CRL")
                .WithCerts("nameConstraints DN3 subCA2 Cert", "nameConstraints DN3 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.18 Valid DN nameConstraints Test18</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The second intermediate certificate has a subject name that falls outside
        /// that subtree and includes a nameConstraints extension that specifies a permitted subtree that is a
        /// superset of the subtree specified in the first intermediate certificate. The end entity certificate
        /// includes a subject name that falls within the permitted subtree specified in the second intermediate
        /// certificate but outside the excluded subtree specified in the first intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_13_18()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test18 EE")
                .WithCrls("nameConstraints DN3 subCA2 CRL", "nameConstraints DN3 CA CRL")
                .WithCerts("nameConstraints DN3 subCA2 Cert", "nameConstraints DN3 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.19 Valid Self-Issued DN nameConstraints Test19</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The second intermediate certificate is a self-issued certificate. The
        /// subject name in the self-issued certificate does not fall within the permitted subtree specified in the
        /// first intermediate certificate. The end entity certificate includes a subject name that falls within the
        /// permitted subtree specified in the first intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_13_19()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN nameConstraints Test19 EE")
                .WithCerts("nameConstraints DN1 SelfIssued CA Cert", "nameConstraints DN1 CA Cert")
                .WithCrls("nameConstraints DN1 CA CRL")
                .DoTest();
        }

        /// <summary>4.13.20 Invalid Self-Issued DN nameConstraints Test20</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate is a self-issued certificate. The subject name in
        /// the self-issued certificate does not fall within the permitted subtree specified in the intermediate
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_13_20()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN nameConstraints Test20 EE")
                .WithCrls("nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject failed.");
        }

        /// <summary>4.13.21 Valid RFC822 nameConstraints Test21</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with an
        /// e-mail address that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_21()
        {
            new PkitsTest()
                .WithEndEntity("Valid RFC822 nameConstraints Test21 EE")
                .WithCrls("nameConstraints RFC822 CA1 CRL")
                .WithCerts("nameConstraints RFC822 CA1 Cert")
                .DoTest();
        }

        /// <summary>4.13.22 Invalid RFC822 nameConstraints Test22</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with an
        /// e-mail address that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_22()
        {
            new PkitsTest()
                .WithEndEntity("Invalid RFC822 nameConstraints Test22 EE")
                .WithCrls("nameConstraints RFC822 CA1 CRL")
                .WithCerts("nameConstraints RFC822 CA1 Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.23 Valid RFC822 nameConstraints Test23</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with an
        /// e-mail address that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_23()
        {
            new PkitsTest()
                .WithEndEntity("Valid RFC822 nameConstraints Test23 EE")
                .WithCrls("nameConstraints RFC822 CA2 CRL")
                .WithCerts("nameConstraints RFC822 CA2 Cert")
                .DoTest();
        }

        /// <summary>4.13.24 Invalid RFC822 nameConstraints Test24</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with an
        /// e-mail address that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_24()
        {
            new PkitsTest()
                .WithEndEntity("Invalid RFC822 nameConstraints Test24 EE")
                .WithCrls("nameConstraints RFC822 CA2 CRL")
                .WithCerts("nameConstraints RFC822 CA2 Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.25 Valid RFC822 nameConstraints Test25</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subjectAltName extension with an
        /// e-mail address that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_25()
        {
            new PkitsTest()
                .WithEndEntity("Valid RFC822 nameConstraints Test25 EE")
                .WithCrls("nameConstraints RFC822 CA3 CRL")
                .WithCerts("nameConstraints RFC822 CA3 Cert")
                .DoTest();
        }

        /// <summary>4.13.26 Invalid RFC822 nameConstraints Test26</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subjectAltName extension with an
        /// e-mail address that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_26()
        {
            new PkitsTest()
                .WithEndEntity("Invalid RFC822 nameConstraints Test26 EE")
                .WithCrls("nameConstraints RFC822 CA3 CRL")
                .WithCerts("nameConstraints RFC822 CA3 Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.27 Valid DN and RFC822 nameConstraints Test27</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree of type directoryName. The second intermediate certificate includes a
        /// subject name that falls within that subtree and a nameConstraints extension that specifies a
        /// permitted subtree of type rfc822Name. The end entity certificate includes a subject name that falls
        /// within the subtree specified by the first intermediate certificate and an e-mail address that falls
        /// within the permitted subtree specified by the second intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_13_27()
        {
            new PkitsTest()
                .WithEndEntity("Valid DN and RFC822 nameConstraints Test27 EE")
                .WithCrls("nameConstraints DN1 subCA3 CRL", "nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 subCA3 Cert", "nameConstraints DN1 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.28 Invalid DN and RFC822 nameConstraints Test28</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree of type directoryName. The second intermediate certificate includes a
        /// subject name that falls within that subtree and a nameConstraints extension that specifies a
        /// permitted subtree of type rfc822Name. The end entity certificate includes a subject name that falls
        /// within the subtree specified by the first intermediate certificate and an e-mail address that falls
        /// outside the permitted subtree specified by the second intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_13_28()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN and RFC822 nameConstraints Test28 EE")
                .WithCrls("nameConstraints DN1 subCA3 CRL", "nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 subCA3 Cert", "nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.29 Invalid DN and RFC822 nameConstraints Test29</summary>
        /// <remarks>
        /// In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree of type directoryName. The second intermediate certificate includes a
        /// subject name that falls within that subtree and a nameConstraints extension that specifies a
        /// permitted subtree of type rfc822Name. The end entity certificate includes a subject name that falls
        /// within the subtree specified by the first intermediate certificate but the subject name includes an
        /// attribute of type EmailAddress whose value falls outside the permitted subtree specified in the
        /// second intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_13_29()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DN and RFC822 nameConstraints Test29 EE")
                .WithCrls("nameConstraints DN1 subCA3 CRL", "nameConstraints DN1 CA CRL")
                .WithCerts("nameConstraints DN1 subCA3 Cert", "nameConstraints DN1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative email failed.");
        }

        /// <summary>4.13.30 Valid DNS nameConstraints Test30</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with a
        /// dNSName that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_30()
        {
            new PkitsTest()
                .WithEndEntity("Valid DNS nameConstraints Test30 EE")
                .WithCrls("nameConstraints DNS1 CA CRL")
                .WithCerts("nameConstraints DNS1 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.31 Invalid DNS nameConstraints Test31</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with a
        /// dNSName that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_31()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DNS nameConstraints Test31 EE")
                .WithCrls("nameConstraints DNS1 CA CRL")
                .WithCerts("nameConstraints DNS1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.32 Valid DNS nameConstraints Test32</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subjectAltName extension with a
        /// dNSName that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_32()
        {
            new PkitsTest()
                .WithEndEntity("Valid DNS nameConstraints Test32 EE")
                .WithCrls("nameConstraints DNS2 CA CRL")
                .WithCerts("nameConstraints DNS2 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.33 Invalid DNS nameConstraints Test33</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subjectAltName extension with a
        /// dNSName that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_33()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DNS nameConstraints Test33 EE")
                .WithCrls("nameConstraints DNS2 CA CRL")
                .WithCerts("nameConstraints DNS2 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.34 Valid URI nameConstraints Test34</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with a
        /// uniformResourceIdentifier that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_34()
        {
            new PkitsTest()
                .WithEndEntity("Valid URI nameConstraints Test34 EE")
                .WithCrls("nameConstraints URI1 CA CRL")
                .WithCerts("nameConstraints URI1 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.35 Invalid URI nameConstraints Test35</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with a
        /// uniformResourceIdentifier that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_35()
        {
            new PkitsTest()
                .WithEndEntity("Invalid URI nameConstraints Test35 EE")
                .WithCrls("nameConstraints URI1 CA CRL")
                .WithCerts("nameConstraints URI1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.36 Valid URI nameConstraints Test36</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subjectAltName extension with a
        /// uniformResourceIdentifier that falls outside that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_36()
        {
            new PkitsTest()
                .WithEndEntity("Valid URI nameConstraints Test36 EE")
                .WithCrls("nameConstraints URI2 CA CRL")
                .WithCerts("nameConstraints URI2 CA Cert")
                .DoTest();
        }

        /// <summary>4.13.37 Invalid URI nameConstraints Test37</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single excluded subtree. The end entity certificate includes a subjectAltName extension with a
        /// uniformResourceIdentifier that falls within that subtree.
        /// </remarks>
        [Test]
        public void Test4_13_37()
        {
            new PkitsTest()
                .WithEndEntity("Invalid URI nameConstraints Test37 EE")
                .WithCrls("nameConstraints URI2 CA CRL")
                .WithCerts("nameConstraints URI2 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.13.38 Invalid DNS nameConstraints Test38</summary>
        /// <remarks>
        /// In this test, the intermediate certificate includes a nameConstraints extension that specifies a
        /// single permitted subtree. The end entity certificate includes a subjectAltName extension with a
        /// dNSName that falls outside that subtree. The permitted subtree is “testcertificates.gov” and the
        /// subjectAltName is “mytestcertificates.gov”.
        /// </remarks>
        [Test]
        public void Test4_13_38()
        {
            new PkitsTest()
                .WithEndEntity("Invalid DNS nameConstraints Test38 EE")
                .WithCrls("nameConstraints DNS1 CA CRL")
                .WithCerts("nameConstraints DNS1 CA Cert")
                .DoExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
        }

        /// <summary>4.14.1 Valid distributionPoint Test1</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a matching
        /// distributionPoint.
        /// </remarks>
        [Test]
        public void Test4_14_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid distributionPoint Test1 EE")
                .WithCrls("distributionPoint1 CA CRL")
                .WithCerts("distributionPoint1 CA Cert")
                .DoTest();
        }

        /// <summary>4.14.2 Invalid distributionPoint Test2</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a matching
        /// distributionPoint. The CRL lists the end entity certificate as being revoked.
        /// </remarks>
        [Test]
        public void Test4_14_2()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid distributionPoint Test2 EE")
                .WithCrls("distributionPoint1 CA CRL")
                .WithCerts("distributionPoint1 CA Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.3 Invalid distributionPoint Test3</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The only CRL
        /// available from the issuer of the end entity certificate includes an issuingDistributionPoint
        /// extension with a distributionPoint that does not match the distributionPoint specified in the end
        /// entity certificate.
        /// </remarks>
        [Test]
        public void Test4_14_3()
        {
            new PkitsTest()
                .WithEndEntity("Invalid distributionPoint Test3 EE")
                .WithCrls("distributionPoint1 CA CRL")
                .WithCerts("distributionPoint1 CA Cert")
                .DoExceptionTest(0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
        }

        /// <summary>4.14.4 Valid distributionPoint Test4</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a matching
        /// distributionPoint. The distributionPoint in the end entity certificate is specified as a
        /// nameRelativeToCRLIssuer while the distributionPoint in the CRL is specified as a fullName.
        /// </remarks>
        [Test]
        public void Test4_14_4()
        {
            new PkitsTest()
                .WithEndEntity("Valid distributionPoint Test4 EE")
                .WithCrls("distributionPoint1 CA CRL")
                .WithCerts("distributionPoint1 CA Cert")
                .DoTest();
        }

        /// <summary>4.14.5 Valid distributionPoint Test5</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a matching
        /// distributionPoint. The distributionPoint in both the end entity certificate and the CRL are
        /// specified as a nameRelativeToCRLIssuer.
        /// </remarks>
        [Test]
        public void Test4_14_5()
        {
            new PkitsTest()
                .WithEndEntity("Valid distributionPoint Test5 EE")
                .WithCrls("distributionPoint2 CA CRL")
                .WithCerts("distributionPoint2 CA Cert")
                .DoTest();
        }

        /// <summary>4.14.6 Invalid distributionPoint Test6</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a matching
        /// distributionPoint. The distributionPoint in both the end entity certificate and the CRL are
        /// specified as a nameRelativeToCRLIssuer. The CRL lists the end entity certificate as being
        /// revoked.
        /// </remarks>
        [Test]
        public void Test4_14_6()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid distributionPoint Test6 EE")
                .WithCrls("distributionPoint2 CA CRL")
                .WithCerts("distributionPoint2 CA Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.7 Valid distributionPoint Test7</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a matching
        /// distributionPoint. The distributionPoint in the CRL is specified as a
        /// nameRelativeToCRLIssuer and the distributionPoint in the end entity certificate is specified as
        /// a fullName.
        /// </remarks>
        [Test]
        public void Test4_14_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid distributionPoint Test7 EE")
                .WithCrls("distributionPoint2 CA CRL")
                .WithCerts("distributionPoint2 CA Cert")
                .DoTest();
        }

        /// <summary>4.14.8 Invalid distributionPoint Test8</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
        /// DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
        /// covers the end entity certificate includes an issuingDistributionPoint extension with a
        /// distributionPoint that does not match. The distributionPoint in the CRL is specified as a
        /// nameRelativeToCRLIssuer and the distributionPoint in the end entity certificate is specified as
        /// a fullName.
        /// </remarks>
        [Test]
        public void Test4_14_8()
        {
            new PkitsTest()
                .WithEndEntity("Invalid distributionPoint Test8 EE")
                .WithCrls("distributionPoint2 CA CRL")
                .WithCerts("distributionPoint2 CA Cert")
                .DoExceptionTest(0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
        }

        /// <summary>4.14.9 Invalid distributionPoint Test9</summary>
        /// <remarks>
        /// In this test, the CRL that covers the end entity certificate includes an issuingDistributionPoint
        /// extension with a distributionPoint. The distributionPoint does not match the CRL issuer's
        /// name. The end entity certificate does not include a cRLDistributionPoints extension.
        /// </remarks>
        [Test]
        public void Test4_14_9()
        {
            new PkitsTest()
                .WithEndEntity("Invalid distributionPoint Test9 EE")
                .WithCrls("distributionPoint2 CA CRL")
                .WithCerts("distributionPoint2 CA Cert")
                .DoExceptionTest(0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
        }

        /// <summary>4.14.10 Valid No issuingDistributionPoint Test10</summary>
        /// <remarks>
        /// In this test, the CRL that covers the end entity certificate does not include an
        /// issuingDistributionPoint extension. The end entity certificate includes a
        /// cRLDistributionPoints extension with a distributionPoint name.
        /// </remarks>
        [Test]
        public void Test4_14_10()
        {
            new PkitsTest()
                .WithEndEntity("Valid No issuingDistributionPoint Test10 EE")
                .WithCrls("No issuingDistributionPoint CA CRL")
                .WithCerts("No issuingDistributionPoint CA Cert")
                .DoTest();
        }

        /// <summary>4.14.11 Invalid onlyContainsUserCerts CRL Test11</summary>
        /// <remarks>
        /// In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
        /// extension with onlyContainsUserCerts set to TRUE. The final certificate in the path is a CA
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_14_11()
        {
            new PkitsTest()
                .WithEndEntity("Invalid onlyContainsUserCerts Test11 EE")
                .WithCrls("onlyContainsUserCerts CA CRL")
                .WithCerts("onlyContainsUserCerts CA Cert")
                .DoExceptionTest(0, "CA Cert CRL only contains user certificates.");
        }

        /// <summary>4.14.12 Invalid onlyContainsCACerts CRL Test12</summary>
        /// <remarks>
        /// In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
        /// extension with onlyContainsCACerts set to TRUE.
        /// </remarks>
        [Test]
        public void Test4_14_12()
        {
            new PkitsTest()
                .WithEndEntity("Invalid onlyContainsCACerts Test12 EE")
                .WithCrls("onlyContainsCACerts CA CRL")
                .WithCerts("onlyContainsCACerts CA Cert")
                .DoExceptionTest(0, "End CRL only contains CA certificates.");
        }

        /// <summary>4.14.13 Valid onlyContainsCACerts CRL Test13</summary>
        /// <remarks>
        /// In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
        /// extension with onlyContainsCACerts set to TRUE. The final certificate in the path is a CA
        /// certificate.
        /// </remarks>
        [Test]
        public void Test4_14_13()
        {
            new PkitsTest()
                .WithEndEntity("Valid onlyContainsCACerts Test13 EE")
                .WithCrls("onlyContainsCACerts CA CRL")
                .WithCerts("onlyContainsCACerts CA Cert")
                .DoTest();
        }

        /// <summary>4.14.14 Invalid onlyContainsAttributeCerts Test14</summary>
        /// <remarks>
        /// In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
        /// extension with onlyContainsAttributeCerts set to TRUE.
        /// </remarks>
        [Test]
        public void Test4_14_14()
        {
            new PkitsTest()
                .WithEndEntity("Invalid onlyContainsAttributeCerts Test14 EE")
                .WithCrls("onlyContainsAttributeCerts CA CRL")
                .WithCerts("onlyContainsAttributeCerts CA Cert")
                .DoExceptionTest(0, "onlyContainsAttributeCerts boolean is asserted.");
        }

        /// <summary>4.14.15 Invalid onlySomeReasons Test15</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
        /// and cACompromise reason codes and the other covering the remaining reason codes. The end
        /// entity certificate has been revoked for key compromise.
        /// </remarks>
        [Test]
        public void Test4_14_15()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid onlySomeReasons Test15 EE")
                .WithCrls("onlySomeReasons CA1 other reasons CRL", "onlySomeReasons CA1 compromise CRL")
                .WithCerts("onlySomeReasons CA1 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.16 Invalid onlySomeReasons Test16</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
        /// and cACompromise reason codes and the other covering the remaining reason codes. The end
        /// entity certificate has been placed on hold.
        /// </remarks>
        [Test]
        public void Test4_14_16()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid onlySomeReasons Test16 EE")
                .WithCrls("onlySomeReasons CA1 other reasons CRL", "onlySomeReasons CA1 compromise CRL")
                .WithCerts("onlySomeReasons CA1 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: certificateHold");
        }

        /// <summary>4.14.17 Invalid onlySomeReasons Test17</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the affiliationChanged
        /// and superseded reason codes and the other covering the cessationOfOperation and
        /// certificateHold reason codes. The end entity certificate is not listed on either CRL.
        /// </remarks>
        [Test]
        public void Test4_14_17()
        {
            new PkitsTest()
                .WithEndEntity("Invalid onlySomeReasons Test17 EE")
                .WithCrls("onlySomeReasonsCA2 CRL2", "onlySomeReasons CA2 CRL1")
                .WithCerts("onlySomeReasons CA2 Cert")
                .DoExceptionTest(0, "Certificate status could not be determined.");
        }

        /// <summary>4.14.18 Valid onlySomeReasons Test18</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
        /// and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
        /// include an issuingDistributionPoint extension with the same distributionPoint name. The end
        /// entity certificate includes a cRLDistributionPoints extension with the same distributionPoint
        /// name.
        /// </remarks>
        [Test]
        public void Test4_14_18()
        {
            new PkitsTest()
                .WithEndEntity("Valid onlySomeReasons Test18 EE")
                .WithCrls("onlySomeReasons CA3 other reasons CRL", "onlySomeReasons CA3 compromise CRL")
                .WithCerts("onlySomeReasons CA3 Cert")
                .DoTest();
        }

        /// <summary>4.14.19 Valid onlySomeReasons Test19</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
        /// and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
        /// include an issuingDistributionPoint extension with a different distributionPoint name. The end
        /// entity certificate includes a cRLDistributionPoints extension with two DistributionPoints, one
        /// for each CRL.
        /// </remarks>
        [Test]
        public void Test4_14_19()
        {
            new PkitsTest()
                .WithEndEntity("Valid onlySomeReasons Test19 EE")
                .WithCrls("onlySomeReasons CA4 other reasons CRL", "onlySomeReasons CA4 compromise CRL")
                .WithCerts("onlySomeReasons CA4 Cert")
                .DoTest();
        }

        /// <summary>4.14.20 Invalid onlySomeReasons Test20</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
        /// and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
        /// include an issuingDistributionPoint extension with a different distributionPoint name. The end
        /// entity certificate includes a cRLDistributionPoints extension with two DistributionPoints, one
        /// for each CRL. The end entity certificate has been revoked for key compromise.
        /// </remarks>
        [Test]
        public void Test4_14_20()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid onlySomeReasons Test20 EE")
                .WithCrls("onlySomeReasons CA4 other reasons CRL", "onlySomeReasons CA4 compromise CRL")
                .WithCerts("onlySomeReasons CA4 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.21 Invalid onlySomeReasons Test21</summary>
        /// <remarks>
        /// In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
        /// and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
        /// include an issuingDistributionPoint extension with a different distributionPoint name. The end
        /// entity certificate includes a cRLDistributionPoints extension with two DistributionPoints, one
        /// for each CRL. The end entity certificate has been revoked as a result of a change in affiliation.
        /// </remarks>
        [Test]
        public void Test4_14_21()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid onlySomeReasons Test21 EE")
                .WithCrls("onlySomeReasons CA4 other reasons CRL", "onlySomeReasons CA4 compromise CRL")
                .WithCerts("onlySomeReasons CA4 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: affiliationChanged");
        }

        /// <summary>4.14.22 Valid IDP with indirectCRL Test22</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a CRL that contains an issuingDistributionPoint
        /// extension with the indirectCRL flag set. The end entity certificate was issued by the intermediate
        /// CA.
        /// </remarks>
        [Test]
        public void Test4_14_22()
        {
            new PkitsTest()
                .WithEndEntity("Valid IDP with indirectCRL Test22 EE")
                .WithCrls("indirectCRL CA1 CRL")
                .WithCerts("indirectCRL CA1 Cert")
                .DoTest();
        }

        /// <summary>4.14.23 Invalid IDP with indirectCRL Test23</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a CRL that contains an issuingDistributionPoint
        /// extension with the indirectCRL flag set. The end entity certificate was issued by the intermediate
        /// CA and is listed as revoked on the CRL.
        /// </remarks>
        [Test]
        public void Test4_14_23()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid IDP with indirectCRL Test23 EE")
                .WithCrls("indirectCRL CA1 CRL")
                .WithCerts("indirectCRL CA1 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.24 Valid IDP with indirectCRL Test24</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The public key needed to validate the indirect CRL is in a certificate issued by the Trust Anchor.
        /// </remarks>
        [Test, Ignore("CHECK")]
        public void Test4_14_24()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid IDP with indirectCRL Test24 EE")
                .WithCrls("indirectCRL CA1 CRL")
                .WithCerts("indirectCRL CA1 Cert", "indirectCRL CA2 Cert")
                .DoTest();
        }

        /// <summary>4.14.25 Valid IDP with indirectCRL Test25</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The public key needed to validate the indirect CRL is in a certificate issued by the Trust Anchor.
        /// The end entity's serial number is listed on the CRL, but there is no certificateIssuer CRL entry
        /// extension, indicating that the revoked certificate was one issued by the CRL issuer.
        /// </remarks>
        [Test, Ignore("CHECK")]
        public void Test4_14_25()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid IDP with indirectCRL Test25 EE")
                .WithCrls("indirectCRL CA1 CRL")
                .WithCerts("indirectCRL CA1 Cert", "indirectCRL CA2 Cert")
                .DoTest();
        }

        /// <summary>4.14.26 Invalid IDP with indirectCRL Test26</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The entity specified in the cRLIssuer field does not exist.
        /// </remarks>
        [Test, Ignore("CHECK not forming path, \"Trust anchor for certification path not found.\"")]
        public void Test4_14_26()
        {
            // TODO[pkix] Resolve Ignore. Expected it to be failing because the end entity has been revoked.
            new PkitsTest()
                .WithEndEntity("Invalid IDP with indirectCRL Test26 EE")
                .WithCrls("indirectCRL CA1 CRL")
                .WithCerts("indirectCRL CA1 Cert", "indirectCRL CA2 Cert")
                .DoExceptionTest(-1, "--");
        }

        /// <summary>4.14.27 Invalid cRLIssuer Test27</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The CRL issued by the entity specified in the cRLIssuer field does not include an
        /// issuingDistributionPoint extension.
        /// </remarks>
        [Test, Ignore("CHECK not forming path, \"Trust anchor for certification path not found.\"")]
        public void Test4_14_27()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Invalid cRLIssuer Test27 EE")
                .WithCrls("Good CA CRL")
                .WithCerts("Good CA Cert", "indirectCRL CA2 Cert")
                .DoExceptionTest(-1, "--");
        }

        /// <summary>4.14.28 Valid cRLIssuer Test28</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The indirect CRL issuer has been issued a certificate by the issuer of the end entity certificate. The
        /// certificate issued to the CRL issuer is covered by a CRL issued by the issuer of the end entity
        /// certificate.
        /// </remarks>
        [Test, Ignore("CHECK")]
        public void Test4_14_28()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid cRLIssuer Test28 EE")
                .WithCrls("indirectCRL CA3 cRLIssuer CRL", "indirectCRL CA3 CRL")
                .WithCerts("indirectCRL CA3 cRLIssuer Cert", "indirectCRL CA3 Cert")
                .DoTest();
        }

        /// <summary>4.14.29 Valid cRLIssuer Test29</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The distributionPoint in the end entity certificate is specified as nameRelativeToCRLIssuer.
        /// The indirect CRL issuer has been issued a certificate by the issuer of the end entity certificate. The
        /// certificate issued to the CRL issuer is covered by a CRL issued by the issuer of the end entity
        /// certificate.
        /// </remarks>
        [Test, Ignore("CHECK")]
        public void Test4_14_29()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid cRLIssuer Test29 EE")
                .WithCrls("indirectCRL CA3 cRLIssuer CRL", "indirectCRL CA3 CRL")
                .WithCerts("indirectCRL CA3 cRLIssuer Cert", "indirectCRL CA3 Cert")
                .DoTest();
        }

        /// <summary>4.14.30 Valid cRLIssuer Test30</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The indirect CRL issuer has been issued a certificate by the issuer of the end entity certificate.
        /// Both the end entity certificate and the certificate issued to the CRL issuer are covered by the
        /// indirect CRL issued by the CRL issuer.
        /// </remarks>
        [Test, Ignore("CHECK")]
        public void Test4_14_30()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid cRLIssuer Test30 EE")
                .WithCrls("indirectCRL CA4 cRLIssuer CRL")
                .WithCerts("indirectCRL CA4 cRLIssuer Cert", "indirectCRL CA4 Cert")
                .DoTest();
        }

        /// <summary>4.14.31 Invalid cRLIssuer Test31</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The indirect CRL contains a CRL entry listing the end entity certificate's serial number that
        /// includes a certificateIssuer extension specifying the end entity certificate's issuer.
        /// </remarks>
        [Test, Ignore("CHECK not forming path, \"Trust anchor for certification path not found.\"")]
        public void Test4_14_31()
        {
            // TODO[pkix] Resolve Ignore. Expected it to be failing because the end entity has been revoked.
            new PkitsTest()
                .WithEndEntity("Invalid cRLIssuer Test31 EE")
                .WithCerts("indirectCRL CA6 Cert", "indirectCRL CA5 Cert")
                .WithCrls("indirectCRL CA5 CRL")
                .DoExceptionTest(-1, "--");
        }

        /// <summary>4.14.32 Invalid cRLIssuer Test32</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The indirect CRL contains a CRL entry listing the end entity certificate's serial number and the
        /// preceding CRL entry includes a certificateIssuer extension specifying the end entity certificate's
        /// issuer.
        /// </remarks>
        [Test, Ignore("CHECK not forming path, \"Trust anchor for certification path not found.\"")]
        public void Test4_14_32()
        {
            // TODO[pkix] Resolve Ignore. Expected it to be failing because the end entity has been revoked.
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid cRLIssuer Test32 EE")
                .WithCerts("indirectCRL CA6 Cert", "indirectCRL CA5 Cert")
                .WithCrls("indirectCRL CA5 CRL")
                .DoExceptionTest(-1, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.33 Valid cRLIssuer Test33</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with a
        /// cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
        /// The indirect CRL contains a CRL entry listing the end entity certificate's serial number, but the
        /// most recent CRL entry to include a certificateIssuer extension specified a different certificate
        /// issuer.
        /// </remarks>
        [Test, Ignore("CHECK")]
        public void Test4_14_33()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Valid cRLIssuer Test33 EE")
                .WithCerts("indirectCRL CA6 Cert", "indirectCRL CA5 Cert")
                .WithCrls("indirectCRL CA5 CRL")
                .DoTest();
        }

        /// <summary>4.14.34 Invalid cRLIssuer Test34</summary>
        /// <remarks>
        /// In this test, the end entity certificate is issued by the same CA that issues the corresponding CRL,
        /// but the CRL is also an indirect CRL for other CAs. The end entity certificate's serial number is
        /// listed on the CRL and the most recent CRL entry to include a certificateIssuer extension specifies
        /// the end entity certificate's issuer.
        /// </remarks>
        [Test]
        public void Test4_14_34()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid cRLIssuer Test34 EE")
                .WithCrls("indirectCRL CA5 CRL")
                .WithCerts("indirectCRL CA5 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.14.35 Invalid cRLIssuer Test35</summary>
        /// <remarks>
        /// In this test, the end entity certificate includes a cRLDistributionPoints extension with both a
        /// distributionPoint name and a cRLIssuer field indicating that the CRL is issued by an entity other
        /// than the certificate issuer. There is no CRL available from the entity specified in cRLIssuer, but
        /// the certificate issuer has issued a CRL with an issuingDistributionPoint extension that includes a
        /// distributionPoint that matches the distributionPoint in the certificate.
        /// </remarks>
        [Test, Ignore("Seems like there are multiple exceptions, and we end up with the wrong one")]
        public void Test4_14_35()
        {
            // TODO[pkix] Resolve Ignore
            new PkitsTest()
                .WithEndEntity("Invalid cRLIssuer Test35 EE")
                .WithCrls("indirectCRL CA5 CRL")
                .WithCerts("indirectCRL CA5 Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"ou=indirectCRL CA5,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.15.1 Invalid deltaCRLIndicator No Base Test1</summary>
        /// <remarks>
        /// In this test, the CRL covering the end entity certificate includes a deltaCRLIndicator extension,
        /// but no other CRLs are available for the intermediate certificate.
        /// </remarks>
        [Test]
        public void Test4_15_1()
        {
            new PkitsTest()
                .WithEndEntity("Invalid deltaCRLIndicator No Base Test1 EE")
                .WithCrls("deltaCRLIndicator No Base CA CRL")
                .WithCerts("deltaCRLIndicator No Base CA Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=deltaCRLIndicator No Base CA,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.15.2 Valid delta-CRL Test2</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to the complete CRL as its base CRL.
        /// </remarks>
        [Test]
        public void Test4_15_2()
        {
            new PkitsTest()
                .WithEndEntity("Valid deltaCRL Test2 EE")
                .WithCrls("deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL")
                .WithCerts("deltaCRL CA1 Cert")
                .DoTest();
        }

        /// <summary>4.15.3 Invalid delta-CRL Test3</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to the complete CRL as its base CRL. The end entity certificate is listed as revoked on the
        /// complete CRL.
        /// </remarks>
        [Test]
        public void Test4_15_3()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid deltaCRL Test3 EE")
                .WithCrls("deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL")
                .WithCerts("deltaCRL CA1 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.15.4 Invalid delta-CRL Test4</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to the complete CRL as its base CRL. The end entity certificate is listed as revoked on the
        /// delta-CRL.
        /// </remarks>
        [Test]
        public void Test4_15_4()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .EnableDeltaCrls(true)
                .WithEndEntity("Invalid deltaCRL Test4 EE")
                .WithCrls("deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL")
                .WithCerts("deltaCRL CA1 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.15.5 Valid delta-CRL Test5</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to the complete CRL as its base CRL. The end entity certificate is listed as on hold on the
        /// complete CRL, but the delta-CRL indicates that it should be removed from the CRL.
        /// </remarks>
        [Test]
        public void Test4_15_5()
        {
            new PkitsTest()
                .EnableDeltaCrls(true)
                .WithEndEntity("Valid deltaCRL Test5 EE")
                .WithCrls("deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL")
                .WithCerts("deltaCRL CA1 Cert")
                .DoTest();
        }

        /// <summary>4.15.6 Invalid delta-CRL Test6</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to the complete CRL as its base CRL. The end entity certificate is listed as on hold on the
        /// complete CRL and the delta-CRL indicates that it has been revoked.
        /// </remarks>
        [Test]
        public void Test4_15_6()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .EnableDeltaCrls(true)
                .WithEndEntity("Invalid deltaCRL Test6 EE")
                .WithCrls("deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL")
                .WithCerts("deltaCRL CA1 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.15.7 Valid delta-CRL Test7</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to the complete CRL as its base CRL. The end entity certificate is not listed on the complete
        /// CRL and is listed on the delta-CRL as removeFromCRL.
        /// </remarks>
        [Test]
        public void Test4_15_7()
        {
            new PkitsTest()
                .WithEndEntity("Valid deltaCRL Test7 EE")
                .WithCrls("deltaCRL CA1 deltaCRL", "deltaCRL CA1 CRL")
                .WithCerts("deltaCRL CA1 Cert")
                .DoTest();
        }

        /// <summary>4.15.8 Valid delta-CRL Test8</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to a CRL that was issued earlier than the complete CRL as its base CRL. The end entity
        /// certificate is not listed on either the complete CRL or the delta-CRL.
        /// </remarks>
        [Test]
        public void Test4_15_8()
        {
            new PkitsTest()
                .WithEndEntity("Valid deltaCRL Test8 EE")
                .WithCrls("deltaCRL CA2 deltaCRL", "deltaCRL CA2 CRL")
                .WithCerts("deltaCRL CA2 Cert")
                .DoTest();
        }

        /// <summary>4.15.9 Invalid delta-CRL Test9</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to a CRL that was issued earlier than the complete CRL as its base CRL. The end entity
        /// certificate is listed as revoked on both the complete CRL and the delta-CRL.
        /// </remarks>
        [Test]
        public void Test4_15_9()
        {
            var expectedDate = FormatRevocationDate(2001, 4, 19, 14, 57, 20);
            new PkitsTest()
                .WithEndEntity("Invalid deltaCRL Test9 EE")
                .WithCrls("deltaCRL CA2 deltaCRL", "deltaCRL CA2 CRL")
                .WithCerts("deltaCRL CA2 Cert")
                .DoExceptionTest(0, $"Certificate revocation after {expectedDate}, reason: keyCompromise");
        }

        /// <summary>4.15.10 Invalid delta-CRL Test10</summary>
        /// <remarks>
        /// In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
        /// refers to a CRL that was issued later than the complete CRL as its base CRL. The end entity
        /// certificate is not listed as revoked on either the complete CRL or the delta-CRL, but the delta-CRL
        /// can not be used in conjunction with the provided complete CRL. The complete CRL has a
        /// nextUpdate time that is in the past.
        /// </remarks>
        [Test]
        public void Test4_15_10()
        {
            new PkitsTest()
                .EnableDeltaCrls(true)
                .WithEndEntity("Invalid deltaCRL Test10 EE")
                .WithCrls("deltaCRL CA3 deltaCRL", "deltaCRL CA3 CRL")
                .WithCerts("deltaCRL CA3 Cert")
                // TODO[pkix] Stable X509Name strings
                //.DoExceptionTest(0, "No CRLs found for issuer \"cn=deltaCRL CA3,o=Test Certificates,c=US\"");
                .DoExceptionPrefixTest(0, "No CRLs found for issuer ");
        }

        /// <summary>4.16.1 Valid Unknown Not Critical Certificate Extension Test1</summary>
        /// <remarks>
        /// In this test, the end entity certificate contains a private, non-critical certificate extension.
        /// </remarks>
        [Test]
        public void Test4_16_1()
        {
            new PkitsTest()
                .WithEndEntity("Valid Unknown Not Critical Certificate Extension Test1 EE")
                .DoTest();
        }

        /// <summary>4.16.2 Invalid Unknown Critical Certificate Extension Test2</summary>
        /// <remarks>
        /// In this test, the end entity certificate contains a private, critical certificate extension.
        /// </remarks>
        [Test]
        public void Test4_16_2()
        {
            new PkitsTest()
                .WithEndEntity("Invalid Unknown Critical Certificate Extension Test2 EE")
                .DoExceptionTest(0, "Certificate has unsupported critical extension: [2.16.840.1.101.2.1.12.2]");
        }

        private static string FormatDate(string format, DateTime date) =>
            date.ToString(format, DateTimeFormatInfo.InvariantInfo);

        // NOTE: bc-java format looks like: 2001-04-19 14:57:20 +0000
        private static string FormatRevocationDate(int year, int month, int day, int hour, int minute, int second) =>
            FormatDate(@"yyyy-MM-dd HH:mm:ss K", UtcDate(year, month, day, hour, minute, second));

        // NOTE: bc-java format looks like: 20470101120100GMT+00:00
        private static string FormatValidityDate(int year, int month, int day, int hour, int minute, int second) =>
            FormatDate(@"yyyyMMddHHmmssK", UtcDate(year, month, day, hour, minute, second));

        private static DateTime UtcDate(int year, int month, int day, int hour, int minute, int second) =>
            new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
    }
}
