using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Cert.Tests
{
    [TestFixture]
    public class RelatedCertificateTest
    {
        // =====================================================================
        // OID + extension constants
        // =====================================================================

        [Test]
        public void OidValues()
        {
            Assert.AreEqual("1.3.6.1.5.5.7.1.36", X509ObjectIdentifiers.id_pe_relatedCert.GetID());
            Assert.AreEqual("1.3.6.1.5.5.7.1.36", X509Extensions.RelatedCertificate.GetID());
            Assert.AreEqual(X509ObjectIdentifiers.id_pe_relatedCert, X509Extensions.RelatedCertificate);
            Assert.AreEqual("1.2.840.113549.1.9.16.2.60", PkcsObjectIdentifiers.IdAARelatedCertRequest.GetID());
        }

        // =====================================================================
        // BinaryTime
        // =====================================================================

        [Test]
        public void BinaryTimeRoundTrip()
        {
            // Pick a fixed epoch-second value to anchor the wire encoding.
            long sec = 1700000000L;
            BinaryTime t = new BinaryTime(sec);
            Assert.That(t.Time.HasValue(sec));

            BinaryTime reparsed = BinaryTime.GetInstance(t.GetEncoded());
            Assert.AreEqual(t, reparsed);
            Assert.That(reparsed.Time.HasValue(sec));

            BinaryTime fromDateTime = new BinaryTime(DateTimeUtilities.UnixMsToDateTime(sec * 1000L));
            Assert.AreEqual(t, fromDateTime);
            Assert.AreEqual(sec * 1000L, DateTimeUtilities.DateTimeToUnixMs(fromDateTime.GetDateTime()));
            Assert.True(fromDateTime.TryGetDateTime(out var tryDateTime));
            Assert.AreEqual(sec * 1000L, DateTimeUtilities.DateTimeToUnixMs(tryDateTime));
        }

        [Test]
        public void BinaryTimeRejectsNegative()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new BinaryTime(-1L),
                "BinaryTime accepted negative seconds");

            Assert.Throws<ArgumentOutOfRangeException>(() => new BinaryTime(DerInteger.ValueOf(-1L)),
                "BinaryTime accepted negative seconds");

            var preEpoch = DateTimeUtilities.UnixEpoch.AddSeconds(-1);
            Assert.Throws<ArgumentOutOfRangeException>(() => new BinaryTime(preEpoch),
                "BinaryTime accepted pre-epoch DateTime");
        }
    }
}
