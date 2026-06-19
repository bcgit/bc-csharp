using System;

using NUnit.Framework;

namespace Org.BouncyCastle.Asn1.Cms.Tests
{
    /*
     * RFC 5084 constrains the AEAD ICV length to a small set of values. Parsing an out-of-range length from an
     * untrusted AlgorithmIdentifier (e.g. a CMS content-encryption algorithm) must be rejected; in particular a
     * zero length must not be accepted, since it can defeat the AEAD tag check on decryption.
     */
    [TestFixture]
    public class GcmParametersTest
    {
        private static Asn1Sequence Seq(int icvLen) =>
            new DerSequence(DerOctetString.WithContents(new byte[12]), DerInteger.ValueOf(icvLen));

        private static Asn1Sequence SeqNoIcv() => new DerSequence(DerOctetString.WithContents(new byte[12]));

        [Test]
        public void DefaultIcvLen() =>
            Assert.AreEqual(12, GcmParameters.GetInstance(SeqNoIcv()).IcvLen);

        [Test]
        public void InvalidIcvLen()
        {
            foreach (int icvLen in new int[]{ -1, 0, 11, 17 })
            {
                Assert.Throws<ArgumentException>(() => GcmParameters.GetInstance(Seq(icvLen)));
                Assert.Throws<ArgumentException>(() => new GcmParameters(new byte[12], icvLen));
            }
        }

        [Test]
        public void ValidIcvLen()
        {
            foreach (int icvLen in new int[]{ 12, 13, 14, 15, 16 })
            {
                Assert.AreEqual(icvLen, GcmParameters.GetInstance(Seq(icvLen)).IcvLen);
                Assert.AreEqual(icvLen, new GcmParameters(new byte[12], icvLen).IcvLen);
            }
        }
    }
}
