using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms.Tests
{
    /// <summary>Tests for <see cref="SignerInfo"/> </summary>
    [TestFixture]
    public class SignerInfoTest
    {
        /// <summary>
        /// Confirms <see cref="SignerInfo"/> decodes its version and trailing unsignedAttrs elements through
        /// <c>GetInstance</c> rather than a direct cast, so a malformed-but-parseable <c>SignerInfo</c> fails with
        /// <see cref="ArgumentException"/> (the <c>GetInstance</c> contract) rather than leaking an
        /// <see cref="InvalidCastException"/>. Relates to github (bc-java) #2342.
        /// </summary>
        [Test]
        public void ExceptionContract()
        {
            SignerIdentifier sid = new SignerIdentifier(new DerOctetString(new byte[]{ 1, 2, 3, 4, 5 }));
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"));
            AlgorithmIdentifier encAlg = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.1"));
            DerOctetString encryptedDigest = new DerOctetString(new byte[]{ 6, 7, 8, 9 });

            SignerInfo signerInfo = new SignerInfo(sid, digAlg, (Asn1Set)null, encAlg, encryptedDigest, (Asn1Set)null);

            Asn1Sequence seq = Asn1Sequence.GetInstance(signerInfo.ToAsn1Object());

            // well-formed round-trip
            Assert.That(Arrays.AreEqual(signerInfo.GetEncoded(), SignerInfo.GetInstance(seq).GetEncoded()),
                "SignerInfo round-trip");

            // version element is not an INTEGER
            Asn1EncodableVector badVersion = new Asn1EncodableVector();
            badVersion.Add(new DerUtf8String("not an integer"));
            for (int i = 1; i != seq.Count; i++)
            {
                badVersion.Add(seq[i]);
            }
            ExpectArgumentException("non-INTEGER version", new DerSequence(badVersion));

            // trailing unsignedAttrs element is not a tagged object
            Asn1EncodableVector badUnsigned = new Asn1EncodableVector();
            for (int i = 0; i != seq.Count; i++)
            {
                badUnsigned.Add(seq[i]);
            }
            badUnsigned.Add(DerInteger.ValueOf(99));
            ExpectArgumentException("non-tagged unsignedAttrs", new DerSequence(badUnsigned));
        }

        private static void ExpectArgumentException(string label, Asn1Sequence malformed)
        {
            try
            {
                SignerInfo.GetInstance(malformed);
                Assert.Fail($"malformed SignerInfo ({label}) not rejected");
            }
            catch (ArgumentException)
            {
                // expected - the GetInstance contract, not a leaked InvalidCastException
            }
        }
    }
}
