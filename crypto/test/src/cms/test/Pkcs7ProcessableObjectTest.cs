using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
    public class Pkcs7ProcessableObjectTest
    {
        private static readonly DerObjectIdentifier ContentType = new DerObjectIdentifier("1.2.3.4.5");

        private static readonly string SignDN = "O=Bouncy Castle, C=AU";

        private AsymmetricCipherKeyPair m_signKP;
        private X509Certificate m_signCert;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            m_signKP = CmsTestUtil.MakeECDsaKeyPair();
            m_signCert = CmsTestUtil.MakeCertificate(m_signKP, SignDN, m_signKP, SignDN);
        }

        // Lengths chosen to cover the short-form length (< 128), and long-form lengths with one and two length octets.
        [TestCase(100)]
        [TestCase(200)]
        [TestCase(300)]
        public void WriteEmitsContentsOctets(int length)
        {
            string text = MakeText(length, '1');
            byte[] expected = Strings.ToUtf8ByteArray(text);

            Assert.AreEqual(expected, WriteToArray(new Pkcs7ProcessableObject(ContentType, new DerUtf8String(text))));
        }

        // High tag numbers (>= 31) use multiple identifier octets, which must be skipped as well.
        [TestCase(100, 50)]
        [TestCase(200, 200)]
        public void WriteEmitsContentsOctetsHighTagNumber(int tagNo, int length)
        {
            byte[] expected = new byte[length];
            for (int i = 0; i < length; ++i)
            {
                expected[i] = (byte)(0x80 | i);
            }

            var content = new DerTaggedObject(false, tagNo, new DerOctetString(expected));

            Assert.AreEqual(expected, WriteToArray(new Pkcs7ProcessableObject(ContentType, content)));
        }

        [Test]
        public void WriteEmitsSequenceElements()
        {
            var e1 = new DerInteger(12345);
            var e2 = new DerUtf8String(MakeText(200, '1'));
            byte[] expected = Arrays.Concatenate(e1.GetEncoded(Asn1Encodable.Der), e2.GetEncoded(Asn1Encodable.Der));

            Assert.AreEqual(expected, WriteToArray(new Pkcs7ProcessableObject(ContentType, new DerSequence(e1, e2))));
        }

        // A signature computed (e.g. by another implementation) over the contents octets of non-OCTET STRING
        // encapsulated content must verify.
        [TestCase(100)]
        [TestCase(200)]
        [TestCase(300)]
        public void VerifyExternallyDigestedContent(int length)
        {
            string text = MakeText(length, '1');
            var signedOver = new CmsProcessableByteArray(ContentType, Strings.ToUtf8ByteArray(text));

            CmsSignedData signedData = SignAndEncapsulate(signedOver, new DerUtf8String(text));

            Assert.IsInstanceOf(typeof(Pkcs7ProcessableObject), signedData.SignedContent);
            Assert.IsTrue(VerifyAll(signedData));
        }

        // Every contents octet must be covered by the signature, including the first ones after a long-form length.
        [TestCase(100)]
        [TestCase(200)]
        [TestCase(300)]
        public void VerifyRejectsModifiedContent(int length)
        {
            string text = MakeText(length, '1');
            var signedOver = new Pkcs7ProcessableObject(ContentType, new DerUtf8String(text));

            Assert.IsTrue(VerifyAll(SignAndEncapsulate(signedOver, new DerUtf8String(text))));

            string modifiedFirst = MakeText(length, '9');
            AssertDigestMismatch(SignAndEncapsulate(signedOver, new DerUtf8String(modifiedFirst)));

            char[] chars = text.ToCharArray();
            chars[12] = 'B';
            string modifiedLater = new string(chars);
            AssertDigestMismatch(SignAndEncapsulate(signedOver, new DerUtf8String(modifiedLater)));
        }

        private void AssertDigestMismatch(CmsSignedData signedData)
        {
            var e = Assert.Throws<CmsException>(() => VerifyAll(signedData));
            StringAssert.Contains("message-digest attribute value does not match", e.Message);
        }

        private static string MakeText(int length, char first)
        {
            string prefix = first + "000 EUR to Alice. ";
            return prefix + new string('x', length - prefix.Length);
        }

        private static byte[] WriteToArray(CmsProcessable processable)
        {
            var bOut = new MemoryStream();
            processable.Write(bOut);
            return bOut.ToArray();
        }

        /// <summary>
        /// Sign <paramref name="signedOver"/> detached, then encapsulate <paramref name="encapContent"/> (which is not
        /// an OCTET STRING, as with PKCS #7 content) and re-parse the encoding as a recipient would.
        /// </summary>
        private CmsSignedData SignAndEncapsulate(CmsTypedData signedOver, Asn1Encodable encapContent)
        {
            var gen = new CmsSignedDataGenerator();
            gen.AddSigner(m_signKP.Private, m_signCert, CmsSignedGenerator.DigestSha256);
            SignedData detached = gen.Generate(signedOver, encapsulate: false).SignedData;

            var signedData = new SignedData(detached.DigestAlgorithms, new ContentInfo(ContentType, encapContent),
                detached.Certificates, detached.CRLs, detached.SignerInfos);
            var contentInfo = new ContentInfo(CmsObjectIdentifiers.SignedData, signedData);
            return new CmsSignedData(contentInfo.GetEncoded(Asn1Encodable.Der));
        }

        private bool VerifyAll(CmsSignedData signedData)
        {
            var signers = signedData.GetSignerInfos().GetSigners();
            Assert.AreEqual(1, signers.Count);

            foreach (SignerInformation signer in signers)
            {
                if (!signer.Verify(m_signCert))
                    return false;
            }
            return true;
        }
    }
}
