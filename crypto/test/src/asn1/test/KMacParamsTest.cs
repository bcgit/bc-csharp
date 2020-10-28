using NUnit.Framework;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class KMacParamsTest  :SimpleTest
    {
        public override string Name => "KMacParamsTest";

      
        public override void PerformTest()
        {
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(256).GetEncoded(), new DerSequence().GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(512).GetEncoded(), new DerSequence().GetEncoded()));

            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(512).GetEncoded(), new DerSequence(new DerInteger(512)).GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(256).GetEncoded(), new DerSequence(new DerInteger(256)).GetEncoded()));

            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(512).GetEncoded(), KMACwithSHAKE128_params.getInstance(new DerSequence(new DerInteger(512))).GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(256).GetEncoded(), KMACwithSHAKE256_params.getInstance(new DerSequence(new DerInteger(256))).GetEncoded()));

            byte[] customizationString = Strings.ToByteArray("hello, world!");

            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(512, customizationString).GetEncoded(), new DerSequence(
                new Asn1Encodable[] { new DerInteger(512), new DerOctetString(customizationString) }).GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(256, customizationString).GetEncoded(), new DerSequence(
                new Asn1Encodable[] { new DerInteger(256), new DerOctetString(customizationString) }).GetEncoded()));

            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(512, customizationString).GetEncoded(),
                KMACwithSHAKE128_params.getInstance(
                    new DerSequence(new Asn1Encodable[] { new DerInteger(512), new DerOctetString(customizationString) })).GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(256, customizationString).GetEncoded(),
                KMACwithSHAKE256_params.getInstance(new DerSequence(
                new Asn1Encodable[] { new DerInteger(256), new DerOctetString(customizationString) })).GetEncoded()));

            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(256, customizationString).GetEncoded(), new DerSequence(
                new Asn1Encodable[] { new DerOctetString(customizationString) }).GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(512, customizationString).GetEncoded(), new DerSequence(
                new Asn1Encodable[] { new DerOctetString(customizationString) }).GetEncoded()));

            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE128_params(256, customizationString).GetEncoded(),
                KMACwithSHAKE128_params.getInstance(
                    new DerSequence(new Asn1Encodable[] { new DerOctetString(customizationString) })).GetEncoded()));
            Assert.IsTrue(Arrays.AreEqual(new KMACwithSHAKE256_params(512, customizationString).GetEncoded(),
                KMACwithSHAKE256_params.getInstance(new DerSequence(
                new Asn1Encodable[] { new DerOctetString(customizationString) })).GetEncoded()));

            KMACwithSHAKE128_params p128 = new KMACwithSHAKE128_params(256, customizationString);
            Assert.AreEqual(256, p128.OutputLength);
            Assert.IsTrue(Arrays.AreEqual(customizationString, p128.CustomizationString));
            Assert.IsTrue(p128 == KMACwithSHAKE128_params.getInstance(p128));

            KMACwithSHAKE256_params p256 = new KMACwithSHAKE256_params(512, customizationString);
            Assert.AreEqual(512, p256.OutputLength);
            Assert.IsTrue(Arrays.AreEqual(customizationString, p256.CustomizationString));
            Assert.IsTrue(p256 == KMACwithSHAKE256_params.getInstance(p256));

            p128 = new KMACwithSHAKE128_params(512);
            Assert.AreEqual(512, p128.OutputLength);
            Assert.IsTrue(Arrays.AreEqual(new byte[0], p128.CustomizationString));

            p256 = new KMACwithSHAKE256_params(256);
            Assert.AreEqual(256, p256.OutputLength);
            Assert.IsTrue(Arrays.AreEqual(new byte[0], p256.CustomizationString));
        }

        public static void Main(
            string[] args)
        {
            RunTest(new KMacParamsTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(resultText, Name + ": Okay", resultText);
        }
    }
}
