using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Security.Tests
{
    [TestFixture]
    public class JksStoreTest
    {
        private static readonly byte[] Test1 = Base64.Decode(
            "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");

        private static readonly byte[] Test2 = Base64.Decode(
            "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"
          + "4fNHHstpt64C");

        [Test]
        public void TestJks()
        {
            JksStore ks = new JksStore();

            ks.Load(new MemoryStream(Test1, false), "fredfred".ToCharArray());

            ks.GetKey("rsa", "samsam".ToCharArray());

            IAsymmetricCipherKeyPairGenerator kpGen = new RsaKeyPairGenerator();
            kpGen.Init(new RsaKeyGenerationParameters(new BigInteger("10001", 16), new SecureRandom(), 1024, 100));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            ks.SetKeyEntry("fred", kp.Private, "bobbob".ToCharArray(), ks.GetCertificateChain("rsa"));

            ks.GetKey("fred", "bobbob".ToCharArray());

            MemoryStream bOut = new MemoryStream();

            ks.Save(bOut, "billbill".ToCharArray());

            ks = new JksStore();

            ks.Load(new MemoryStream(Test2, false), "samsam".ToCharArray());

            AsymmetricKeyParameter privKey = ks.GetKey("rsa", "samsam".ToCharArray());

            ks = new JksStore();

            try
            {
                ks.Load(new MemoryStream(bOut.ToArray()), "wrong".ToCharArray());
                Assert.Fail("Exception expected for Load() with wrong password");
            }
            catch (Exception)
            {
                // Expected
            }

            ks.Load(new MemoryStream(bOut.ToArray()), "billbill".ToCharArray());

            privKey = ks.GetKey("rsa", "samsam".ToCharArray());

            privKey = ks.GetKey("fred", "bobbob".ToCharArray());

            Assert.IsNull(ks.GetCertificate("george"));
            Assert.IsNull(ks.GetCertificateChain("george"));
            Assert.IsNull(ks.GetKey("george", "ignored".ToCharArray()));

            try
            {
                privKey = ks.GetKey("fred", "wrong".ToCharArray());
                Assert.Fail("Exception expected for GetKey() with wrong password");
            }
            catch (Exception)
            {
                // Expected
            }
        }
    }
}
