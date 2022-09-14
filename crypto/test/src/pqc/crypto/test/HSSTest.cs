using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class HSSTest
    {
        [Test]
		public void TestKeyGenAndSign()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

            kpGen.Init(new HSSKeyGenerationParameters(
                new LMSParameters[]{
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
                }, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HSSSigner signer = new HSSSigner();

            signer.Init(true, kp.Private);

            byte[] sig = signer.GenerateSignature(msg);

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg, sig));
        }

        [Test]
		public void TestKeyGenAndUsage()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

            kpGen.Init(new HSSKeyGenerationParameters(
                new LMSParameters[]{
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
                }, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HSSPrivateKeyParameters privKey = (HSSPrivateKeyParameters)kp.Private;

            HSSPublicKeyParameters pubKey = (HSSPublicKeyParameters)kp.Public;
            
            LMSParameters lmsParam = pubKey.GetLmsPublicKey().GetLmsParameters();

            Assert.AreEqual(LMSigParameters.lms_sha256_n32_h5, lmsParam.GetLmSigParam());
            Assert.AreEqual(LMOtsParameters.sha256_n32_w4, lmsParam.GetLmotsParam());

            HSSSigner signer = new HSSSigner();

            signer.Init(true, privKey);

            Assert.AreEqual(1024, privKey.GetUsagesRemaining());
            Assert.AreEqual(2, privKey.GetLmsParameters().Length);

            for (int i = 1; i <= 1024; i++)
            {
                signer.GenerateSignature(msg);

                Assert.AreEqual(i, privKey.GetIndex());
                Assert.AreEqual(1024 - i, privKey.GetUsagesRemaining());
            }
        }

		[Test]
		public void TestKeyGenAndSignTwoSigsWithShard()
        {
            byte[] msg1 = Strings.ToByteArray("Hello, world!");
            byte[] msg2 = Strings.ToByteArray("Now is the time");

            IAsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

            kpGen.Init(new HSSKeyGenerationParameters(
                new LMSParameters[]{
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
                }, new SecureRandom()));
            
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HSSPrivateKeyParameters privKey = ((HSSPrivateKeyParameters)kp.Private).ExtractKeyShard(2);

            Assert.AreEqual(2, ((HSSPrivateKeyParameters)kp.Private).GetIndex());

            HSSSigner signer = new HSSSigner();

            Assert.AreEqual(0, privKey.GetIndex());

            signer.Init(true, privKey);

            byte[] sig1 = signer.GenerateSignature(msg1);

            Assert.AreEqual(1, privKey.GetIndex());

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg1, sig1));

            signer.Init(true, privKey);

            byte[] sig = signer.GenerateSignature(msg2);

            Assert.AreEqual(2, privKey.GetIndex());

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg2, sig));

            try
            {
                sig = signer.GenerateSignature(msg2);
                Assert.Fail("no exception");
            }
            catch (Exception e)
            {
                Assert.AreEqual("hss private key shard is exhausted", e.Message);
            }

            signer.Init(true, ((HSSPrivateKeyParameters)kp.Private));

            sig = signer.GenerateSignature(msg1);

            Assert.AreEqual(3, ((HSSPrivateKeyParameters)kp.Private).GetIndex());

            Assert.False(Arrays.AreEqual(sig1, sig));

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg1, sig1));
        }
    }
}