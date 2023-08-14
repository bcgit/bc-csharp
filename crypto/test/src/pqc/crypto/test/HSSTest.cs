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
        public void TestOneLevelKeyGenAndSign()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

            var lmsParameters = new LmsParameters[]
            {
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            };
            kpGen.Init(new HssKeyGenerationParameters(lmsParameters, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HssSigner signer = new HssSigner();

            signer.Init(true, kp.Private);

            byte[] sig = signer.GenerateSignature(msg);

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg, sig));

            HssPublicKeyParameters hssPubKey = (HssPublicKeyParameters)kp.Public;

            hssPubKey.GenerateLmsContext(sig);
        }

        [Test]
		public void TestKeyGenAndSign()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

            var lmsParameters = new LmsParameters[]
            {
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            };
            kpGen.Init(new HssKeyGenerationParameters(lmsParameters, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HssSigner signer = new HssSigner();

            signer.Init(true, kp.Private);

            byte[] sig = signer.GenerateSignature(msg);

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg, sig));
        }

        [Test]
		public void TestKeyGenAndUsage()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

            kpGen.Init(new HssKeyGenerationParameters(
                new LmsParameters[]{
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
                }, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HssPrivateKeyParameters privKey = (HssPrivateKeyParameters)kp.Private;

            HssPublicKeyParameters pubKey = (HssPublicKeyParameters)kp.Public;
            
            LmsParameters lmsParam = pubKey.LmsPublicKey.GetLmsParameters();

            Assert.AreEqual(LMSigParameters.lms_sha256_n32_h5, lmsParam.LMSigParameters);
            Assert.AreEqual(LMOtsParameters.sha256_n32_w4, lmsParam.LMOtsParameters);

            HssSigner signer = new HssSigner();

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

            IAsymmetricCipherKeyPairGenerator kpGen = new HssKeyPairGenerator();

            kpGen.Init(new HssKeyGenerationParameters(
                new LmsParameters[]{
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
                }, new SecureRandom()));
            
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            HssPrivateKeyParameters privKey = ((HssPrivateKeyParameters)kp.Private).ExtractKeyShard(2);

            Assert.AreEqual(2, ((HssPrivateKeyParameters)kp.Private).GetIndex());

            HssSigner signer = new HssSigner();

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

            signer.Init(true, ((HssPrivateKeyParameters)kp.Private));

            sig = signer.GenerateSignature(msg1);

            Assert.AreEqual(3, ((HssPrivateKeyParameters)kp.Private).GetIndex());

            Assert.False(Arrays.AreEqual(sig1, sig));

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg1, sig1));
        }
    }
}