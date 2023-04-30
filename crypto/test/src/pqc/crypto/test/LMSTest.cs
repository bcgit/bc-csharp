using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class LMSTest
    {
        [Test]
        public void TestKeyGenAndSign()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new LmsKeyPairGenerator();

            kpGen.Init(new LmsKeyGenerationParameters(
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            LmsSigner signer = new LmsSigner();

            signer.Init(true, kp.Private);

            byte[] sig = signer.GenerateSignature(msg);

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg, sig));
        }

        [Test]
        public void TestKeyGenAndSignTwoSigsWithShard()
        {
            byte[] msg1 = Strings.ToByteArray("Hello, world!");
            byte[] msg2 = Strings.ToByteArray("Now is the time");

            IAsymmetricCipherKeyPairGenerator kpGen = new LmsKeyPairGenerator();

            kpGen.Init(new LmsKeyGenerationParameters(
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            LmsPrivateKeyParameters privKey = ((LmsPrivateKeyParameters)kp.Private).ExtractKeyShard(2);

            Assert.AreEqual(2, ((LmsPrivateKeyParameters)kp.Private).GetIndex());

            LmsSigner signer = new LmsSigner();

            Assert.AreEqual(2, privKey.GetUsagesRemaining());
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
                Assert.AreEqual("ots private key exhausted", e.Message);
            }

            signer.Init(true, ((LmsPrivateKeyParameters)kp.Private));

            sig = signer.GenerateSignature(msg1);

            Assert.AreEqual(3, ((LmsPrivateKeyParameters)kp.Private).GetIndex());

            Assert.False(Arrays.AreEqual(sig1, sig));

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg1, sig1));

            PrivateKeyInfo pInfo = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);//TODO
            AsymmetricKeyParameter pKey = PqcPrivateKeyFactory.CreateKey(pInfo.GetEncoded());

            signer.Init(false, ((LmsPrivateKeyParameters)pKey).GetPublicKey());

            Assert.True(signer.VerifySignature(msg1, sig1));
        }
    }
}