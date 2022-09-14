using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

using PrivateKeyFactory = Org.BouncyCastle.Pqc.Crypto.Utilities.PrivateKeyFactory;
using PrivateKeyInfoFactory = Org.BouncyCastle.Pqc.Crypto.Utilities.PrivateKeyInfoFactory;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class LMSTest
    {
        [Test]
        public void TestKeyGenAndSign()
        {
            byte[] msg = Strings.ToByteArray("Hello, world!");
            IAsymmetricCipherKeyPairGenerator kpGen = new LMSKeyPairGenerator();

            kpGen.Init(new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            LMSSigner signer = new LMSSigner();

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

            IAsymmetricCipherKeyPairGenerator kpGen = new LMSKeyPairGenerator();

            kpGen.Init(new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            LMSPrivateKeyParameters privKey = ((LMSPrivateKeyParameters)kp.Private).ExtractKeyShard(2);

            Assert.AreEqual(2, ((LMSPrivateKeyParameters)kp.Private).GetIndex());

            LMSSigner signer = new LMSSigner();

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

            signer.Init(true, ((LMSPrivateKeyParameters)kp.Private));

            sig = signer.GenerateSignature(msg1);

            Assert.AreEqual(3, ((LMSPrivateKeyParameters)kp.Private).GetIndex());

            Assert.False(Arrays.AreEqual(sig1, sig));

            signer.Init(false, kp.Public);

            Assert.True(signer.VerifySignature(msg1, sig1));

            PrivateKeyInfo pInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);//TODO
            AsymmetricKeyParameter pKey = PrivateKeyFactory.CreateKey(pInfo.GetEncoded());

            signer.Init(false, ((LMSPrivateKeyParameters)pKey).GetPublicKey());

            Assert.True(signer.VerifySignature(msg1, sig1));
        }
    }
}