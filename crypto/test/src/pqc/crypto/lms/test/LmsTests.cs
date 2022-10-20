using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    [TestFixture]
    public class LmsTests
    {
        [Test]
        public void TestCoefFunc()
        {
            byte[] S = Hex.Decode("1234");
            Assert.AreEqual(0, LM_OTS.Coef(S, 7, 1));
            Assert.AreEqual(1, LM_OTS.Coef(S, 0, 4));
        }

        [Test]
        public void TestPrivateKeyRound()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LM_OTS.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LMSContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsSignature sig = LM_OTS.LMOtsGenerateSignature(privateKey, ctx.GetQ(), ctx.C);
            Assert.True(LM_OTS.LMOtsValidateSignature(publicKey, sig, ms, false));

            //  Vandalise signature
            {

                byte[] vandalisedSignature = sig.GetEncoded(); // Arrays.clone(sig);
                vandalisedSignature[256] ^= 1; // Single bit error
                Assert.False(LM_OTS.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(vandalisedSignature), ms, false));
            }

            // Vandalise public key.
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[50] ^= 1;
                Assert.False(LM_OTS.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false));
            }

            //
            // check incorrect alg type is detected.
            //
            try
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[3] += 1;
                LM_OTS.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false);
                Assert.True(false, "Must fail as public key type not match signature type.");
            }
            catch (LMSException ex)
            {
                Assert.True(ex.Message.Contains("public key and signature ots types do not match"));
            }
        }

        [Test]
        public void TestLMS()
        {
            byte[] msg = Hex.Decode("54686520656e756d65726174696f6e20\n" +
                                    "696e2074686520436f6e737469747574\n" +
                                    "696f6e2c206f66206365727461696e20\n" +
                                    "7269676874732c207368616c6c206e6f\n" +
                                    "7420626520636f6e7374727565642074\n" +
                                    "6f2064656e79206f7220646973706172\n" +
                                    "616765206f7468657273207265746169\n" +
                                    "6e6564206279207468652070656f706c\n" +
                                    "652e0a");

            byte[] seed = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            int level = 1;
            LMSPrivateKeyParameters lmsPrivateKey = LMS.GenerateKeys(
                LMSigParameters.GetParametersByID(5),
                LMOtsParameters.GetParametersByID(4),
                level, Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);

            LMSPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();

            lmsPrivateKey.ExtractKeyShard(3);

            LMSSignature signature = LMS.GenerateSign(lmsPrivateKey, msg);
            Assert.True(LMS.VerifySignature(publicKey, signature, msg));

            // Serialize / Deserialize
            Assert.True(LMS.VerifySignature(
                LMSPublicKeyParameters.GetInstance(publicKey.GetEncoded()),
                LMSSignature.GetInstance(signature.GetEncoded()), msg));

            //
            // Vandalise signature.
            //
            {
                byte[] bustedSig = Arrays.Clone(signature.GetEncoded());
                bustedSig[100] ^= 1;
                Assert.False(LMS.VerifySignature(publicKey, LMSSignature.GetInstance(bustedSig), msg));
            }

            //
            // Vandalise message
            //
            {
                byte[] msg2 = Arrays.Clone(msg);
                msg2[10] ^= 1;
                Assert.False(LMS.VerifySignature(publicKey, signature, msg2));
            }
        }

        [Test]
        public void TestContextSingleUse()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LM_OTS.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LMSContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsSignature sig = LM_OTS.LMOtsGenerateSignature(privateKey, ctx.GetQ(), ctx.C);
            Assert.True(LM_OTS.LMOtsValidateSignature(publicKey, sig, ms, false));

            try
            {
                ctx.Update(1);
                Assert.Fail("Digest reuse after signature taken.");
            }
            catch (NullReferenceException)
            {
                // Expected
            }
        }
    }
}
