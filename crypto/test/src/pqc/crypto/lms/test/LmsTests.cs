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
            Assert.AreEqual(0, LMOts.Coef(S, 7, 1));
            Assert.AreEqual(1, LMOts.Coef(S, 0, 4));
        }

        [Test]
        public void TestPrivateKeyRound()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, ctx.GetQ(), ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));

            // Recreate signature
            {
                byte[] recreatedSignature = sig.GetEncoded();
                Assert.True(LMOts.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(recreatedSignature), ms, false));
            }

            // Recreate public key.
            {
                byte[] recreatedPubKey = Arrays.Clone(publicKey.GetEncoded());
                Assert.True(LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(recreatedPubKey), sig, ms, false));
            }

            // Vandalise signature
            {

                byte[] vandalisedSignature = sig.GetEncoded();
                vandalisedSignature[256] ^= 1; // Single bit error
                Assert.False(LMOts.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(vandalisedSignature), ms, false));
            }

            // Vandalise public key.
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[50] ^= 1;
                Assert.False(LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false));
            }

            //
            // check incorrect alg type is detected.
            //
            try
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[3] += 1;
                LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false);
                Assert.True(false, "Must fail as public key type not match signature type.");
            }
            catch (LmsException ex)
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
            LmsPrivateKeyParameters lmsPrivateKey = Lms.GenerateKeys(
                LMSigParameters.GetParametersByID(5),
                LMOtsParameters.GetParametersByID(4),
                level, Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);

            LmsPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();

            lmsPrivateKey.ExtractKeyShard(3);

            LmsSignature signature = Lms.GenerateSign(lmsPrivateKey, msg);
            Assert.True(Lms.VerifySignature(publicKey, signature, msg));

            // Serialize / Deserialize
            Assert.True(Lms.VerifySignature(
                LmsPublicKeyParameters.GetInstance(publicKey.GetEncoded()),
                LmsSignature.GetInstance(signature.GetEncoded()), msg));

            //
            // Vandalise signature.
            //
            {
                byte[] bustedSig = Arrays.Clone(signature.GetEncoded());
                bustedSig[100] ^= 1;
                Assert.False(Lms.VerifySignature(publicKey, LmsSignature.GetInstance(bustedSig), msg));
            }

            //
            // Vandalise message
            //
            {
                byte[] msg2 = Arrays.Clone(msg);
                msg2[10] ^= 1;
                Assert.False(Lms.VerifySignature(publicKey, signature, msg2));
            }
        }

        [Test]
        public void TestContextSingleUse()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, ctx.GetQ(), ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));

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
