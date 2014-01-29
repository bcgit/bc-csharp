using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * Test vectors from the "work in progress" Internet-Draft <a
     * href="http://tools.ietf.org/html/draft-irtf-cfrg-ocb-05">The OCB Authenticated-Encryption
     * Algorithm</a>
     */
    public class OcbTest
        : SimpleTest
    {
        private const string K = "000102030405060708090A0B0C0D0E0F";
        private const string N = "000102030405060708090A0B";

        /*
         * Test vectors contain the strings A, P, C in order
         */

        // Sample data for 96 bit tag, taken from a CFRG post
        private static readonly string[][] TEST_VECTORS_96 = new string[][]{ new string[]{
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
            "09A4FD29DE949D9A9AA9924248422097AD4883B4713E6C214FF6567ADA08A96766FC4E2EE3E3A5A11B6C44F34E3ABB3CBF8976E7" } };

        // Test vectors from Appendix A of the specification
        private static readonly string[][] TEST_VECTORS_128 = new string[][]{
            new string[]{ "", "", "197B9C3C441D3C83EAFB2BEF633B9182" },
            new string[]{ "0001020304050607", "0001020304050607", "92B657130A74B85A16DC76A46D47E1EAD537209E8A96D14E" },
            new string[]{ "0001020304050607", "", "98B91552C8C009185044E30A6EB2FE21" },
            new string[]{ "", "0001020304050607", "92B657130A74B85A971EFFCAE19AD4716F88E87B871FBEED" },
            new string[]{ "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F",
                "BEA5E8798DBE7110031C144DA0B26122776C9924D6723A1F" + "C4524532AC3E5BEB" },
            new string[]{ "000102030405060708090A0B0C0D0E0F", "", "7DDB8E6CEA6814866212509619B19CC6" },
            new string[]{ "", "000102030405060708090A0B0C0D0E0F",
                "BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A" + "4CBB3E4BD6B456AF" },
            new string[]{ "000102030405060708090A0B0C0D0E0F1011121314151617", "000102030405060708090A0B0C0D0E0F1011121314151617",
                "BEA5E8798DBE7110031C144DA0B26122FCFCEE7A2A8D4D48" + "5FA94FC3F38820F1DC3F3D1FD4E55E1C" },
            new string[]{ "000102030405060708090A0B0C0D0E0F1011121314151617", "", "282026DA3068BC9FA118681D559F10F6" },
            new string[]{ "", "000102030405060708090A0B0C0D0E0F1011121314151617",
                "BEA5E8798DBE7110031C144DA0B26122FCFCEE7A2A8D4D48" + "6EF2F52587FDA0ED97DC7EEDE241DF68" },
            new string[]{ "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F",
                "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F",
                "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6" + "57149D53773463CBB2A040DD3BD5164372D76D7BB6824240" },
            new string[]{ "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F", "",
                "E1E072633BADE51A60E85951D9C42A1B" },
            new string[]{ "", "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F",
                "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6" + "57149D53773463CB4A3BAE824465CFDAF8C41FC50C7DF9D9" },
            new string[]{
                "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
                "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
                "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6" + "57149D53773463CB68C65778B058A635659C623211DEEA0D"
                    + "E30D2C381879F4C8" },
            new string[]{ "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627", "",
                "7AEB7A69A1687DD082CA27B0D9A37096" },
            new string[]{
                "",
                "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
                "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6" + "57149D53773463CB68C65778B058A635060C8467F4ABAB5E"
                    + "8B3C2067A2E115DC" },
        };

        public override string Name
        {
            get { return "OCB"; }
        }

        public override void PerformTest()
        {
            for (int i = 0; i < TEST_VECTORS_96.Length; ++i)
            {
                RunTestCase("Test Case " + i, TEST_VECTORS_96[i], 96);
            }
            for (int i = 0; i < TEST_VECTORS_128.Length; ++i)
            {
                RunTestCase("Test Case " + i, TEST_VECTORS_128[i], 128);
            }

            RunLongerTestCase(128, 128, Hex.Decode("B2B41CBF9B05037DA7F16C24A35C1C94"));
            RunLongerTestCase(192, 128, Hex.Decode("1529F894659D2B51B776740211E7D083"));
            RunLongerTestCase(256, 128, Hex.Decode("42B83106E473C0EEE086C8D631FD4C7B"));
            RunLongerTestCase(128, 96, Hex.Decode("1A4F0654277709A5BDA0D380"));
            RunLongerTestCase(192, 96, Hex.Decode("AD819483E01DD648978F4522"));
            RunLongerTestCase(256, 96, Hex.Decode("CD2E41379C7E7C4458CCFB4A"));
            RunLongerTestCase(128, 64, Hex.Decode("B7ECE9D381FE437F"));
            RunLongerTestCase(192, 64, Hex.Decode("DE0574C87FF06DF9"));
            RunLongerTestCase(256, 64, Hex.Decode("833E45FF7D332F7E"));

            DoTestExceptions();
        }

        private void DoTestExceptions()
        {
            OcbBlockCipher ocb = new OcbBlockCipher(new AesFastEngine(), new AesFastEngine());

            try
            {
                ocb = new OcbBlockCipher(new DesEngine(), new DesEngine());
                Fail("incorrect block size not picked up");
            }
            catch (ArgumentException)
            {
                // expected
            }

            try
            {
                ocb.Init(false, new KeyParameter(new byte[16]));
                Fail("illegal argument not picked up");
            }
            catch (ArgumentException)
            {
                // expected
            }

            // TODO
            //AEADTestUtil.testReset(this, new OCBBlockCipher(new AESEngine(), new AESEngine()), new OCBBlockCipher(new AESEngine(), new AESEngine()), new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[15]));
            //AEADTestUtil.testTampering(this, ocb, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[15]));
        }

        private void RunTestCase(string testName, string[] testVector, int macLengthBits)
        {
            byte[] key = Hex.Decode(K);
            byte[] nonce = Hex.Decode(N);

            int pos = 0;
            byte[] A = Hex.Decode(testVector[pos++]);
            byte[] P = Hex.Decode(testVector[pos++]);
            byte[] C = Hex.Decode(testVector[pos++]);

            int macLengthBytes = macLengthBits / 8;

            // TODO Variations processing AAD and cipher bytes incrementally

            KeyParameter keyParameter = new KeyParameter(key);
            AeadParameters aeadParameters = new AeadParameters(keyParameter, macLengthBits, nonce, A);

            OcbBlockCipher encCipher = InitCipher(true, aeadParameters);
            OcbBlockCipher decCipher = InitCipher(false, aeadParameters);

            CheckTestCase(encCipher, decCipher, testName, macLengthBytes, P, C);
            CheckTestCase(encCipher, decCipher, testName + " (reused)", macLengthBytes, P, C);

            // TODO Key reuse
        }

        private OcbBlockCipher InitCipher(bool forEncryption, AeadParameters parameters)
        {
            OcbBlockCipher c = new OcbBlockCipher(new AesFastEngine(), new AesFastEngine());
            c.Init(forEncryption, parameters);
            return c;
        }

        private void CheckTestCase(OcbBlockCipher encCipher, OcbBlockCipher decCipher, string testName,
            int macLengthBytes, byte[] P, byte[] C)
        {
            byte[] tag = Arrays.Copy(C, C.Length - macLengthBytes, macLengthBytes);

            {
                byte[] enc = new byte[encCipher.GetOutputSize(P.Length)];
                int len = encCipher.ProcessBytes(P, 0, P.Length, enc, 0);
                len += encCipher.DoFinal(enc, len);

                if (enc.Length != len)
                {
                    Fail("encryption reported incorrect length: " + testName);
                }

                if (!AreEqual(C, enc))
                {
                    Fail("incorrect encrypt in: " + testName);
                }

                if (!AreEqual(tag, encCipher.GetMac()))
                {
                    Fail("getMac() not the same as the appended tag: " + testName);
                }
            }

            {
                byte[] dec = new byte[decCipher.GetOutputSize(C.Length)];
                int len = decCipher.ProcessBytes(C, 0, C.Length, dec, 0);
                len += decCipher.DoFinal(dec, len);

                if (dec.Length != len)
                {
                    Fail("decryption reported incorrect length: " + testName);
                }

                if (!AreEqual(P, dec))
                {
                    Fail("incorrect decrypt in: " + testName);
                }

                if (!AreEqual(tag, decCipher.GetMac()))
                {
                    Fail("getMac() not the same as the appended tag: " + testName);
                }
            }
        }

        private void RunLongerTestCase(int aesKeySize, int tagLen, byte[] expectedOutput)
        {
            KeyParameter key = new KeyParameter(new byte[aesKeySize / 8]);
            byte[] N = new byte[12];

            IAeadBlockCipher c1 = new OcbBlockCipher(new AesFastEngine(), new AesFastEngine());
            c1.Init(true, new AeadParameters(key, tagLen, N));

            IAeadBlockCipher c2 = new OcbBlockCipher(new AesFastEngine(), new AesFastEngine());

            long total = 0;

            byte[] S = new byte[128];

            for (int i = 0; i < 128; ++i)
            {
                N[11] = (byte) i;

                c2.Init(true, new AeadParameters(key, tagLen, N));

                total += UpdateCiphers(c1, c2, S, i, true, true);
                total += UpdateCiphers(c1, c2, S, i, false, true);
                total += UpdateCiphers(c1, c2, S, i, true, false);
            }

            long expectedTotal = 16256 + (48 * tagLen);

            if (total != expectedTotal)
            {
                Fail("test generated the wrong amount of input: " + total);
            }

            byte[] output = new byte[c1.GetOutputSize(0)];
            c1.DoFinal(output, 0);

            if (!AreEqual(expectedOutput, output))
            {
                Fail("incorrect encrypt in long-form test");
            }
        }

        private int UpdateCiphers(IAeadBlockCipher c1, IAeadBlockCipher c2, byte[] S, int i,
            bool includeAAD, bool includePlaintext)
        {
            int inputLen = includePlaintext ? i : 0;
            int outputLen = c2.GetOutputSize(inputLen);

            byte[] output = new byte[outputLen];

            int len = 0;

            if (includeAAD) {
                c2.ProcessAadBytes(S, 0, i);
            }

            if (includePlaintext) {
                len += c2.ProcessBytes(S, 0, i, output, len);
            }

            len += c2.DoFinal(output, len);

            c1.ProcessAadBytes(output, 0, len);

            return len;
        }

        public static void Main(
            string[] args)
        {
            RunTest(new OcbTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
