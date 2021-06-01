using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class ChaCha20Poly1305Test
        : SimpleTest
    {
        private static readonly string[][] TestVectors = new string[][]
        {
            new string[]
            {
                "Test Case 1",
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "4c616469657320616e642047656e746c"
                + "656d656e206f662074686520636c6173"
                + "73206f66202739393a20496620492063"
                + "6f756c64206f6666657220796f75206f"
                + "6e6c79206f6e652074697020666f7220"
                + "746865206675747572652c2073756e73"
                + "637265656e20776f756c642062652069"
                + "742e",
                "50515253c0c1c2c3c4c5c6c7",
                "070000004041424344454647",
                "d31a8d34648e60db7b86afbc53ef7ec2"
                + "a4aded51296e08fea9e2b5a736ee62d6"
                + "3dbea45e8ca9671282fafb69da92728b"
                + "1a71de0a9e060b2905d6a5b67ecd3b36"
                + "92ddbd7f2d778b8c9803aee328091b58"
                + "fab324e4fad675945585808b4831d7bc"
                + "3ff4def08e4b7a9de576d26586cec64b"
                + "6116",
                "1ae10b594f09e26a7e902ecbd0600691",
            },
        };

        public override string Name
        {
            get { return "ChaCha20Poly1305"; }
        }

        public override void PerformTest()
        {
            for (int i = 0; i < TestVectors.Length; ++i)
            {
                RunTestCase(TestVectors[i]);
            }

            OutputSizeTests();
            RandomTests();
            TestExceptions();
        }

        private void CheckTestCase(
            ChaCha20Poly1305    encCipher,
            ChaCha20Poly1305    decCipher,
            string              testName,
            byte[]              SA,
            byte[]              P,
            byte[]              C,
            byte[]              T)
        {
            byte[] enc = new byte[encCipher.GetOutputSize(P.Length)];
            if (SA != null)
            {
                encCipher.ProcessAadBytes(SA, 0, SA.Length);
            }
            int len = encCipher.ProcessBytes(P, 0, P.Length, enc, 0);
            len += encCipher.DoFinal(enc, len);

            if (enc.Length != len)
            {
                Fail("encryption reported incorrect length: " + testName);
            }

            byte[] mac = encCipher.GetMac();

            byte[] data = new byte[P.Length];
            Array.Copy(enc, 0, data, 0, data.Length);
            byte[] tail = new byte[enc.Length - P.Length];
            Array.Copy(enc, P.Length, tail, 0, tail.Length);

            if (!AreEqual(C, data))
            {
                Fail("incorrect encrypt in: " + testName);
            }

            if (!AreEqual(T, mac))
            {
                Fail("getMac() returned wrong mac in: " + testName);
            }

            if (!AreEqual(T, tail))
            {
                Fail("stream contained wrong mac in: " + testName);
            }

            byte[] dec = new byte[decCipher.GetOutputSize(enc.Length)];
            if (SA != null)
            {
                decCipher.ProcessAadBytes(SA, 0, SA.Length);
            }
            len = decCipher.ProcessBytes(enc, 0, enc.Length, dec, 0);
            len += decCipher.DoFinal(dec, len);
            mac = decCipher.GetMac();

            data = new byte[C.Length];
            Array.Copy(dec, 0, data, 0, data.Length);

            if (!AreEqual(P, data))
            {
                Fail("incorrect decrypt in: " + testName);
            }
        }

        private ChaCha20Poly1305 InitCipher(bool forEncryption, AeadParameters parameters)
        {
            ChaCha20Poly1305 c = new ChaCha20Poly1305();
            c.Init(forEncryption, parameters);
            return c;
        }

        private static int NextInt(SecureRandom rand, int n)
        {
            if ((n & -n) == n)  // i.e., n is a power of 2
            {
                return (int)(((uint)n * (ulong)((uint)rand.NextInt() >> 1)) >> 31);
            }

            int bits, value;
            do
            {
                bits = (int)((uint)rand.NextInt() >> 1);
                value = bits % n;
            }
            while (bits - value + (n - 1) < 0);

            return value;
        }

        private void OutputSizeTests()
        {
            byte[] K = new byte[32];
            byte[] A = null;
            byte[] N = new byte[12];

            AeadParameters parameters = new AeadParameters(new KeyParameter(K), 16 * 8, N, A);
            ChaCha20Poly1305 cipher = InitCipher(true, parameters);

            if (cipher.GetUpdateOutputSize(0) != 0)
            {
                Fail("incorrect getUpdateOutputSize for initial 0 bytes encryption");
            }

            if (cipher.GetOutputSize(0) != 16)
            {
                Fail("incorrect getOutputSize for initial 0 bytes encryption");
            }

            cipher.Init(false, parameters);

            if (cipher.GetUpdateOutputSize(0) != 0)
            {
                Fail("incorrect getUpdateOutputSize for initial 0 bytes decryption");
            }

            // NOTE: 0 bytes would be truncated data, but we want it to fail in the doFinal, not here
            if (cipher.GetOutputSize(0) != 0)
            {
                Fail("fragile getOutputSize for initial 0 bytes decryption");
            }

            if (cipher.GetOutputSize(16) != 0)
            {
                Fail("incorrect getOutputSize for initial MAC-size bytes decryption");
            }
        }

        private void RandomTests()
        {
            SecureRandom random = new SecureRandom();
            random.SetSeed(DateTimeUtilities.CurrentUnixMs());

            for (int i = 0; i < 100; ++i)
            {
                RandomTest(random);
            }
        }

        private void RandomTest(SecureRandom random)
        {
            int kLength = 32;
            byte[] K = new byte[kLength];
            random.NextBytes(K);

            int pHead = random.Next(256);
            int pLength = random.Next(65536);
            int pTail = random.Next(256);
            byte[] P = new byte[pHead + pLength + pTail];
            random.NextBytes(P);

            int aLength = random.Next(256);
            byte[] A = new byte[aLength];
            random.NextBytes(A);

            int saLength = random.Next(256);
            byte[] SA = new byte[saLength];
            random.NextBytes(SA);

            int nonceLength = 12;
            byte[] nonce = new byte[nonceLength];
            random.NextBytes(nonce);

            AeadParameters parameters = new AeadParameters(new KeyParameter(K), 16 * 8, nonce, A);
            ChaCha20Poly1305 cipher = InitCipher(true, parameters);

            int ctLength = cipher.GetOutputSize(pLength);
            byte[] C = new byte[saLength + ctLength];
            Array.Copy(SA, 0, C, 0, saLength);

            int split = NextInt(random, saLength + 1);
            cipher.ProcessAadBytes(C, 0, split);
            cipher.ProcessAadBytes(C, split, saLength - split);

            int predicted = cipher.GetUpdateOutputSize(pLength);
            int len = cipher.ProcessBytes(P, pHead, pLength, C, saLength);
            if (predicted != len)
            {
                Fail("encryption reported incorrect update length in randomised test");
            }

            len += cipher.DoFinal(C, saLength + len);
            if (ctLength != len)
            {
                Fail("encryption reported incorrect length in randomised test");
            }

            byte[] encT = cipher.GetMac();
            byte[] tail = new byte[ctLength - pLength];
            Array.Copy(C, saLength + pLength, tail, 0, tail.Length);

            if (!AreEqual(encT, tail))
            {
                Fail("stream contained wrong mac in randomised test");
            }

            cipher.Init(false, parameters);

            int decPHead = random.Next(256);
            int decPLength = cipher.GetOutputSize(ctLength);
            int decPTail = random.Next(256);
            byte[] decP = new byte[decPHead + decPLength + decPTail];

            split = NextInt(random, saLength + 1);
            cipher.ProcessAadBytes(C, 0, split);
            cipher.ProcessAadBytes(C, split, saLength - split);

            predicted = cipher.GetUpdateOutputSize(ctLength);
            len = cipher.ProcessBytes(C, saLength, ctLength, decP, decPHead);
            if (predicted != len)
            {
                Fail("decryption reported incorrect update length in randomised test");
            }

            len += cipher.DoFinal(decP, decPHead + len);

            if (!AreEqual(P, pHead, pHead + pLength, decP, decPHead, decPHead + decPLength))
            {
                Fail("incorrect decrypt in randomised test");
            }

            byte[] decT = cipher.GetMac();
            if (!AreEqual(encT, decT))
            {
                Fail("decryption produced different mac from encryption");
            }

            //
            // key reuse test
            //
            cipher.Init(false, AeadTestUtilities.ReuseKey(parameters));

            decPHead = random.Next(256);
            decPLength = cipher.GetOutputSize(ctLength);
            decPTail = random.Next(256);
            decP = new byte[decPHead + decPLength + decPTail];

            split = NextInt(random, saLength + 1);
            cipher.ProcessAadBytes(C, 0, split);
            cipher.ProcessAadBytes(C, split, saLength - split);

            len = cipher.ProcessBytes(C, saLength, ctLength, decP, decPHead);
            len += cipher.DoFinal(decP, decPHead + len);

            if (!AreEqual(P, pHead, pHead + pLength, decP, decPHead, decPHead + decPLength))
            {
                Fail("incorrect decrypt in randomised test");
            }

            decT = cipher.GetMac();
            if (!AreEqual(encT, decT))
            {
                Fail("decryption produced different mac from encryption");
            }
        }

        private void RunTestCase(string[] testVector)
        {
            int pos = 0;
            string testName = testVector[pos++];
            byte[] K = Hex.DecodeStrict(testVector[pos++]);
            byte[] P = Hex.DecodeStrict(testVector[pos++]);
            byte[] A = Hex.DecodeStrict(testVector[pos++]);
            byte[] N = Hex.DecodeStrict(testVector[pos++]);
            byte[] C = Hex.DecodeStrict(testVector[pos++]);
            byte[] T = Hex.DecodeStrict(testVector[pos++]);

            RunTestCase(testName, K, N, A, P, C, T);
        }

        private void RunTestCase(
            string  testName,
            byte[]  K,
            byte[]  N,
            byte[]  A,
            byte[]  P,
            byte[]  C,
            byte[]  T)
        {
            byte[] fa = new byte[A.Length / 2];
            byte[] la = new byte[A.Length - (A.Length / 2)];
            Array.Copy(A, 0, fa, 0, fa.Length);
            Array.Copy(A, fa.Length, la, 0, la.Length);

            RunTestCase(testName + " all initial associated data", K, N, A, null, P, C, T);
            RunTestCase(testName + " all subsequent associated data", K, N, null, A, P, C, T);
            RunTestCase(testName + " split associated data", K, N, fa, la, P, C, T);
        }

        private void RunTestCase(
            string  testName,
            byte[]  K,
            byte[]  N,
            byte[]  A,
            byte[]  SA,
            byte[]  P,
            byte[]  C,
            byte[]  T)
        {
            AeadParameters parameters = new AeadParameters(new KeyParameter(K), T.Length * 8, N, A);
            ChaCha20Poly1305 encCipher = InitCipher(true, parameters);
            ChaCha20Poly1305 decCipher = InitCipher(false, parameters);
            CheckTestCase(encCipher, decCipher, testName, SA, P, C, T);
            encCipher = InitCipher(true, parameters);
            CheckTestCase(encCipher, decCipher, testName + " (reused)", SA, P, C, T);

            // Key reuse
            AeadParameters keyReuseParams = AeadTestUtilities.ReuseKey(parameters);

            try
            {
                encCipher.Init(true, keyReuseParams);
                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsTrue("wrong message", "cannot reuse nonce for ChaCha20Poly1305 encryption".Equals(e.Message));
            }
        }

        private void TestExceptions()
        {
            ChaCha20Poly1305 c = new ChaCha20Poly1305();

            try
            {
                c = new ChaCha20Poly1305(new SipHash());

                Fail("incorrect mac size not picked up");
            }
            catch (ArgumentException)
            {
                // expected
            }

            try
            {
                c.Init(false, new KeyParameter(new byte[32]));

                Fail("illegal argument not picked up");
            }
            catch (ArgumentException)
            {
                // expected
            }

            AeadTestUtilities.TestTampering(this, c, new AeadParameters(new KeyParameter(new byte[32]), 128, new byte[12]));

            byte[] P = Strings.ToByteArray("Hello world!");
            byte[] buf = new byte[100];

            c = new ChaCha20Poly1305();
            AeadParameters aeadParameters = new AeadParameters(new KeyParameter(new byte[32]), 128, new byte[12]);
            c.Init(true, aeadParameters);

            c.ProcessBytes(P, 0, P.Length, buf, 0);

            c.DoFinal(buf, 0);

            try
            {
                c.DoFinal(buf, 0);
                Fail("no exception on reuse");
            }
            catch (InvalidOperationException e)
            {
                IsTrue("wrong message", e.Message.Equals("ChaCha20Poly1305 cannot be reused for encryption"));
            }

            try
            {
                c.Init(true, aeadParameters);
                Fail("no exception on reuse");
            }
            catch (ArgumentException e)
            {
                IsTrue("wrong message", e.Message.Equals("cannot reuse nonce for ChaCha20Poly1305 encryption"));
            }
        }

        public static void Main(string[] args)
        {
            RunTest(new ChaCha20Poly1305Test());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
