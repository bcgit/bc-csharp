using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class AriaTest
        : SimpleTest
    {
        private static readonly SecureRandom R = new SecureRandom();

        private static readonly string[][] TEST_VECTORS_RFC5794 = {
            new string[]{
                "128-Bit Key",
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff",
                "d718fbd6ab644c739da95f3be6451778"
            },
            new string[]{
                "192-Bit Key",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "00112233445566778899aabbccddeeff",
                "26449c1805dbe7aa25a468ce263a9e79"
            },
            new string[]{
                "256-Bit Key",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00112233445566778899aabbccddeeff",
                "f92bd7c79fb72e2f2b8f80c1972d24fc"
            },
        };

        public override string Name
        {
            get { return "ARIA"; }
        }

        public override void PerformTest()
        {
            CheckTestVectors_RFC5794();

            for (int i = 0; i < 100; ++i)
            {
                CheckRandomRoundtrips();
            }

            new MyAriaEngine().CheckImplementation();
        }

        private void CheckRandomRoundtrips()
        {
            AriaEngine ce = new AriaEngine();
            AriaEngine cd = new AriaEngine();

            byte[] txt = new byte[ce.GetBlockSize()];
            byte[] enc = new byte[ce.GetBlockSize()];
            byte[] dec = new byte[ce.GetBlockSize()];

            for (int keyLen = 16; keyLen <= 32; keyLen += 8)
            {
                byte[] K = new byte[keyLen];

                R.NextBytes(K);

                KeyParameter key = new KeyParameter(K);
                ce.Init(true, key);
                cd.Init(false, key);

                R.NextBytes(txt);

                for (int i = 0; i < 100; ++i)
                {
                    ce.ProcessBlock(txt, 0, enc, 0);
                    cd.ProcessBlock(enc, 0, dec, 0);

                    IsTrue(Arrays.AreEqual(txt, dec));

                    Array.Copy(enc, 0, txt, 0, enc.Length);
                }
            }
        }

        private void CheckTestVector_RFC5794(string[] tv)
        {
            string name = "'" + tv[0] + "'";

            IBlockCipher c = new AriaEngine();
            int blockSize = c.GetBlockSize();
            IsTrue("Wrong block size returned from getBlockSize() for " + name, 16 == blockSize);

            KeyParameter key = new KeyParameter(Hex.Decode(tv[1]));
            byte[] plaintext = Hex.Decode(tv[2]);
            byte[] ciphertext = Hex.Decode(tv[3]);

            IsTrue("Unexpected plaintext length for " + name, blockSize == plaintext.Length);
            IsTrue("Unexpected ciphertext length for " + name, blockSize == ciphertext.Length);

            c.Init(true, key);

            byte[] actual = new byte[blockSize];
            int num = c.ProcessBlock(plaintext, 0, actual, 0);

            IsTrue("Wrong length returned from processBlock() (encryption) for " + name, blockSize == num);
            IsTrue("Incorrect ciphertext computed for " + name, Arrays.AreEqual(ciphertext, actual));

            c.Init(false, key);
            num = c.ProcessBlock(ciphertext, 0, actual, 0);

            IsTrue("Wrong length returned from processBlock() (decryption) for " + name, blockSize == num);
            IsTrue("Incorrect plaintext computed for " + name, Arrays.AreEqual(plaintext, actual));
        }

        private void CheckTestVectors_RFC5794()
        {
            for (int i = 0; i < TEST_VECTORS_RFC5794.Length; ++i)
            {
                CheckTestVector_RFC5794(TEST_VECTORS_RFC5794[i]);
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        private class MyAriaEngine
            : AriaEngine
        {
            public void CheckImplementation()
            {
                CheckInvolution();
                CheckSBoxes();
            }

            private void CheckInvolution()
            {
                byte[] x = new byte[16], y = new byte[16];

                for (int i = 0; i < 100; ++i)
                {
                    R.NextBytes(x);
                    Array.Copy(x, 0, y, 0, 16);
                    A(y);
                    A(y);
                    Assert.IsTrue(Arrays.AreEqual(x, y));
                }
            }

            private void CheckSBoxes()
            {
                for (int i = 0; i < 256; ++i)
                {
                    byte x = (byte)i;

                    Assert.IsTrue(x == SB1(SB3(x)));
                    Assert.IsTrue(x == SB3(SB1(x)));

                    Assert.IsTrue(x == SB2(SB4(x)));
                    Assert.IsTrue(x == SB4(SB2(x)));
                }
            }
        }
    }
}
