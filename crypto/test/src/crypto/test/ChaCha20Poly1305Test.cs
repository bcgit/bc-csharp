using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * ChaCha Test
     * <p>
     * Test cases generated using ref version of ChaCha20Poly1305 in RFC8439.
     * </p>
     */
    [TestFixture]
    public class ChaCha20Poly1305Test
        : SimpleTest
    {
        private static readonly byte[] plaintext = Hex.Decode(
            "4c616469657320616e642047656e746c"
            + "656d656e206f662074686520636c6173"
            + "73206f66202739393a20496620492063"
            + "6f756c64206f6666657220796f75206f"
            + "6e6c79206f6e652074697020666f7220"
            + "746865206675747572652c2073756e73"
            + "637265656e20776f756c642062652069"
            + "742e");

        private static readonly byte[] aad = Hex.Decode(
            "50515253c0c1c2c3c4c5c6c7");

        private static readonly byte[] key = Hex.Decode(
            "808182838485868788898a8b8c8d8e8f"
            + "909192939495969798999a9b9c9d9e9f");

        private static readonly byte[] iv = Hex.Decode(
            "070000004041424344454647");

        public override string Name
        {
            get { return "ChaCha20Poly1305"; }
        }

        public override void PerformTest()
        {
            Test(plaintext, aad, key, iv);
        }

        private void Test(
            byte[] plaintext_,
            byte[] aad_,
            byte[] key_,
            byte[] iv_)
        {
            KeyParameter keyParam = new KeyParameter(key_);
            ParametersWithIV paramsWithIv = new ParametersWithIV(keyParam, iv_);

            ChaCha20Poly1305 encryptor = new ChaCha20Poly1305();
            encryptor.Init(true, paramsWithIv);

            encryptor.ProcessAadBytes(aad_, 0, aad_.Length);

            byte[] outBytes = new byte[encryptor.GetOutputSize(plaintext_.Length)];
            encryptor.ProcessBytes(plaintext_, 0, plaintext_.Length, outBytes, 0);

            encryptor.DoFinal(outBytes, 0);

            ChaCha20Poly1305 decryptor = new ChaCha20Poly1305();
            decryptor.Init(false, paramsWithIv);

            decryptor.ProcessAadBytes(aad_, 0, aad_.Length);

            byte[] calculatedPlaintext = new byte[decryptor.GetOutputSize(outBytes.Length)];
            decryptor.ProcessBytes(outBytes, 0, outBytes.Length, calculatedPlaintext, 0);

            decryptor.DoFinal(calculatedPlaintext, 0);

            if (!Arrays.ConstantTimeAreEqual(plaintext_, calculatedPlaintext))
            {
                Fail("ChaCha20Poly1305 encrypt / decrypt test failed");
            }

        }

        public static void Main(
            string[] args)
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
