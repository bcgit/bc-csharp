using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    class AesWrapPadTest : ITest
    {
        public string Name
        {
            get
            {
                return "AESWrapPad";
            }
        }

        private ITestResult WrapTest(
            int id,
            byte[] kek,
            byte[] inBytes,
            byte[] outBytes)
        {
            IWrapper wrapper = new AesWrapPadEngine();

            wrapper.Init(true, new KeyParameter(kek));

            try
            {
                byte[] cText = wrapper.Wrap(inBytes, 0, inBytes.Length);
                if (!Arrays.AreEqual(cText, outBytes))
                {
                    return new SimpleTestResult(false, Name + ": failed wrap test " + id
                        + " expected " + Hex.ToHexString(outBytes)
                        + " got " + Hex.ToHexString(cText));
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, Name + ": failed wrap test exception " + e);
            }

            wrapper.Init(false, new KeyParameter(kek));

            try
            {
                byte[] pText = wrapper.Unwrap(outBytes, 0, outBytes.Length);
                if (!Arrays.AreEqual(pText, inBytes))
                {
                    return new SimpleTestResult(false, Name + ": failed unwrap test " + id
                        + " expected " + Hex.ToHexString(inBytes)
                        + " got " + Hex.ToHexString(pText));
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, Name + ": failed unwrap test exception.", e);
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

        public ITestResult Perform()
        {
            // Message length is divided by 8

            byte[] kek1 = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] in1 = Hex.Decode("00112233445566778899aabbccddeeff");
            byte[] out1 = Hex.Decode("2cef0c9e30de26016c230cb78bc60d51b1fe083ba0c79cd5");
            ITestResult result = WrapTest(1, kek1, in1, out1);

            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek2 = Hex.Decode("000102030405060708090a0b0c0d0e0f1011121314151617");
            byte[] in2 = Hex.Decode("00112233445566778899aabbccddeeff");
            byte[] out2 = Hex.Decode("5fd7477fdc165910c8e5dd891a421b10db10362fd293b128");
            result = WrapTest(2, kek2, in2, out2);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek3 = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] in3 = Hex.Decode("00112233445566778899aabbccddeeff");
            byte[] out3 = Hex.Decode("afc860015ffe2d75bedf43c444fe58f4ad9d89c4ec71e23b");
            result = WrapTest(3, kek3, in3, out3);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek4 = Hex.Decode("000102030405060708090a0b0c0d0e0f1011121314151617");
            byte[] in4 = Hex.Decode("00112233445566778899aabbccddeeff0001020304050607");
            byte[] out4 = Hex.Decode("39c3bf03c71e0d49bd968f26397b3855e5e89eaafd256edbc2f1d03f3266f3f4");
            result = WrapTest(4, kek4, in4, out4);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek5 = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] in5 = Hex.Decode("00112233445566778899aabbccddeeff0001020304050607");
            byte[] out5 = Hex.Decode("b9f05286f13fc80d1f8614a1acac931f293f66d7a3bb3811fb568f7108ec6210");
            result = WrapTest(5, kek5, in5, out5);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek6 = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] in6 = Hex.Decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
            byte[] out6 = Hex.Decode("4a8029243027353b0694cf1bd8fc745bb0ce8a739b19b1960b12426d4c39cfeda926d103ab34e9f6");
            result = WrapTest(6, kek6, in6, out6);
            if (!result.IsSuccessful())
            {
                return result;
            }

            // Message length is NOT divided by 8 (will be padded)

            byte[] kek7 = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] in7 = Hex.Decode("00112233");
            byte[] out7 = Hex.Decode("9475a703b9ed66e4898e8154e66273a7");
            result = WrapTest(7, kek7, in7, out7);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek8 = Hex.Decode("000102030405060708090a0b0c0d0e0f1011121314151617");
            byte[] in8 = Hex.Decode("00112233445566778899");
            byte[] out8 = Hex.Decode("62a641a96427fde579e81d6b9a9ea4fc9585d56736e3b74f");
            result = WrapTest(8, kek8, in8, out8);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek9 = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] in9 = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f001122334455");
            byte[] out9 = Hex.Decode("3b4d9aa29078180ccfe9c0b8b0775408a071ebf3d58842d8f14b26f55aa4e40e24d138b84023c7c24f2a065f853a59a5");
            result = WrapTest(9, kek9, in9, out9);
            if (!result.IsSuccessful())
            {
                return result;
            }

            // RFC 5649 test vectors
            byte[] kek10 = Hex.Decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
            byte[] in10 = Hex.Decode("c37b7e6492584340bed12207808941155068f738");
            byte[] out10 = Hex.Decode("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
            result = WrapTest(10, kek10, in10, out10);
            if (!result.IsSuccessful())
            {
                return result;
            }

            byte[] kek11 = Hex.Decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
            byte[] in11 = Hex.Decode("466f7250617369");
            byte[] out11 = Hex.Decode("afbeb0f07dfbf5419200f2ccb50bb24f");
            result = WrapTest(11, kek11, in11, out11);
            if (!result.IsSuccessful())
            {
                return result;
            }

            IWrapper wrapper = new AesWrapPadEngine();
            KeyParameter key = new KeyParameter(new byte[16]);
            byte[] buf = new byte[16];

            try
            {
                wrapper.Init(true, key);

                wrapper.Unwrap(buf, 0, buf.Length);

                return new SimpleTestResult(false, Name + ": failed unwrap state test.");
            }
            catch (InvalidOperationException)
            {
                // expected
            }
            catch (InvalidCipherTextException e)
            {
                return new SimpleTestResult(false, Name + ": unexpected exception: " + e, e);
            }

            try
            {
                wrapper.Init(false, key);

                wrapper.Wrap(buf, 0, buf.Length);

                return new SimpleTestResult(false, Name + ": failed unwrap state test.");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            //
            // short test
            //
            try
            {
                wrapper.Init(false, key);

                wrapper.Unwrap(buf, 0, buf.Length / 2);

                return new SimpleTestResult(false, Name + ": failed unwrap short test.");
            }
            catch (InvalidCipherTextException)
            {
                // expected
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

        public static void Main()
        {
            var test = new AesWrapPadTest();
            ITestResult result = test.Perform();

            Console.WriteLine(result);
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
