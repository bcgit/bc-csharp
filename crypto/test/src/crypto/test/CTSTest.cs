using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary> CTS tester</summary>
    [TestFixture]
    public class CtsTest
        : ITest
    {
        public string Name => "CTS";

        internal static byte[] in1 = Hex.Decode("4e6f7720697320746865207420");
        internal static byte[] in2 = Hex.Decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f0aaa");
        internal static byte[] out1 = Hex.Decode("9952f131588465033fa40e8a98");
        internal static byte[] out2 = Hex.Decode("358f84d01eb42988dc34efb994");
        internal static byte[] out3 = Hex.Decode("170171cfad3f04530c509b0c1f0be0aefbd45a8e3755a873bff5ea198504b71683c6");

        private class CtsTester
            : ITest
        {
            private readonly CtsTest enclosingInstance;
            private readonly int id;
            private readonly IBlockCipher cipher;
            private readonly ICipherParameters parameters;
            private readonly byte[] input;
            private readonly byte[] output;

            internal CtsTester(CtsTest enclosingInstance, int id, IBlockCipher cipher, ICipherParameters parameters,
                byte[] input, byte[] output)
            {
                this.enclosingInstance = enclosingInstance;
                this.id = id;
                this.cipher = cipher;
                this.parameters = parameters;
                this.input = input;
                this.output = output;
            }

            public CtsTest Enclosing_Instance => enclosingInstance;

            public string Name => "CTS";

            public virtual ITestResult Perform()
            {
                byte[] outBytes = new byte[input.Length];
                BufferedBlockCipher engine = new CtsBlockCipher(cipher);

                engine.Init(true, parameters);

                int len = engine.ProcessBytes(input, 0, input.Length, outBytes, 0);

                try
                {
                    engine.DoFinal(outBytes, len);
                }
                catch (Exception e)
                {
                    return new SimpleTestResult(false, Name + ": encryption exception - " + e.ToString());
                }

                for (int i = 0; i != output.Length; i++)
                {
                    if (outBytes[i] != output[i])
                    {
                        return new SimpleTestResult(false, Name + ": failed encryption expected "
							+ Hex.ToHexString(output) + " got " + Hex.ToHexString(outBytes));
                    }
                }

                engine.Init(false, parameters);

                len = engine.ProcessBytes(output, 0, output.Length, outBytes, 0);

                try
                {
                    engine.DoFinal(outBytes, len);
                }
                catch (Exception e)
                {
                    return new SimpleTestResult(false, Name + ": decryption exception - " + e.ToString());
                }

                for (int i = 0; i != input.Length; i++)
                {
                    if (outBytes[i] != input[i])
                    {
                        return new SimpleTestResult(false, Name + ": failed encryption expected "
							+ Hex.ToHexString(input) + " got " + Hex.ToHexString(outBytes));
                    }
                }

                return new SimpleTestResult(true, Name + ": Okay");
            }
        }

        public CtsTest()
        {
        }

        public virtual ITestResult Perform()
        {
            byte[] key1 = new byte[]{ (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF };
            byte[] key2 = new byte[]{ (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0xee, (byte)0xff };
            byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

            ITest test = new CtsTester(this, 1, new DesEngine(), new KeyParameter(key1), in1, out1);
            ITestResult result = test.Perform();

            if (!result.IsSuccessful())
                return result;

            test = new CtsTester(this, 2, new CbcBlockCipher(new DesEngine()), new ParametersWithIV(new KeyParameter(key1), iv), in1, out2);
            result = test.Perform();

            if (!result.IsSuccessful())
                return result;

            test = new CtsTester(this, 3, new CbcBlockCipher(new SkipjackEngine()), new ParametersWithIV(new KeyParameter(key2), iv), in2, out3);
            result = test.Perform();

            if (!result.IsSuccessful())
                return result;

            return new SimpleTestResult(true, Name + ": Okay");
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
