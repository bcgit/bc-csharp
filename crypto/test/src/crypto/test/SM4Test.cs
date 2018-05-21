using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Tests
{
    /**
     * SM4 tester, vectors from <a href="http://eprint.iacr.org/2008/329.pdf">http://eprint.iacr.org/2008/329.pdf</a>
     */
    [TestFixture]
    public class SM4Test : CipherTest
    {
        internal static SimpleTest[] tests = {
        new BlockCipherVectorTest(0, new SM4Engine(),
            new KeyParameter(Hex.Decode("0123456789abcdeffedcba9876543210")),
            "0123456789abcdeffedcba9876543210",
            "681edf34d206965e86b3e94f536e4246")
            };

        public override string Name { get { return "SM4"; } }


        SM4Test()
            : base(tests, new SM4Engine(), new KeyParameter(new byte[16]))
        {
        }

        public override void PerformTest()
        {
            base.PerformTest();
            Test1000000();
        }

        private void Test1000000()
        {
            byte[] plain = Hex.Decode("0123456789abcdeffedcba9876543210");
            byte[] key = Hex.Decode("0123456789abcdeffedcba9876543210");
            byte[] cipher = Hex.Decode("595298c7c6fd271f0402f804c33d3f66");
            byte[] buf = new byte[16];

            IBlockCipher engine = new SM4Engine();

            engine.Init(true, new KeyParameter(key));

            Array.Copy(plain, 0, buf, 0, buf.Length);

            for (int i = 0; i != 1000000; i++)
            {
                engine.ProcessBlock(buf, 0, buf, 0);
            }

            if (!AreEqual(cipher, buf))
            {
                Fail("1000000 encryption test failed");
            }

            engine.Init(false, new KeyParameter(key));

            for (int i = 0; i != 1000000; i++)
            {
                engine.ProcessBlock(buf, 0, buf, 0);
            }

            if (!AreEqual(plain, buf))
            {
                Fail("1000000 decryption test failed");
            }
        }

        public String GetName()
        {
            return "SM4";
        }

        public static void Main(
            String[] args)
        {
            RunTest(new SM4Test());
        }
    }
}
