using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// SipHash test values from "SipHash: a fast short-input PRF", by Jean-Philippe
    /// Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf), Appendix A.
    /// </summary>
    [TestFixture]
    public class SipHashTest
        : SimpleTest
    {
        public override string Name
        {
            get { return "SipHash"; }
        }

        public override void PerformTest()
        {
            byte[] key = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] input = Hex.Decode("000102030405060708090a0b0c0d0e");

            long expected = unchecked((long)0xa129ca6149be45e5);

            SipHash mac = new SipHash();
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(input, 0, input.Length);

            long result = mac.DoFinal();
            if (expected != result)
            {
                Fail("Result does not match expected value for DoFinal()");
            }

            // NOTE: Little-endian representation of 0xa129ca6149be45e5
            byte[] expectedBytes = Hex.Decode("e545be4961ca29a1");

            mac.BlockUpdate(input, 0, input.Length);

            byte[] output = new byte[mac.GetMacSize()];
            int len = mac.DoFinal(output, 0);
            if (len != output.Length)
            {
                Fail("Result length does not equal GetMacSize() for DoFinal(byte[],int)");
            }
            if (!AreEqual(expectedBytes, output))
            {
                Fail("Result does not match expected value for DoFinal(byte[],int)");
            }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new SipHashTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
