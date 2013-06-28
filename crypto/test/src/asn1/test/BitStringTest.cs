using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class BitStringTest
        : ITest
    {
        public ITestResult Perform()
        {
            KeyUsage k = new KeyUsage(KeyUsage.DigitalSignature);
            if ((k.GetBytes()[0] != (byte)KeyUsage.DigitalSignature) || (k.PadBits != 7))
            {
                return new SimpleTestResult(false, Name + ": failed digitalSignature");
            }

            k = new KeyUsage(KeyUsage.NonRepudiation);
            if ((k.GetBytes()[0] != (byte)KeyUsage.NonRepudiation) || (k.PadBits != 6))
            {
                return new SimpleTestResult(false, Name + ": failed nonRepudiation");
            }

            k = new KeyUsage(KeyUsage.KeyEncipherment);
            if ((k.GetBytes()[0] != (byte)KeyUsage.KeyEncipherment) || (k.PadBits != 5))
            {
                return new SimpleTestResult(false, Name + ": failed keyEncipherment");
            }

            k = new KeyUsage(KeyUsage.CrlSign);
            if ((k.GetBytes()[0] != (byte)KeyUsage.CrlSign)  || (k.PadBits != 1))
            {
                return new SimpleTestResult(false, Name + ": failed cRLSign");
            }

            k = new KeyUsage(KeyUsage.DecipherOnly);
            if ((k.GetBytes()[1] != (byte)(KeyUsage.DecipherOnly >> 8))  || (k.PadBits != 7))
            {
                return new SimpleTestResult(false, Name + ": failed decipherOnly");
            }

			// test for zero length bit string
			try
			{
				Asn1Object.FromByteArray(new DerBitString(new byte[0], 0).GetEncoded());
			}
			catch (IOException e)
			{
				return new SimpleTestResult(false, Name + ": " + e);
			}

            return new SimpleTestResult(true, Name + ": Okay");
        }

        public string Name
        {
			get { return "BitString"; }
        }

		public static void Main(
            string[] args)
        {
            ITest test = new BitStringTest();
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
