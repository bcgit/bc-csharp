using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class MiscTest
        : ITest
    {
        public ITestResult Perform()
        {
            byte[] testIv = { 1, 2, 3, 4, 5, 6, 7, 8 };

            Asn1Encodable[] values =
            {
                new Cast5CbcParameters(testIv, 128),
                new NetscapeCertType(NetscapeCertType.Smime),
                new VerisignCzagExtension(new DerIA5String("hello")),
                new IdeaCbcPar(testIv),
                new NetscapeRevocationUrl(new DerIA5String("http://test"))
            };

            byte[] data = Base64.Decode("MA4ECAECAwQFBgcIAgIAgAMCBSAWBWhlbGxvMAoECAECAwQFBgcIFgtodHRwOi8vdGVzdA==");

            try
            {
                MemoryStream bOut = new MemoryStream();
                Asn1OutputStream aOut = new Asn1OutputStream(bOut);

                for (int i = 0; i != values.Length; i++)
                {
                    aOut.WriteObject(values[i]);
                }

                if (!Arrays.AreEqual(bOut.ToArray(), data))
                {
                    return new SimpleTestResult(false, Name + ": Failed data check");
                }

                Asn1InputStream aIn = new Asn1InputStream(bOut.ToArray());

                for (int i = 0; i != values.Length; i++)
                {
                    Asn1Object o = aIn.ReadObject();

                    if (!values[i].Equals(o))
                    {
                        return new SimpleTestResult(false, Name + ": Failed equality test for " + o);
                    }

                    if (o.GetHashCode() != values[i].GetHashCode())
                    {
                        return new SimpleTestResult(false, Name + ": Failed hashCode test for " + o);
                    }
                }

                return new SimpleTestResult(true, Name + ": Okay");
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, Name + ": Failed - exception " + e.ToString(), e);
            }
        }

        public string Name
        {
            get { return "Misc"; }
        }

        public static void Main(
            string[] args)
        {
            ITest test = new MiscTest();
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
