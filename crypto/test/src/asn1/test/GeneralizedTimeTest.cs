using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    /**
     * X.690 test example
     */
    [TestFixture]
    public class GeneralizedTimeTest
        : SimpleTest
    {
        private static readonly string[] input =
        {
            "20020122122220",
            "20020122122220Z",
            "20020122122220-1000",
            "20020122122220+00",
            "20020122122220.1",
            "20020122122220.1Z",
            "20020122122220.1-1000",
            "20020122122220.1+00",
            "20020122122220.01",
            "20020122122220.01Z",
            "20020122122220.01-1000",
            "20020122122220.01+00",
            "20020122122220.001",
            "20020122122220.001Z",
            "20020122122220.001-1000",
            "20020122122220.001+00",
            "20020122122220.0001",
            "20020122122220.0001Z",
            "20020122122220.0001-1000",
            "20020122122220.0001+00",
            "20020122122220.0001+1000"
        };

        private static readonly string[] mzOutput =
        {
            "20020122122220.000Z",
            "20020122122220.000Z",
            "20020122222220.000Z",
            "20020122122220.000Z",
            "20020122122220.100Z",
            "20020122122220.100Z",
            "20020122222220.100Z",
            "20020122122220.100Z",
            "20020122122220.010Z",
            "20020122122220.010Z",
            "20020122222220.010Z",
            "20020122122220.010Z",
            "20020122122220.001Z",
            "20020122122220.001Z",
            "20020122222220.001Z",
            "20020122122220.001Z",
            "20020122122220.000Z",
            "20020122122220.000Z",
            "20020122222220.000Z",
            "20020122122220.000Z",
            "20020122022220.000Z"
        };

        private static readonly string[] derMzOutput =
        {
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220.1Z",
            "20020122122220.1Z",
            "20020122222220.1Z",
            "20020122122220.1Z",
            "20020122122220.01Z",
            "20020122122220.01Z",
            "20020122222220.01Z",
            "20020122122220.01Z",
            "20020122122220.001Z",
            "20020122122220.001Z",
            "20020122222220.001Z",
            "20020122122220.001Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122022220Z"
        };

        private static readonly string[] truncOutput =
        {
            "200201221222Z",
            "2002012212Z"
        };

        private static readonly string[] derTruncOutput =
        {
            "20020122122200Z",
            "20020122120000Z"
        };

        public override string Name
        {
            get { return "GeneralizedTime"; }
        }

        public override void PerformTest()
        {
            for (int i = 0; i != input.Length; i++)
            {
                Asn1GeneralizedTime t = new Asn1GeneralizedTime(input[i]);

                if (!t.ToDateTime().ToString(@"yyyyMMddHHmmss.fff\Z").Equals(mzOutput[i]))
                {
                    Console.WriteLine("{0} != {1}", t.ToDateTime().ToString(@"yyyyMMddHHmmss.fff\Z"), mzOutput[i]);

                    Fail("failed long date conversion test " + i);
                }
            }

            for (int i = 0; i != mzOutput.Length; i++)
            {
                DerGeneralizedTime t = new DerGeneralizedTime(mzOutput[i]);

                if (!AreEqual(t.GetEncoded(), new Asn1GeneralizedTime(derMzOutput[i]).GetEncoded()))
                {
                    Fail("DER encoding wrong");
                }
            }

            for (int i = 0; i != truncOutput.Length; i++)
            {
                DerGeneralizedTime t = new DerGeneralizedTime(truncOutput[i]);

                if (!AreEqual(t.GetEncoded(), new Asn1GeneralizedTime(derTruncOutput[i]).GetEncoded()))
                {
                    Fail("trunc DER encoding wrong");
                }
            }

            {
                // check BER encoding is still "as given"
                Asn1GeneralizedTime ber = new Asn1GeneralizedTime("202208091215Z");

                IsTrue(Arrays.AreEqual(Hex.Decode("180d3230323230383039313231355a"), ber.GetEncoded(Asn1Encodable.DL)));
                IsTrue(Arrays.AreEqual(Hex.Decode("180d3230323230383039313231355a"), ber.GetEncoded(Asn1Encodable.Ber)));
                IsTrue(Arrays.AreEqual(Hex.Decode("180f32303232303830393132313530305a"), ber.GetEncoded(Asn1Encodable.Der)));

                // check always uses DER encoding
                DerGeneralizedTime der = new DerGeneralizedTime("202208091215Z");

                IsTrue(Arrays.AreEqual(Hex.Decode("180f32303232303830393132313530305a"), der.GetEncoded(Asn1Encodable.DL)));
                IsTrue(Arrays.AreEqual(Hex.Decode("180f32303232303830393132313530305a"), der.GetEncoded(Asn1Encodable.Ber)));
                IsTrue(Arrays.AreEqual(Hex.Decode("180f32303232303830393132313530305a"), der.GetEncoded(Asn1Encodable.Der)));
            }

            try
            {
                new DerGeneralizedTime(string.Empty);
                Fail("Expected exception");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("invalid date string"));
            }

            /*
             * [BMA-87]
             */
            {
                DateTime t1 = new DerUtcTime("110616114855Z").ToDateTime();
                DateTime t2 = new DerGeneralizedTime("20110616114855Z").ToDateTime();

                if (t1 != t2)
                {
                    Fail("failed UTC equivalence test");
                }

                DateTime u1 = t1.ToUniversalTime();
                DateTime u2 = t2.ToUniversalTime();

                if (u1 != u2)
                {
                    Fail("failed UTC conversion test");
                }
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
