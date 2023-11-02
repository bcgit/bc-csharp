using NUnit.Framework;

using Org.BouncyCastle.Asn1.Icao;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class CscaMasterListTest
        : SimpleTest
    {
		public override string Name => "CscaMasterList";

		public override void PerformTest()
        {
			byte[] input = SimpleTest.GetTestData("asn1.masterlist-content.data");
			CscaMasterList parsedList = CscaMasterList.GetInstance(Asn1Object.FromByteArray(input));

			IsEquals("Cert structure parsing failed: incorrect length", 3, parsedList.GetCertStructs().Length);

			byte[] output = parsedList.GetEncoded();
			FailIf("Encoding failed after parse", !AreEqual(input, output));
		}

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
