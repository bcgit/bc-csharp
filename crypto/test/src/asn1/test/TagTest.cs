using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	/**
	* X.690 test example
	*/
	[TestFixture]
	public class TagTest
		: SimpleTest
	{
		private static readonly byte[] longTagged = Base64.Decode(
			  "ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz"
			+ "A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF"
			+ "kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE"
			+ "RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY"
			+ "GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV"
			+ "FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka"
			+ "lAg=");

		private static readonly byte[] longAppSpecificTag = Hex.Decode("5F610101");

        private static readonly byte[] taggedInteger = Hex.Decode("BF2203020101");

		public override string Name
		{
			get { return "Tag"; }
		}

		public override void PerformTest()
		{
            Asn1InputStream aIn = new Asn1InputStream(longTagged);

			Asn1TaggedObject app = (Asn1TaggedObject)aIn.ReadObject();
			if (!app.HasTag(Asn1Tags.Application, 5))
			{
				Fail("unexpected tag value found - not 5");
			}

			app = app.GetExplicitBaseTagged();
			if (!app.HasTag(Asn1Tags.Application, 19))
			{
				Fail("unexpected tag value found - not 19");
			}

			Asn1Sequence seq = (Asn1Sequence)app.GetBaseUniversal(false, Asn1Tags.Sequence);

			Asn1TaggedObject tagged = (Asn1TaggedObject)seq[0];
			if (!tagged.HasContextTag(32))
			{
				Fail("unexpected tag value found - not 32");
			}

            tagged = (Asn1TaggedObject)Asn1Object.FromByteArray(tagged.GetEncoded());
			if (!tagged.HasContextTag(32))
			{
				Fail("unexpected tag value found on recode - not 32");
			}

			tagged = (Asn1TaggedObject)seq[1];
			if (!tagged.HasContextTag(33))
			{
				Fail("unexpected tag value found - not 33");
			}

			tagged = (Asn1TaggedObject) Asn1Object.FromByteArray(tagged.GetEncoded());
			if (!tagged.HasContextTag(33))
			{
				Fail("unexpected tag value found on recode - not 33");
			}

			aIn = new Asn1InputStream(longAppSpecificTag);

			app = (Asn1TaggedObject)aIn.ReadObject();
			if (!app.HasTag(Asn1Tags.Application, 97))
			{
				Fail("incorrect tag number read");
			}

			app = (Asn1TaggedObject)Asn1Object.FromByteArray(app.GetEncoded());
			if (!app.HasTag(Asn1Tags.Application, 97))
			{
				Fail("incorrect tag number read on recode");
			}

			SecureRandom sr = new SecureRandom();
			for (int i = 0; i < 100; ++i)
			{
				int testTag = (sr.NextInt() & int.MaxValue) >> sr.Next(26);
				app = new DerTaggedObject(false, Asn1Tags.Application, testTag, new DerOctetString(new byte[]{ 1 }));
				app = (Asn1TaggedObject)Asn1Object.FromByteArray(app.GetEncoded());

				if (!app.HasTag(Asn1Tags.Application, testTag))
				{
                    Fail("incorrect tag number read on recode (random test value: " + testTag + ")");
                }
			}

			tagged = new DerTaggedObject(false, 34, new DerTaggedObject(true, 1000, new DerInteger(1)));
            if (!AreEqual(taggedInteger, tagged.GetEncoded()))
            {
                Fail("incorrect encoding for implicit explicit tagged integer");
            }
        }

        public static void Main(
			string[] args)
		{
			RunTest(new TagTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
