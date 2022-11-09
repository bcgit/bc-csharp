using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class EqualsAndHashCodeTest
        : SimpleTest
    {
        public override void PerformTest()
        {
            byte[] data = { 0, 1, 0, 1, 0, 0, 1 };

			Asn1Object[] values =
			{
                new BerOctetString(data),
                new BerSequence(new DerPrintableString("hello world")),
                new BerSet(new DerPrintableString("hello world")),
                new BerTaggedObject(0, new DerPrintableString("hello world")),
                new DerBitString(data),
                new DerBmpString("hello world"),
                DerBoolean.True,
                DerBoolean.False,
                new DerEnumerated(100),
                new DerGeneralizedTime("20070315173729Z"),
                new DerGeneralString("hello world"),
                new DerIA5String("hello"),
                new DerInteger(1000),
                DerNull.Instance,
                new DerNumericString("123456"),
                new DerObjectIdentifier("1.1.1.10000.1"),
                new Asn1RelativeOid("3.2.0.123456"),
                new DerOctetString(data),
                new DerPrintableString("hello world"),
                new DerSequence(new DerPrintableString("hello world")),
                new DerSet(new DerPrintableString("hello world")),
                new DerT61String("hello world"),
                new DerTaggedObject(0, new DerPrintableString("hello world")),
                new DerUniversalString(data),
#pragma warning disable CS0618 // Type or member is obsolete
                new DerUtcTime(DateTime.Now),
#pragma warning restore CS0618 // Type or member is obsolete
                new DerUtcTime(DateTime.Now, 2049),
                new DerUtf8String("hello world"),
                new DerVisibleString("hello world"),
                new DerGraphicString(Hex.Decode("deadbeef")),
                new DerVideotexString(Strings.ToByteArray("Hello World"))
            };

			MemoryStream bOut = new MemoryStream();
            Asn1OutputStream aOut = Asn1OutputStream.Create(bOut);

            for (int i = 0; i != values.Length; i++)
            {
                aOut.WriteObject(values[i]);
            }

			Asn1InputStream aIn = new Asn1InputStream(bOut.ToArray());

			for (int i = 0; i != values.Length; i++)
            {
                Asn1Object o = aIn.ReadObject();
                if (!o.Equals(values[i]))
                {
                    Fail("Failed equality test for " + o.GetType().Name);
                }

                if (o.GetHashCode() != values[i].GetHashCode())
                {
                    Fail("Failed hashCode test for " + o.GetType().Name);
                }
            }
        }

		public override string Name
		{
			get { return "EqualsAndHashCode"; }
		}

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
