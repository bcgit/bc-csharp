using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class MiscTest
    {
        [Test]
        public void Basic()
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

            MemoryStream bOut = new MemoryStream();
            using (var asn1Out = Asn1OutputStream.Create(bOut))
            {
                for (int i = 0; i != values.Length; i++)
                {
                    asn1Out.WriteObject(values[i]);
                }
            }

            byte[] output = bOut.ToArray();
            Assert.That(Arrays.AreEqual(output, data), "Failed data check");

            using (var asn1In = new Asn1InputStream(output))
            {
                for (int i = 0; i != values.Length; i++)
                {
                    Asn1Object o = asn1In.ReadObject();
                    if (!values[i].Equals(o))
                    {
                        Assert.Fail("Failed equality test for " + o);
                    }
                    if (o.GetHashCode() != values[i].GetHashCode())
                    {
                        Assert.Fail("Failed hashCode test for " + o);
                    }
                }
            }
        }

        [Test]
        public void DerIntegerTest()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, false.ToString(), () =>
            {
                try
                {
                    new DerInteger(new byte[] { 0x00, 0x00, 0x00, 0x01 });
                    Assert.Fail("expected ArgumentException");
                }
                catch (ArgumentException e)
                {
                    Assert.True(e.Message.StartsWith("malformed integer"), "wrong exc 1: " + e.Message);
                }

                try
                {
                    new DerInteger(new byte[] { 0xFF, 0x80, 0x00, 0x01 });
                    Assert.Fail("expected ArgumentException");
                }
                catch (ArgumentException e)
                {
                    Assert.True(e.Message.StartsWith("malformed integer"), "wrong exc 2: " + e.Message);
                }

                try
                {
                    new DerEnumerated(new byte[] { 0x00, 0x00, 0x00, 0x01 });
                    Assert.Fail("expected ArgumentException");
                }
                catch (ArgumentException e)
                {
                    Assert.True(e.Message.StartsWith("malformed enumerated"), "wrong exc 3: " + e.Message);
                }

                try
                {
                    new DerEnumerated(new byte[] { 0xFF, 0x80, 0x00, 0x01 });
                    Assert.Fail("expected ArgumentException");
                }
                catch (ArgumentException e)
                {
                    Assert.True(e.Message.StartsWith("malformed enumerated"), "wrong exc 4: " + e.Message);
                }
            });
        }

        [Test]
        public void ShouldFailOnExtraData()
        {
            // basic construction
            DerBitString s1 = new DerBitString(new byte[0], 0);

            Asn1Object.FromByteArray(s1.GetEncoded());

            Asn1Object.FromByteArray(new BerSequence(s1).GetEncoded());

            try
            {
                Asn1Object obj = Asn1Object.FromByteArray(Arrays.Concatenate(s1.GetEncoded(), new byte[1]));
                Assert.Fail("no exception");
            }
            catch (IOException e)
            {
                //if (!"Extra data detected in stream".Equals(e.Message))
                if (!"extra data found after object".Equals(e.Message))
                {
                    Assert.Fail("wrong exception");
                }
            }
        }
    }
}
