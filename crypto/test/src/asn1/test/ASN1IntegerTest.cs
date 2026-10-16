using System;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class Asn1IntegerTest
    {
        private static readonly byte[] suspectKey = Base64.Decode(
            "MIGJAoGBAHNc+iExm94LUrJdPSJ4QJ9tDRuvaNmGVHpJ4X7a5zKI02v+2E7RotuiR2MHDJfVJkb9LUs2kb3XBlyENhtMLsbeH+3Muy3" +
            "hGDlh/mLJSh1s4c5jDKBRYOHom7Uc8wP0P2+zBCA+OEdikNDFBaP5PbR2Xq9okG2kPh35M2quAiMTAgMBAAE=");

        [Test]
        public void Basic()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, true.ToString(), () =>
            {
                Asn1Sequence.GetInstance(suspectKey);

                new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));
                new DerEnumerated(Hex.Decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));
                new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));
            });

            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, false.ToString(), () =>
            {
                try
                {
                    new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));
                    Assert.Fail("no exception");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }

                try
                {
                    Asn1Sequence.GetInstance(suspectKey);
                    Assert.Fail("no exception");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException("test 1", e, "failed to construct sequence from byte[]");
                }

                try
                {
                    new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));
                    Assert.Fail("no exception");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }

                try
                {
                    new DerEnumerated(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));
                    Assert.Fail("no exception");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed enumerated");
                }

                try
                {
                    new DerEnumerated(Hex.Decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));
                    Assert.Fail("no exception");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed enumerated");
                }
            });
        }

        [Test]
        public void InvalidEncoding_00()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, false.ToString(), () =>
            {
                try
                {
                    byte[] rawInt = Hex.Decode("0010FF");
                    DerInteger i = new DerInteger(rawInt);
                    CheckIntValue(i, 4351);
                    Assert.Fail("Expecting illegal argument exception.");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }
            });
        }

        [Test]
        public void InvalidEncoding_00_32bits()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, false.ToString(), () =>
            {
                //
                // Check what would pass loose validation fails outside of loose validation.
                //
                try
                {
                    byte[] rawInt = Hex.Decode("0000000010FF");
                    new DerInteger(rawInt);
                    Assert.Fail("Expecting illegal argument exception.");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }
            });
        }

        [Test]
        public void InvalidEncoding_FF()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, false.ToString(), () =>
            {
                try
                {
                    byte[] rawInt = Hex.Decode("FF81FF");
                    new DerInteger(rawInt);
                    Assert.Fail("Expecting illegal argument exception.");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }
            });
        }

        [Test]
        public void InvalidEncoding_FF_32bits()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, false.ToString(), () =>
            {
                //
                // Check what would pass loose validation fails outside of loose validation.
                //
                try
                {
                    byte[] rawInt = Hex.Decode("FFFFFFFF01FF");
                    new DerInteger(rawInt);
                    Assert.Fail("Expecting illegal argument exception.");
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }
            });
        }

        [Test]
        public void LooseValidEncoding_00_32BAligned()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, true.ToString(), () =>
            {
                //
                // Should pass as loose validation permits 3 leading 0x00 bytes.
                //
                byte[] rawInt = Hex.Decode("00000010FF000000");
                DerInteger i = new DerInteger(rawInt);
                CheckLongValue(i, 72997666816L);
            });
        }

        [Test]
        public void LooseValidEncoding_FF_32BAligned()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, true.ToString(), () =>
            {
                //
                // Should pass as loose validation permits 3 leading 0xFF bytes
                //
                byte[] rawInt = Hex.Decode("FFFFFF10FF000000");
                DerInteger i = new DerInteger(rawInt);
                CheckLongValue(i, -1026513960960L);
            });
        }

        [Test]
        public void LooseValidEncoding_FF_32BAligned_1not0()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, true.ToString(), () =>
            {
                //
                // Should pass as loose validation permits 3 leading 0xFF bytes.
                //
                byte[] rawInt = Hex.Decode("FFFEFF10FF000000");
                DerInteger i = new DerInteger(rawInt);
                CheckLongValue(i, -282501490671616L);
            });
        }

        [Test]
        public void LooseValidEncoding_FF_32BAligned_2not0()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, true.ToString(), () =>
            {
                //
                // Should pass as loose validation permits 3 leading 0xFF bytes.
                //
                byte[] rawInt = Hex.Decode("FFFFFE10FF000000");
                DerInteger i = new DerInteger(rawInt);
                CheckLongValue(i, -2126025588736L);
            });
        }

        [Test]
        public void OversizedEncoding()
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, true.ToString(), () =>
            {
                //
                // Should pass as loose validation permits 3 leading 0xFF bytes.
                //
                byte[] rawInt = Hex.Decode("FFFFFFFE10FF000000000000");
                DerInteger i = new DerInteger(rawInt);
                Assert.AreEqual(new BigInteger(Hex.Decode("FFFFFFFE10FF000000000000")), i.Value);

                rawInt = Hex.Decode("FFFFFFFFFE10FF000000000000");
                try
                {
                    new DerInteger(rawInt);
                }
                catch (ArgumentException e)
                {
                    CheckArgumentException(e, "malformed integer");
                }
            });
        }

        [Test]
        public void ValidEncodingMultiByte()
        {
            CheckValidEncodingMultiByte(false);
            CheckValidEncodingMultiByte(true);
        }

        [Test]
        public void ValidEncodingSingleByte()
        {
            CheckValidEncodingSingleByte(false);
            CheckValidEncodingSingleByte(true);
        }

        private void CheckValidEncodingMultiByte(bool allowUnsafe)
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, allowUnsafe.ToString(), () =>
            {
                byte[] rawInt = Hex.Decode("10FF");
                DerInteger i = new DerInteger(rawInt);
                CheckIntValue(i, 4351);
            });
        }

        private void CheckValidEncodingSingleByte(bool allowUnsafe)
        {
            Properties.WithThreadProperty(Properties.Asn1AllowUnsafeInteger, allowUnsafe.ToString(), () =>
            {
                byte[] rawInt = Hex.Decode("10");
                DerInteger i = new DerInteger(rawInt);
                CheckIntValue(i, 16);
            });
        }

        private static void CheckArgumentException(ArgumentException e, string expectedMessage) =>
            Assert.True(e.Message.StartsWith(expectedMessage));

        private static void CheckArgumentException(string errorText, ArgumentException e, string expectedMessage) =>
            Assert.True(e.Message.StartsWith(expectedMessage), errorText);

        private static void CheckIntValue(DerInteger i, int n)
        {
            BigInteger val = i.Value;
            Assert.AreEqual(val.IntValue, n);
            Assert.AreEqual(val.IntValueExact, n);
            Assert.AreEqual(i.IntValueExact, n);
            Assert.True(i.HasValue(n));
        }

        private static void CheckLongValue(DerInteger i, long n)
        {
            BigInteger val = i.Value;
            Assert.AreEqual(val.LongValue, n);
            Assert.AreEqual(val.LongValueExact, n);
            Assert.AreEqual(i.LongValueExact, n);
            Assert.True(i.HasValue(n));
        }
    }
}
