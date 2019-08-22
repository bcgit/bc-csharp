using System;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class Asn1IntegerTest
        : SimpleTest
    {
        private static readonly byte[] suspectKey = Base64.Decode(
            "MIGJAoGBAHNc+iExm94LUrJdPSJ4QJ9tDRuvaNmGVHpJ4X7a5zKI02v+2E7RotuiR2MHDJfVJkb9LUs2kb3XBlyENhtMLsbeH+3Muy3" +
            "hGDlh/mLJSh1s4c5jDKBRYOHom7Uc8wP0P2+zBCA+OEdikNDFBaP5PbR2Xq9okG2kPh35M2quAiMTAgMBAAE=");

        public override string Name
        {
            get { return "Asn1Integer"; }
        }

        public override void PerformTest()
        {
#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || (PORTABLE && !DOTNET) || NET_1_1
            // Can't SetEnvironmentVariable !
#else
            SetAllowUnsafeProperty(true);

            Asn1Sequence.GetInstance(suspectKey);

            DoTestValidEncodingSingleByte();
            DoTestValidEncodingMultiByte();
            DoTestInvalidEncoding_00();
            DoTestInvalidEncoding_ff();
            DoTestInvalidEncoding_00_32bits();
            DoTestInvalidEncoding_ff_32bits();
            //DoDoTestLooseInvalidValidEncoding_FF_32B();
            //DoTestLooseInvalidValidEncoding_zero_32B();
            DoTestLooseValidEncoding_zero_32BAligned();
            DoTestLooseValidEncoding_FF_32BAligned();
            DoTestLooseValidEncoding_FF_32BAligned_1not0();
            DoTestLooseValidEncoding_FF_32BAligned_2not0();
            DoTestOversizedEncoding();

            SetAllowUnsafeProperty(true);

            new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            new DerEnumerated(Hex.Decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            SetAllowUnsafeProperty(false);

            try
            {
                new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));

                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed integer"));
            }

            // No support for thread-local override in C# version
            //IsTrue(!Properties.SetThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer", true));

            //new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));

            //IsTrue(Properties.RemoveThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer"));

            try
            {
                Asn1Sequence.GetInstance(suspectKey);

                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsEquals("test 1", "failed to construct sequence from byte[]: corrupted stream detected", e.Message);
            }

            try
            {
                new DerInteger(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed integer"));
            }

            try
            {
                new DerEnumerated(Hex.Decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed enumerated"));
            }

            try
            {
                new DerEnumerated(Hex.Decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed enumerated"));
            }
#endif
        }

        /**
         * Ensure existing single byte behavior.
         */
        public void DoTestValidEncodingSingleByte()
        {
            SetAllowUnsafeProperty(false);

            //
            // Without property, single byte.
            //
            byte[] rawInt = Hex.Decode("10");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(i.Value.IntValue, 16);

            //
            // With property set.
            //
            SetAllowUnsafeProperty(true);

            rawInt = Hex.Decode("10");
            i = new DerInteger(rawInt);
            IsEquals(i.Value.IntValue, 16);
        }

        public void DoTestValidEncodingMultiByte()
        {
            SetAllowUnsafeProperty(false);

            //
            // Without property, multi-byte.
            //
            byte[] rawInt = Hex.Decode("10FF");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(i.Value.IntValue, 4351);

            //
            // With property set.
            //
            SetAllowUnsafeProperty(true);

            rawInt = Hex.Decode("10FF");
            i = new DerInteger(rawInt);
            IsEquals(i.Value.IntValue, 4351);
        }

        public void DoTestInvalidEncoding_00()
        {
            SetAllowUnsafeProperty(false);
            try
            {
                byte[] rawInt = Hex.Decode("0010FF");
                DerInteger i = new DerInteger(rawInt);
                IsEquals(i.Value.IntValue, 4351);
                Fail("Expecting illegal argument exception.");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed integer"));
            }
        }

        public void DoTestInvalidEncoding_ff()
        {
            SetAllowUnsafeProperty(false);

            try
            {
                byte[] rawInt = Hex.Decode("FF81FF");
                new DerInteger(rawInt);
                Fail("Expecting illegal argument exception.");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed integer"));
            }
        }

        public void DoTestInvalidEncoding_00_32bits()
        {
            SetAllowUnsafeProperty(false);

            //
            // Check what would pass loose validation fails outside of loose validation.
            //
            try
            {
                byte[] rawInt = Hex.Decode("0000000010FF");
                DerInteger i = new DerInteger(rawInt);
                IsEquals(i.Value.IntValue, 4351);
                Fail("Expecting illegal argument exception.");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed integer"));
            }
        }

        public void DoTestInvalidEncoding_ff_32bits()
        {
            SetAllowUnsafeProperty(false);

            //
            // Check what would pass loose validation fails outside of loose validation.
            //
            try
            {
                byte[] rawInt = Hex.Decode("FFFFFFFF01FF");
                new DerInteger(rawInt);
                Fail("Expecting illegal argument exception.");
            }
            catch (ArgumentException e)
            {
                IsTrue(e.Message.StartsWith("malformed integer"));
            }
        }

        /*
         Unfortunately it turns out that integers stored without sign bits that are assumed to be
         unsigned.. this means a string of FF may occur and then the user will call getPositiveValue().
         Sigh..
        public void DoTestLooseInvalidValidEncoding_zero_32B()
            throws Exception
        {
            //
            // Should still fail as loose validation only permits 3 leading 0x00 bytes.
            //
            try
            {
                SetAllowUnsafeProperty(true);
                byte[] rawInt = Hex.Decode("0000000010FF");
                new DerInteger(rawInt);
                Fail("Expecting illegal argument exception.");
            }
            catch (ArgumentException e)
            {
                IsEquals("malformed integer", e.Message);
            }
        }

        public void DoDoTestLooseInvalidValidEncoding_FF_32B()
            throws Exception
        {
            //
            // Should still fail as loose validation only permits 3 leading 0xFF bytes.
            //
            try
            {
                SetAllowUnsafeProperty(true);
                byte[] rawInt = Hex.Decode("FFFFFFFF10FF");
                new DerInteger(rawInt);
                Fail("Expecting illegal argument exception.");
            }
            catch (ArgumentException e)
            {
                IsEquals("malformed integer", e.Message);
            }
        }
        */

        public void DoTestLooseValidEncoding_zero_32BAligned()
        {
            //
            // Should pass as loose validation permits 3 leading 0x00 bytes.
            //
            SetAllowUnsafeProperty(true);
            byte[] rawInt = Hex.Decode("00000010FF000000");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(72997666816L, i.Value.LongValue);
        }

        public void DoTestLooseValidEncoding_FF_32BAligned()
        {
            //
            // Should pass as loose validation permits 3 leading 0xFF bytes
            //
            SetAllowUnsafeProperty(true);
            byte[] rawInt = Hex.Decode("FFFFFF10FF000000");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(-1026513960960L, i.Value.LongValue);
        }

        public void DoTestLooseValidEncoding_FF_32BAligned_1not0()
        {
            //
            // Should pass as loose validation permits 3 leading 0xFF bytes.
            //
            SetAllowUnsafeProperty(true);
            byte[] rawInt = Hex.Decode("FFFEFF10FF000000");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(-282501490671616L, i.Value.LongValue);
        }

        public void DoTestLooseValidEncoding_FF_32BAligned_2not0()
        {
            //
            // Should pass as loose validation permits 3 leading 0xFF bytes.
            //
            SetAllowUnsafeProperty(true);
            byte[] rawInt = Hex.Decode("FFFFFE10FF000000");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(-2126025588736L, i.Value.LongValue);
        }

        public void DoTestOversizedEncoding()
        {
            //
            // Should pass as loose validation permits 3 leading 0xFF bytes.
            //
            SetAllowUnsafeProperty(true);
            byte[] rawInt = Hex.Decode("FFFFFFFE10FF000000000000");
            DerInteger i = new DerInteger(rawInt);
            IsEquals(new BigInteger(Hex.Decode("FFFFFFFE10FF000000000000")), i.Value);

            rawInt = Hex.Decode("FFFFFFFFFE10FF000000000000");
            try
            {
                new DerInteger(rawInt);
            }
            catch (ArgumentException e)
            {
                IsEquals("malformed integer", e.Message);
            }
        }

        private void SetAllowUnsafeProperty(bool allowUnsafe)
        {
#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || (PORTABLE && !DOTNET) || NET_1_1
            // Can't SetEnvironmentVariable !
#else
            Environment.SetEnvironmentVariable(DerInteger.AllowUnsafeProperty, allowUnsafe ? "true" : "false");
#endif
        }

        public static void Main(
            string[] args)
        {
            RunTest(new Asn1IntegerTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
