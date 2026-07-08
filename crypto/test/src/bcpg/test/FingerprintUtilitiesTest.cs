using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.Tests
{
    [TestFixture]
    public class FingerprintUtilitiesTest
    {
        [Test]
        public void KeyIdFromTooShortFails()
        {
            byte[] decoded = new byte[1];
            try
            {
                FingerprintUtilities.KeyIDFromV4Fingerprint(decoded);
                Assert.Fail("Expected exception");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        [Test]
        public void V4KeyIdFromFingerprint()
        {
            string fingerprint = "1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E";
            byte[] decoded = Hex.Decode(fingerprint);
            Assert.AreEqual(-5425419407118114754L, FingerprintUtilities.KeyIDFromV4Fingerprint(decoded),
                "v4 key-id from fingerprint mismatch");
        }

        [Test]
        public void V6KeyIdFromFingerprint()
        {
            string fingerprint = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
            byte[] decoded = Hex.Decode(fingerprint);
            Assert.AreEqual(-3812177997909612905L, FingerprintUtilities.KeyIDFromV6Fingerprint(decoded),
                "v6 key-id from fingerprint mismatch");
        }

        [Test]
        public void LibrePgpKeyIdFromFingerprint()
        {
            // v6 key-ids are derived from fingerprints the same way as LibrePGP does
            string fingerprint = "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9";
            byte[] decoded = Hex.Decode(fingerprint);
            Assert.AreEqual(-3812177997909612905L, FingerprintUtilities.KeyIDFromLibrePgpFingerprint(decoded),
                "LibrePGP key-id from fingerprint mismatch");
        }

        [Test]
        public void KeyIdFromFingerprint()
        {
            Assert.AreEqual(-5425419407118114754L,
                FingerprintUtilities.KeyIDFromFingerprint(4, Hex.Decode("1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E")),
                "v4 key-id from fingerprint mismatch");
            Assert.AreEqual(-3812177997909612905L,
                FingerprintUtilities.KeyIDFromFingerprint(5,
                    Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")),
                "v5 key-id from fingerprint mismatch");
            Assert.AreEqual(-3812177997909612905L,
                FingerprintUtilities.KeyIDFromFingerprint(6,
                    Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")),
                "v6 key-id from fingerprint mismatch");
        }

        [Test]
        public void LeftMostEqualsRightMostFor8Bytes()
        {
            byte[] bytes = new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            Assert.AreEqual(
                FingerprintUtilities.LongFromLeftMostBytes(bytes),
                FingerprintUtilities.LongFromRightMostBytes(bytes));
            byte[] b = new byte[8];
            FingerprintUtilities.WriteKeyID(FingerprintUtilities.LongFromLeftMostBytes(bytes), b, 0);
            Assert.That(Arrays.AreEqual(bytes, b));
        }

        [Test]
        public void WriteKeyIdToBytes()
        {
            byte[] bytes = new byte[12];
            long keyId = 72623859790382856L;
            FingerprintUtilities.WriteKeyID(keyId, bytes, 2);
            Assert.That(
                Arrays.AreEqual(new byte[]{ 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00 },
                    bytes));

            try
            {
                byte[] b = new byte[7];
                FingerprintUtilities.WriteKeyID(0, b, 0);
                Assert.Fail("Expected ArgumentException for too short byte array.");
            }
            catch (ArgumentException)
            {
                // Expected
            }
        }

        // TODO[pgp] Implement PrettifyFingerprint method
        //[Test]
        //public void PrettifyFingerprint()
        //{
        //    Assert.AreEqual("1D01 8C77 2DF8 C5EF 86A1  DCC9 B4B5 09CB 5936 E03E",
        //        FingerprintUtilities.PrettifyFingerprint(Hex.Decode("1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E")),
        //        "Prettified v4 fingerprint mismatch");
        //    Assert.AreEqual("CB186C4F 0609A697 E4D52DFA 6C722B0C  1F1E27C1 8A56708F 6525EC27 BAD9ACC9",
        //        FingerprintUtilities.PrettifyFingerprint(Hex.Decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")),
        //        "Prettified v5/v6 fingerprint mismatch");
        //}

        // TODO[pgp] Implement PrettifyFingerprint method
        //[Test]
        //public void PrettifyFingerprintReturnsHexForUnknownFormat()
        //{
        //    string fp = "C0FFEE1DECAFF0";
        //    Assert.AreEqual(fp, FingerprintUtilities.PrettifyFingerprint(Hex.Decode(fp)),
        //        "Prettifying fingerprint with unknown format MUST return uppercase hex fingerprint");
        //}
    }
}
