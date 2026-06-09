using System;

using NUnit.Framework;

namespace Org.BouncyCastle.Asn1.Tests
{
    /// <summary>
    /// The bc-java version has a separate ASN1TimeFormat class for validating ASN.1 GeneralizedTime and UTCTime.
    /// The bc-csharp default validation already covers all these cases, so ASN1TimeFormat itself is not needed, but we
    /// include the bc-java test cases in this separate test class for ease of comparison/update w/ bc-java.
    /// </summary>
    [TestFixture]
    public class Asn1TimeFormatTest
    {
        [Test]
        public void ValidUtcTime()
        {
            // X.680 sec. 47: minutes mandatory, seconds optional, zone (Z or offset) mandatory.
            Assert.True(IsValidUtcTime("5001010000Z"));         // no seconds, Z
            Assert.True(IsValidUtcTime("500101000000Z"));       // seconds, Z
            Assert.True(IsValidUtcTime("5001010000+0500"));     // no seconds, offset
            Assert.True(IsValidUtcTime("5001010000+0530"));     // no seconds, offset
            Assert.True(IsValidUtcTime("500101000000-0830"));   // seconds, offset
            Assert.True(IsValidUtcTime("991231235959Z"));       // boundary fields
            Assert.True(IsValidUtcTime("000101120000Z"));       // year 00 is fine
        }

        [Test]
        public void InvalidUtcTimeFieldRanges()
        {
            Assert.False(IsValidUtcTime("000000000000Z"));      // month 00, day 00
            Assert.False(IsValidUtcTime("000200000000Z"));      // day 00
            Assert.False(IsValidUtcTime("241300000000Z"));      // month 13 (and day/... irrelevant)
            Assert.False(IsValidUtcTime("240132000000Z"));      // day 32
            Assert.False(IsValidUtcTime("240101240000Z"));      // hour 24
            Assert.False(IsValidUtcTime("240101006000Z"));      // minute 60
            Assert.False(IsValidUtcTime("240101000060Z"));      // second 60
            Assert.False(IsValidUtcTime("240101000000+2460"));  // offset minute 60
            Assert.False(IsValidUtcTime("5001010000+05"));      // no seconds, offset (no minutes)
            Assert.False(IsValidUtcTime("500101000000+05"));    // seconds, offset (no minutes)
        }

        [Test]
        public void InvalidUtcTimeStructure()
        {
            Assert.False(IsValidUtcTime("240101000000"));       // no zone
            Assert.False(IsValidUtcTime("24010100000Z"));       // illegal length 12
            Assert.False(IsValidUtcTime("2401010000X"));        // bad terminator
            Assert.False(IsValidUtcTime("2401010000+99XX"));    // non-digit offset
            Assert.False(IsValidUtcTime(""));                   // empty

            // embedded control byte where seconds digits are expected
            Assert.False(IsValidUtcTime("2401010000\u00070Z"));

            // high (negative) byte where a digit is expected
            Assert.False(IsValidUtcTime("24010\u00FF000000Z"));
        }

        [Test]
        public void ValidGeneralizedTime()
        {
            Assert.True(IsValidGeneralizedTime("2024010100Z"));         // hour only, Z
            Assert.True(IsValidGeneralizedTime("202401010000Z"));       // minute, Z
            Assert.True(IsValidGeneralizedTime("20240101000000Z"));     // second, Z
            Assert.True(IsValidGeneralizedTime("20240101000000.5Z"));   // fractional '.'
            Assert.True(IsValidGeneralizedTime("20240101000000,123Z")); // fractional ','
            Assert.True(IsValidGeneralizedTime("20240101000000+05"));   // numeric offset (no minutes)
            Assert.True(IsValidGeneralizedTime("20240101000000+0500")); // numeric offset
            Assert.True(IsValidGeneralizedTime("20240101000000+0530")); // numeric offset
            Assert.True(IsValidGeneralizedTime("20240101000000"));      // local, full
            Assert.True(IsValidGeneralizedTime("2024010100"));          // local, hour only
            Assert.True(IsValidGeneralizedTime("19500101000000Z"));
        }

        [Test]
        public void InvalidGeneralizedTimeFieldRanges()
        {
            Assert.False(IsValidGeneralizedTime("20240001000000Z"));    // month 00
            Assert.False(IsValidGeneralizedTime("20241301000000Z"));    // month 13
            Assert.False(IsValidGeneralizedTime("20240132000000Z"));    // day 32
            Assert.False(IsValidGeneralizedTime("2024010124Z"));        // hour 24
            Assert.False(IsValidGeneralizedTime("202401010060Z"));      // minute 60
            Assert.False(IsValidGeneralizedTime("20240101000060Z"));    // second 60
        }

        [Test]
        public void InvalidGeneralizedTimeStructure()
        {
            Assert.False(IsValidGeneralizedTime("202401010"));          // length 9 < 10
            Assert.False(IsValidGeneralizedTime("20240101000000."));    // decimal mark, no digits
            Assert.False(IsValidGeneralizedTime("2024010100ZZ"));       // trailing junk after Z
            Assert.False(IsValidGeneralizedTime("20240101000000X"));    // bad trailing
            Assert.False(IsValidGeneralizedTime("20240101000000+1"));   // truncated offset (no minutes)
            Assert.False(IsValidGeneralizedTime("20240101000000+123")); // truncated offset

            Assert.False(IsValidGeneralizedTime("202401\u00001000000Z"));
        }

        /// <summary>
        /// Exact content octets (tag/length stripped) of inputs from the fuzzing report that BC parses today; every one
        /// must now be rejected.
        /// </summary>
        [Test]
        public void RejectsReportedCorpusContent()
        {
            // 170d 3030303030303030303030305a  -> "000000000000Z" -> today: Date 1999-11-30
            Assert.False(IsValidUtcTime("000000000000Z"));
            // 170d 3030303230303030303030305a  -> "000200000000Z" -> today: Date 2000-01-31
            Assert.False(IsValidUtcTime("000200000000Z"));
            // 180f 303430303031303030303030303030 -> "040001000000000" -> today: Date 399
            Assert.False(IsValidGeneralizedTime("040001000000000"));
            // 180f 30343030303130303030303030302e -> "04000100000000." -> today: getDate() throws
            Assert.False(IsValidGeneralizedTime("04000100000000."));
            // 180f 3034303030313030303030303030302a-derived "04000100000000*" (control/punct tail)
            Assert.False(IsValidGeneralizedTime("04000100000000*"));
        }

        private static bool IsValidGeneralizedTime(string s)
        {
            try
            {
                new Asn1GeneralizedTime(s);
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        private static bool IsValidUtcTime(string s)
        {
            try
            {
                new Asn1UtcTime(s);
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }
    }
}
