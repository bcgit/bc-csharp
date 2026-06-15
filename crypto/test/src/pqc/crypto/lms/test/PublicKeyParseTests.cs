using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    /// <summary>
    /// Well-formedness checks on LMS / HSS public key parsing.
    /// </summary>
    /// <remarks>
    /// RFC 8554: unknown typecodes and out-of-range level counts must be rejected with a clean exception
    /// (sec. 5.3 / 6), and a byte[] encoding must be consumed exactly (sec. 5.3, "If the public key is not exactly 24
    /// + m bytes long, return INVALID").
    /// </remarks>
    [TestFixture]
    public class PublicKeyParseTests
    {
        // lms_sha256_n32_h5 (5) / sha256_n32_w8 (4), I = 16 bytes, T[1] = 32 bytes.
        private static byte[] ValidLmsPublicKey()
        {
            return Composer.Compose()
                .U32Str(LMSigParameters.lms_sha256_n32_h5.ID)
                .U32Str(LMOtsParameters.sha256_n32_w8.ID)
                .Bytes(new byte[16])
                .Bytes(new byte[32])
                .Build();
        }

        private static byte[] ValidHssPublicKey(int l)
        {
            return Composer.Compose()
                .U32Str(l)
                .Bytes(ValidLmsPublicKey())
                .Build();
        }

        [Test]
        public void ValidKeysParse()
        {
            LmsPublicKeyParameters lmsKey = LmsPublicKeyParameters.GetInstance(ValidLmsPublicKey());
            Assert.AreEqual(LMSigParameters.lms_sha256_n32_h5, lmsKey.GetSigParameters());
            Assert.AreEqual(LMOtsParameters.sha256_n32_w8, lmsKey.GetOtsParameters());

            HssPublicKeyParameters hssKey = HssPublicKeyParameters.GetInstance(ValidHssPublicKey(1));
            Assert.AreEqual(1, hssKey.Level);
            Assert.AreEqual(lmsKey, hssKey.LmsPublicKey);

            Assert.AreEqual(8, HssPublicKeyParameters.GetInstance(ValidHssPublicKey(8)).Level);
        }

        [Test]
        public void UnknownLMSTypeCodeRejected()
        {
            byte[] enc = ValidLmsPublicKey();
            enc[3] = (byte)0xee;

            try
            {
                LmsPublicKeyParameters.GetInstance(enc);
                Assert.Fail("unknown LMS typecode accepted");
            }
            catch (InvalidDataException e)
            {
                Assert.AreEqual("unknown LMS type code: 238", e.Message);
            }
        }

        [Test]
        public void UnknownOtsTypeCodeRejected()
        {
            byte[] enc = ValidLmsPublicKey();
            enc[7] = (byte)0xee;

            try
            {
                LmsPublicKeyParameters.GetInstance(enc);
                Assert.Fail("unknown LM-OTS typecode accepted");
            }
            catch (InvalidDataException e)
            {
                Assert.AreEqual("unknown LM-OTS type code: 238", e.Message);
            }
        }

        [Test]
        public void UnknownTypeCodeRejectedViaHSS()
        {
            byte[] enc = ValidHssPublicKey(1);
            enc[7] = (byte)0xee;

            try
            {
                HssPublicKeyParameters.GetInstance(enc);
                Assert.Fail("unknown LMS typecode accepted");
            }
            catch (InvalidDataException e)
            {
                Assert.AreEqual("unknown LMS type code: 238", e.Message);
            }
        }

        [Test]
        public void HssLevelCountRange()
        {
            int[] badL = new int[]{ 0, 9, 99, -1 };
            for (int i = 0; i != badL.Length; i++)
            {
                try
                {
                    HssPublicKeyParameters.GetInstance(ValidHssPublicKey(badL[i]));
                    Assert.Fail("HSS L value " + badL[i] + " accepted");
                }
                catch (InvalidDataException e)
                {
                    Assert.AreEqual("L value of HSS public key out of range: " + badL[i], e.Message);
                }
            }
        }

        [Test]
        public void TrailingDataRejectedHss()
        {
            byte[] hssTrailing = Arrays.Append(ValidHssPublicKey(2), (byte)0);

            try
            {
                HssPublicKeyParameters.GetInstance(hssTrailing);
                Assert.Fail("trailing data after HSS public key accepted");
            }
            catch (InvalidDataException e)
            {
                Assert.AreEqual("unexpected data found after HSS public key", e.Message);
            }
        }

        [Test]
        public void TrailingDataRejectedLms()
        {
            byte[] lmsTrailing = Arrays.Append(ValidLmsPublicKey(), (byte)0);

            try
            {
                LmsPublicKeyParameters.GetInstance(lmsTrailing);
                Assert.Fail("trailing data after LMS public key accepted");
            }
            catch (InvalidDataException e)
            {
                Assert.AreEqual("unexpected data found after LMS public key", e.Message);
            }
        }

        /// <summary>
        /// The stream entry points are used to read public keys embedded in larger structures (HSS signature chains),
        /// so they must not require the stream to be exhausted.
        /// </summary>
        [Test]
        public void StreamParseLeavesTrailingData()
        {
            byte[] two = Arrays.Concatenate(ValidLmsPublicKey(), ValidLmsPublicKey());
            using (var buf = new MemoryStream(two, false))
            {
                LmsPublicKeyParameters first = LmsPublicKeyParameters.GetInstance(buf);
                LmsPublicKeyParameters second = LmsPublicKeyParameters.GetInstance(buf);

                Assert.AreEqual(buf.Position, buf.Length);
            }
        }
    }
}
