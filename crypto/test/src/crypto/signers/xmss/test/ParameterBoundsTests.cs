using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A tree height is only meaningful up to the point where an int index can still count the tree's leaves, and the
    /// parameter classes take one from whoever asks.
    /// </summary>
    /// <remarks>
    /// The XMSS methods, and the XMSS half of <see cref="TestSecurityParameterOutsideRegisteredSetsRefused"/>. The
    /// XMSS^MT methods and half arrive with the XMSS^MT parameters, and the two that read a height or a layer count
    /// out of an encoded key with the key factories.
    /// </remarks>
    [TestFixture]
    public class ParameterBoundsTests
    {
        /// <summary>
        /// The two tree digest lookups refuse an absent OID by name, as they refuse an unknown one, rather than with
        /// a null reference.
        /// </summary>
        /// <remarks>
        /// Java's messages end in "null"; C# string concatenation renders a null OID as nothing, so the prefix is
        /// what is asserted.
        /// </remarks>
        [Test]
        public void TestAnAbsentTreeDigestOidIsRefusedByName()
        {
            ArgumentException e = Assert.Throws<ArgumentException>(() => XmssDigestUtilities.GetDigest(null),
                "a null tree digest OID produced a digest");
            StringAssert.StartsWith("unrecognized digest OID:", e.Message);

            e = Assert.Throws<ArgumentException>(() => XmssDigestUtilities.GetDigestName(null),
                "a null tree digest OID produced a name");
            StringAssert.StartsWith("unrecognized digest oid:", e.Message);
        }

        [Test]
        public void TestHeightAboveMaximumRefused()
        {
            // 31 above a multiple of 32 wraps (1 << height) to a negative, which left key generation with no leaves
            // to build from; the rest wrap to a small positive, which built a shorter tree than the one asked for
            int[] heights = new int[]{ 31, 32, 33, 62, 63, 64, 95, 96, int.MaxValue };

            for (int i = 0; i != heights.Length; i++)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssParameters(heights[i], NistObjectIdentifiers.IdSha256),
                    "height " + heights[i] + " accepted");
                Assert.AreEqual("height must be <= 30", e.Message);
            }
        }

        /// <summary>
        /// The security parameter n is the caller's, and nothing derived from it is bounded - len1, len2 and len are
        /// computed from whatever arrives. What refuses one that no registered parameter set defines is the WOTS+
        /// parameter set lookup.
        /// </summary>
        /// <remarks>XMSS half.</remarks>
        [Test]
        public void TestSecurityParameterOutsideRegisteredSetsRefused()
        {
            // 32 and 24 are SHA-256's two, being RFC 8391 XMSS-SHA2_*_256 and SP 800-208 XMSS-SHA2_*_192; 64 is
            // SHA-512's n asked for of SHA-256, which is neither
            int[] sizes = new int[]{ 1, 16, 17, 20, 31, 33, 48, 64, 128 };

            for (int i = 0; i != sizes.Length; i++)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssParameters(10, NistObjectIdentifiers.IdSha256, sizes[i]),
                    "n = " + sizes[i] + " accepted for XMSS");
                Assert.AreEqual("cannot find OID for digest algorithm: SHA-256", e.Message);
            }

            Assert.AreEqual(67, new XmssParameters(10, NistObjectIdentifiers.IdSha256, 32).Len);
            Assert.AreEqual(51, new XmssParameters(10, NistObjectIdentifiers.IdSha256, 24).Len);
        }

        [Test]
        public void TestHeightBelowMinimumRefused()
        {
            int[] heights = new int[]{ int.MinValue, -1, 0, 1 };

            for (int i = 0; i != heights.Length; i++)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssParameters(heights[i], NistObjectIdentifiers.IdSha256),
                    "height " + heights[i] + " accepted");
                Assert.AreEqual("height must be >= 2", e.Message);
            }
        }

        /// <summary>
        /// The bound is the tallest tree the traversal state will validate, not something narrower: a height the
        /// state accepts has to remain constructible.
        /// </summary>
        [Test]
        public void TestMaximumHeightStillConstructs()
        {
            XmssParameters parameters = new XmssParameters(XmssParameters.MaxHeight, NistObjectIdentifiers.IdSha256);

            Assert.AreEqual(30, parameters.Height);

            // and the smallest tree, generated through to a usable key pair
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(2, NistObjectIdentifiers.IdSha256)));

            Assert.IsNotNull(kpg.GenerateKeyPair().Private);
        }
    }
}
