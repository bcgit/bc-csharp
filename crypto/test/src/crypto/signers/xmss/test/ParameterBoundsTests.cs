using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A tree height is only meaningful up to the point where an int index can still count the tree's leaves, and the
    /// parameter classes take one from whoever asks.
    /// </summary>
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

                e = Assert.Throws<ArgumentException>(
                    () => new XmssMTParameters(20, 2, NistObjectIdentifiers.IdSha256, sizes[i]),
                    "n = " + sizes[i] + " accepted for XMSS^MT");
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

        [Test]
        public void TestLayerCountRefused()
        {
            // zero divided into the total height, and a negative that divides into it cleanly
            int[][] cases = new int[][]{ new int[]{ 4, 0 }, new int[]{ 2, 0 }, new int[]{ 4, -1 }, new int[]{ 4, -2 },
                new int[]{ 60, int.MinValue } };

            for (int i = 0; i != cases.Length; i++)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssMTParameters(cases[i][0], cases[i][1], NistObjectIdentifiers.IdSha256),
                    "layers " + cases[i][1] + " accepted");
                Assert.AreEqual("layers must be >= 1", e.Message);
            }
        }

        [Test]
        public void TestTotalHeightAboveMaximumRefused()
        {
            // a total height of 63 leaves every index reading as invalid, and 64 wraps the maximum index to 0 - both
            // silent, so neither shows up as a failure to build the key
            int[][] cases = new int[][]{ new int[]{ 63, 3 }, new int[]{ 64, 4 }, new int[]{ 640, 64 },
                new int[]{ 1200, 120 } };

            for (int i = 0; i != cases.Length; i++)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssMTParameters(cases[i][0], cases[i][1], NistObjectIdentifiers.IdSha256),
                    "total height " + cases[i][0] + " accepted");
                Assert.AreEqual("totalHeight must be <= 62", e.Message);
            }
        }

        /// <summary>
        /// Every parameter set RFC 8391 sec. 5.4 registers has to remain constructible - the bounds are on what the
        /// arithmetic can carry, not a narrowing of the registered sets.
        /// </summary>
        [Test]
        public void TestRegisteredHypertreeSetsStillConstruct()
        {
            int[][] cases = new int[][]{ new int[]{ 20, 2 }, new int[]{ 20, 4 }, new int[]{ 40, 2 },
                new int[]{ 40, 4 }, new int[]{ 40, 8 }, new int[]{ 60, 3 }, new int[]{ 60, 6 }, new int[]{ 60, 12 } };

            for (int i = 0; i != cases.Length; i++)
            {
                XmssMTParameters parameters = new XmssMTParameters(cases[i][0], cases[i][1],
                    NistObjectIdentifiers.IdSha256);

                Assert.AreEqual(cases[i][0], parameters.Height);
                Assert.AreEqual(cases[i][1], parameters.Layers);
            }
        }

        /// <summary>
        /// The height in an XmssKeyParams is whatever the encoded key said it was, so it reaches the parameter set
        /// straight off the wire and is reported the way the rest of a malformed key is.
        /// </summary>
        /// <remarks>Java reports it as an IOException; the key factories here report a malformed key as an
        /// ArgumentException.</remarks>
        [Test]
        public void TestHeightFromEncodedKeyReported()
        {
            AlgorithmIdentifier treeDigest = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss,
                new XmssKeyParams(31, treeDigest));

            ArgumentException e = Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(algId, new XmssPublicKey(new byte[32], new byte[32]))),
                "height 31 in public key parameters accepted");
            Assert.AreEqual("malformed XMSS public key: height must be <= 30", e.Message);

            e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(algId,
                new XmssPrivateKey(0, new byte[32], new byte[32], new byte[32], new byte[32], null))),
                "height 31 in private key parameters accepted");
            Assert.AreEqual("malformed XMSS private key: height must be <= 30", e.Message);
        }

        /// <summary>As for the XMSS height, the layer count reaches the parameter set straight off the wire.</summary>
        [Test]
        public void TestLayerCountFromEncodedKeyReported()
        {
            AlgorithmIdentifier treeDigest = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt,
                new XmssMTKeyParams(4, 0, treeDigest));

            ArgumentException e = Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(algId, new XmssPublicKey(new byte[32], new byte[32]))),
                "zero layers in public key parameters accepted");
            Assert.AreEqual("malformed XMSS^MT public key: layers must be >= 1", e.Message);
        }

        /// <summary>
        /// The other refusals of a total height and a layer count that do not make a hypertree, each reported as
        /// the parameter that was wrong.
        /// </summary>
        [Test]
        public void HypertreeShapeRefused()
        {
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssMTParameters(1, 1, NistObjectIdentifiers.IdSha256));
            Assert.AreEqual("totalHeight must be > 1", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssMTParameters(10, 3, NistObjectIdentifiers.IdSha256));
            Assert.AreEqual("layers must divide totalHeight without remainder", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssMTParameters(4, 4, NistObjectIdentifiers.IdSha256));
            Assert.AreEqual("height / layers must be greater than 1", e.Message);

            // the tallest hypertree, and the per layer bound beneath it: 62 over 2 is 31, past the XMSS maximum
            Assert.AreEqual(62, new XmssMTParameters(XmssMTParameters.MaxHeight, 31,
                NistObjectIdentifiers.IdSha256).Height);
            e = Assert.Throws<ArgumentException>(() => new XmssMTParameters(62, 2, NistObjectIdentifiers.IdSha256));
            Assert.AreEqual("height must be <= 30", e.Message);

            Assert.Throws<ArgumentNullException>(() => new XmssMTParameters(20, 2, (IDigest)null));
        }
    }
}
