using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A used-up XMSS / XMSS^MT private key has to survive being written out and read back. It is the one state that
    /// most needs to persist - a key restored from an earlier saved state would sign again with a one-time key it has
    /// already used - and it is the state the index bound is widest for: an exhausted key carries the index one past
    /// its last leaf, which is the placeholder traversal state installed when the final one-time key is consumed.
    /// </summary>
    /// <remarks>
    /// The PrivateKeyInfo round trips arrive with the key factories.
    /// </remarks>
    [TestFixture]
    public class ExhaustedKeyTests
    {
        private const int Height = 4;
        private const int Layers = 2;

        private static XmssParameters XmssParams() => new XmssParameters(Height, new Sha256Digest());

        private static XmssMTParameters XmssMTParams() => new XmssMTParameters(Height, Layers, new Sha256Digest());

        private static XmssPrivateKeyParameters ExhaustedXmss(XmssParameters parameters)
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            for (int i = 0; i != (1 << Height); i++)
            {
                privKey.RollKey();
            }

            Assert.AreEqual(0, privKey.GetUsagesRemaining());

            return privKey;
        }

        private static XmssMTPrivateKeyParameters ExhaustedXmssMT(XmssMTParameters parameters)
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            for (int i = 0; i != (1 << parameters.Height); i++)
            {
                privKey.RollKey();
            }

            Assert.AreEqual(0, privKey.GetUsagesRemaining());

            return privKey;
        }

        /// <summary>The encoding of a used-up key can be read back, and what comes back is still used up.</summary>
        [Test]
        public void TestExhaustedKeyRoundTripsAndStaysExhausted()
        {
            XmssParameters parameters = XmssParams();
            XmssPrivateKeyParameters privKey = ExhaustedXmss(parameters);

            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(privKey.GetEncoded()).Build();

            Assert.AreEqual(0, restored.GetUsagesRemaining());
            Assert.AreEqual(privKey.Index, restored.Index);
            Assert.AreEqual((1 << Height) - 1, restored.GetBdsState().MaxIndex);
            Assert.IsTrue(Arrays.AreEqual(privKey.GetEncoded(), restored.GetEncoded()));

            XmssMTParameters mtParams = XmssMTParams();
            XmssMTPrivateKeyParameters mtPrivKey = ExhaustedXmssMT(mtParams);

            XmssMTPrivateKeyParameters mtRestored = new XmssMTPrivateKeyParameters.Builder(mtParams)
                .WithPrivateKey(mtPrivKey.GetEncoded()).Build();

            Assert.AreEqual(0, mtRestored.GetUsagesRemaining());
            Assert.AreEqual(mtPrivKey.Index, mtRestored.Index);
            Assert.IsTrue(Arrays.AreEqual(mtPrivKey.GetEncoded(), mtRestored.GetEncoded()));
        }

        /// <summary>
        /// The raw encoding refuses an exhausted XMSS^MT index it cannot carry, rather than narrowing it.
        /// </summary>
        /// <remarks>
        /// The index field of the raw layout is ceil(h / 8) bytes, and the largest index a key can hold is 2^h - the
        /// position it stops at when its last one-time key is spent - so at a height that is a multiple of eight the
        /// field is one bit short. Written narrowed it read back as zero, a key declaring a full tree of unused
        /// one-time keys, and nothing caught it: 2^h decomposes to the same leaf index as 0 at every layer. Height 8
        /// over 2 layers, so the field is one byte and the exhausted key sits at 256. Every position below it still
        /// encodes, which is what the refusal must not cost.
        /// </remarks>
        [Test]
        [Explicit] // slow: ~16s
        public void TestExhaustedKeyAtAByteAlignedHeightRefusesTheRawEncoding()
        {
            XmssMTParameters parameters = new XmssMTParameters(8, 2, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            for (int i = 0; i != (1 << 8); i++)
            {
                Assert.AreEqual(i, privKey.Index);
                Assert.IsTrue(privKey.GetEncoded().Length > 0, "a live key's position was refused");
                privKey.RollKey();
            }

            Assert.AreEqual(1L << 8, privKey.Index);

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => privKey.GetEncoded(),
                "an index the field cannot hold was written narrowed");
            Assert.AreEqual("index 256 does not fit the 1 byte index field of a stored private key", e.Message);
        }

        /// <summary>
        /// The refusal of <see cref="TestExhaustedKeyAtAByteAlignedHeightRefusesTheRawEncoding"/> on a key rebuilt at
        /// the exhausted position rather than rolled to it, which is cheap enough for the default run.
        /// </summary>
        [Test]
        public void RecoveredExhaustedKeyAtAByteAlignedHeightRefusesTheRawEncoding()
        {
            XmssMTParameters parameters = new XmssMTParameters(8, 2, new Sha256Digest());
            byte[] seed = new byte[parameters.TreeDigestSize];

            XmssMTPrivateKeyParameters privKey = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed)
                .WithIndex(1L << 8).Build();

            Assert.AreEqual(1L << 8, privKey.Index);
            Assert.AreEqual(0, privKey.GetUsagesRemaining());

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => privKey.GetEncoded());
            Assert.AreEqual("index 256 does not fit the 1 byte index field of a stored private key", e.Message);

            // one bit wider, and the same position is carried
            XmssMTParameters wider = new XmssMTParameters(9, 3, new Sha256Digest());
            XmssMTPrivateKeyParameters spent = new XmssMTPrivateKeyParameters.Builder(wider)
                .WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed)
                .WithIndex(1L << 9).Build();
            XmssMTPrivateKeyParameters restored = new XmssMTPrivateKeyParameters.Builder(wider)
                .WithPrivateKey(spent.GetEncoded()).Build();
            Assert.AreEqual(1L << 9, restored.Index);
            Assert.AreEqual(0, restored.GetUsagesRemaining());
        }

        /// <summary>
        /// A restored exhausted key refuses to sign. Restoring one that could sign again would reuse a one-time key,
        /// which is the failure RFC 8391 sec. 1.1 exists to prevent.
        /// </summary>
        [Test]
        public void TestRestoredExhaustedKeyRefusesToSign()
        {
            XmssParameters parameters = XmssParams();
            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(ExhaustedXmss(parameters).GetEncoded()).Build();

            XmssSigner signer = new XmssSigner();
            byte[] message = new byte[]{ 1, 2, 3 };

            signer.Init(true, restored);
            signer.BlockUpdate(message, 0, message.Length);

            ExhaustedPrivateKeyException e = Assert.Throws<ExhaustedPrivateKeyException>(
                () => signer.GenerateSignature());
            Assert.AreEqual("no usages of private key remaining", e.Message);

            XmssMTParameters mtParams = XmssMTParams();
            XmssMTPrivateKeyParameters mtRestored = new XmssMTPrivateKeyParameters.Builder(mtParams)
                .WithPrivateKey(ExhaustedXmssMT(mtParams).GetEncoded()).Build();

            XmssMTSigner mtSigner = new XmssMTSigner();

            mtSigner.Init(true, mtRestored);
            mtSigner.BlockUpdate(message, 0, message.Length);

            e = Assert.Throws<ExhaustedPrivateKeyException>(() => mtSigner.GenerateSignature());
            Assert.AreEqual("no usages of private key remaining", e.Message);
        }

        /// <summary>
        /// A key is also left at its one-past-the-end index by handing out its last usages as a shard, rather than
        /// by rolling to the end, and the shard itself carries a maximum index short of the tree's. Both encodings
        /// have to survive the round trip.
        /// </summary>
        [Test]
        public void TestKeyExhaustedByShardExtractionRoundTrips()
        {
            XmssParameters parameters = XmssParams();
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            XmssPrivateKeyParameters shard = privKey.ExtractKeyShard((int)privKey.GetUsagesRemaining());

            Assert.AreEqual(0, privKey.GetUsagesRemaining());
            Assert.AreEqual(1 << Height, shard.GetUsagesRemaining());

            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(privKey.GetEncoded()).Build();

            Assert.AreEqual(0, restored.GetUsagesRemaining());

            // the shard covers the whole tree here, so take a smaller one to reach a maximum index short of the
            // tree's, exhaust that, and round trip it too
            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters parent = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            XmssPrivateKeyParameters smallShard = parent.ExtractKeyShard(2);

            Assert.AreEqual(1, smallShard.GetBdsState().MaxIndex);

            smallShard.RollKey();
            smallShard.RollKey();

            Assert.AreEqual(0, smallShard.GetUsagesRemaining());

            XmssPrivateKeyParameters restoredShard = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(smallShard.GetEncoded()).Build();

            Assert.AreEqual(0, restoredShard.GetUsagesRemaining());
            Assert.AreEqual(smallShard.Index, restoredShard.Index);
        }

        /// <summary>
        /// As <see cref="TestKeyExhaustedByShardExtractionRoundTrips"/>, for an XMSS^MT key: the shard taking all
        /// that is left, and a smaller shard spent by rolling, both leave encodings that read back exhausted.
        /// </summary>
        [Test]
        public void MTKeyExhaustedByShardExtractionRoundTrips()
        {
            XmssMTParameters parameters = XmssMTParams();
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            XmssMTPrivateKeyParameters shard = privKey.ExtractKeyShard((int)privKey.GetUsagesRemaining());

            Assert.AreEqual(0, privKey.GetUsagesRemaining());
            Assert.AreEqual(1 << Height, shard.GetUsagesRemaining());

            XmssMTPrivateKeyParameters restored = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(privKey.GetEncoded()).Build();

            Assert.AreEqual(0, restored.GetUsagesRemaining());

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters parent = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            XmssMTPrivateKeyParameters smallShard = parent.ExtractKeyShard(2);

            Assert.AreEqual(1, smallShard.GetBdsState().MaxIndex);

            smallShard.RollKey();
            smallShard.RollKey();

            Assert.AreEqual(0, smallShard.GetUsagesRemaining());

            XmssMTPrivateKeyParameters restoredShard = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(smallShard.GetEncoded()).Build();

            Assert.AreEqual(0, restoredShard.GetUsagesRemaining());
            Assert.AreEqual(smallShard.Index, restoredShard.Index);
        }

        /// <summary>
        /// The two ways a shard request is outside what the key can give: none at all, and more than the key has
        /// left. The message is how a caller catching ArgumentException tells them apart.
        /// </summary>
        [Test]
        public void TestShardRequestsOutsideWhatTheKeyHasAreRefused()
        {
            XmssParameters parameters = XmssParams();
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            long usages = privKey.GetUsagesRemaining();

            CheckShardRefused(privKey, 0, "cannot ask for a shard with 0 keys");
            CheckShardRefused(privKey, -1, "cannot ask for a shard with 0 keys");
            CheckShardRefused(privKey, (int)usages + 1, "usageCount exceeds usages remaining");

            Assert.AreEqual(usages, privKey.GetUsagesRemaining(), "a refused shard must not move the key");

            XmssMTParameters mtParams = XmssMTParams();
            XmssMTKeyPairGenerator mtKpg = new XmssMTKeyPairGenerator();

            mtKpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), mtParams));

            XmssMTPrivateKeyParameters mtPrivKey = (XmssMTPrivateKeyParameters)mtKpg.GenerateKeyPair().Private;
            long mtUsages = mtPrivKey.GetUsagesRemaining();

            CheckShardRefused(mtPrivKey, 0, "cannot ask for a shard with 0 keys");
            CheckShardRefused(mtPrivKey, -1, "cannot ask for a shard with 0 keys");
            CheckShardRefused(mtPrivKey, (int)mtUsages + 1, "usageCount exceeds usages remaining");

            Assert.AreEqual(mtUsages, mtPrivKey.GetUsagesRemaining(), "a refused shard must not move the key");
        }

        private static void CheckShardRefused(XmssPrivateKeyParameters privKey, int usageCount, string message)
        {
            ArgumentException e = Assert.Throws<ArgumentException>(() => privKey.ExtractKeyShard(usageCount),
                "shard of " + usageCount + " was handed out");
            Assert.AreEqual(message, e.Message);
        }

        private static void CheckShardRefused(XmssMTPrivateKeyParameters privKey, int usageCount, string message)
        {
            ArgumentException e = Assert.Throws<ArgumentException>(() => privKey.ExtractKeyShard(usageCount),
                "shard of " + usageCount + " was handed out");
            Assert.AreEqual(message, e.Message);
        }

        /// <summary>
        /// The index bound is one leaf wider than the signing bound, not open: one past the exhausted index is still
        /// out of bounds, so is a negative index, and an index that does not match the traversal state it arrived
        /// with is still caught.
        /// </summary>
        [Test]
        public void TestIndexBeyondExhaustionStillRejected()
        {
            XmssParameters parameters = XmssParams();
            byte[] encoded = ExhaustedXmss(parameters).GetEncoded();

            CheckRejected(parameters, WithIndex(encoded, (1 << Height) + 1), "index out of bounds");
            CheckRejected(parameters, WithIndex(encoded, -1), "index out of bounds");
            CheckRejected(parameters, WithIndex(encoded, int.MaxValue), "index out of bounds");
            CheckRejected(parameters, WithIndex(encoded, 3), "BDS state has wrong index");
        }

        private static byte[] WithIndex(byte[] encoded, int index)
        {
            byte[] altered = Arrays.Clone(encoded);

            Pack.UInt32_To_BE((uint)index, altered, 0);

            return altered;
        }

        private static void CheckRejected(XmssParameters parameters, byte[] encoded, string message)
        {
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoded).Build());
            Assert.AreEqual(message, e.Message);
        }
    }
}
