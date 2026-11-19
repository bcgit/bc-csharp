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
    /// A used-up XMSS private key has to survive being written out and read back. It is the one state that most
    /// needs to persist - a key restored from an earlier saved state would sign again with a one-time key it has
    /// already used - and it is the state the index bound is widest for: an exhausted key carries the index one past
    /// its last leaf, which is the placeholder traversal state installed when the final one-time key is consumed.
    /// </summary>
    /// <remarks>
    /// The XMSS methods and the XMSS halves of the paired ones. The XMSS^MT methods and halves arrive with the
    /// XMSS^MT keys, and the PrivateKeyInfo round trips with the key factories.
    /// </remarks>
    [TestFixture]
    public class ExhaustedKeyTests
    {
        private const int Height = 4;

        private static XmssParameters XmssParams() => new XmssParameters(Height, new Sha256Digest());

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

        /// <summary>The encoding of a used-up key can be read back, and what comes back is still used up.</summary>
        /// <remarks>XMSS half.</remarks>
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
        }

        /// <summary>
        /// A restored exhausted key refuses to sign. Restoring one that could sign again would reuse a one-time key,
        /// which is the failure RFC 8391 sec. 1.1 exists to prevent.
        /// </summary>
        /// <remarks>XMSS half.</remarks>
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
        /// The two ways a shard request is outside what the key can give: none at all, and more than the key has
        /// left. The message is how a caller catching ArgumentException tells them apart.
        /// </summary>
        /// <remarks>XMSS half.</remarks>
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
        }

        private static void CheckShardRefused(XmssPrivateKeyParameters privKey, int usageCount, string message)
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
