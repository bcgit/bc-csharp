using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// WOTS+ (RFC 8391 sec. 3), the one-time signature XMSS is built on. It is internal, so this is the only
    /// place its verification relation - that the public key recovered from a signature equals the signer's own
    /// public key, and only for the digest that was signed - can be asserted directly.
    /// </summary>
    [TestFixture]
    public class WotsPlusTests
    {
        private const int N = 32;

        private static WotsPlus NewWotsPlus() =>
            new WotsPlus(new WotsPlusParameters(NistObjectIdentifiers.IdSha256, N));

        /// <summary>
        /// A copy of <paramref name="key"/>'s len blocks, made through EncodeTo rather than GetValue so that it
        /// stays a copy whatever GetValue is later decided to hand back. A snapshot that aliases the key would
        /// assert nothing in the tests that compare a key against itself after something has run.
        /// </summary>
        private static byte[][] BlocksOf(WotsPlusPublicKeyParameters key)
        {
            XmssNode[] nodes = key.ToNodes();
            byte[][] blocks = new byte[nodes.Length][];
            for (int i = 0; i != nodes.Length; i++)
            {
                blocks[i] = new byte[nodes[i].ValueLength];
                nodes[i].EncodeTo(blocks[i], 0);
            }
            return blocks;
        }

        [Test]
        public void TestPublicKeyFromSignatureMatchesSigner()
        {
            SecureRandom random = new SecureRandom();
            byte[] secretKeySeed = new byte[N];
            byte[] publicSeed = new byte[N];
            byte[] messageDigest = new byte[N];
            random.NextBytes(secretKeySeed);
            random.NextBytes(publicSeed);
            random.NextBytes(messageDigest);

            byte[] otsHashAddress = XmssAddress.OtsHashAddress(0, 0L, 3);

            WotsPlus wotsPlus = NewWotsPlus();
            wotsPlus.ImportKeys(secretKeySeed, publicSeed);

            byte[][] signature = wotsPlus.Sign(messageDigest, otsHashAddress);

            Assert.AreEqual(wotsPlus.Params.Len, signature.Length);

            WotsPlusPublicKeyParameters expected = wotsPlus.GetPublicKey(otsHashAddress);
            WotsPlusPublicKeyParameters recovered =
                wotsPlus.GetPublicKeyFromSignature(messageDigest, signature, otsHashAddress);

            Assert.IsTrue(XmssUtilities.AreEqual(BlocksOf(expected), BlocksOf(recovered)),
                "public key recovered from signature does not match signer");
        }

        [Test]
        public void TestPublicKeyFromSignatureDiffersForOtherDigest()
        {
            byte[] secretKeySeed = new byte[N];
            byte[] publicSeed = new byte[N];
            byte[] messageDigest = new byte[N];
            byte[] otherDigest = new byte[N];
            Arrays.Fill(secretKeySeed, 0x01);
            Arrays.Fill(publicSeed, 0x02);
            Arrays.Fill(messageDigest, 0x03);
            Arrays.Fill(otherDigest, 0x04);

            byte[] otsHashAddress = XmssAddress.OtsHashAddress(0, 0L, 0);

            WotsPlus wotsPlus = NewWotsPlus();
            wotsPlus.ImportKeys(secretKeySeed, publicSeed);

            byte[][] signature = wotsPlus.Sign(messageDigest, otsHashAddress);

            WotsPlusPublicKeyParameters expected = wotsPlus.GetPublicKey(otsHashAddress);
            WotsPlusPublicKeyParameters recovered =
                wotsPlus.GetPublicKeyFromSignature(otherDigest, signature, otsHashAddress);

            Assert.IsFalse(XmssUtilities.AreEqual(BlocksOf(expected), BlocksOf(recovered)),
                "a signature verified against the wrong digest");
        }

        /// <summary>
        /// WotsPlusPublicKeyParameters holds the blocks its caller built rather than copies of them, and ToNodes
        /// hands those same blocks to the L-tree walk. What makes that safe is that the walk only reads them, so
        /// compressing a key leaves the key as it was.
        /// </summary>
        [Test]
        public void TestCompressingAPublicKeyDoesNotDisturbIt()
        {
            byte[] secretKeySeed = new byte[N];
            byte[] publicSeed = new byte[N];
            Arrays.Fill(secretKeySeed, 0x06);
            Arrays.Fill(publicSeed, 0x07);

            WotsPlus wotsPlus = NewWotsPlus();
            wotsPlus.ImportKeys(secretKeySeed, publicSeed);

            byte[] otsHashAddress = XmssAddress.OtsHashAddress(0, 0L, 3);
            WotsPlusPublicKeyParameters publicKey = wotsPlus.GetPublicKey(otsHashAddress);
            byte[][] before = BlocksOf(publicKey);

            byte[] lTreeAddress = XmssAddress.SubtreeAddressOf(otsHashAddress, XmssAddress.LTreeType);
            Pack.UInt32_To_BE(3U, lTreeAddress, XmssAddress.LTreeAddressOffset);
            XmssNodeUtilities.LTree(wotsPlus, publicKey, lTreeAddress, new byte[N], new byte[2 * N]);

            Assert.IsTrue(XmssUtilities.AreEqual(before, BlocksOf(publicKey)),
                "compressing a public key changed the key");
        }

        /// <summary>
        /// A WOTS+ signature is the len blocks its caller built, and WotsPlusPublicKeyParameters likewise holds
        /// those blocks, so each has to be an array of its own. A digest of 0x0f bytes is every digit alternately
        /// 0 and 15, so each of the len positions is a zero-step chain on one of the two sides.
        /// </summary>
        [Test]
        public void TestChainedBlocksAreArraysOfTheirOwn()
        {
            byte[] secretKeySeed = new byte[N];
            byte[] publicSeed = new byte[N];
            byte[] messageDigest = new byte[N];
            Arrays.Fill(secretKeySeed, 0x08);
            Arrays.Fill(publicSeed, 0x09);
            Arrays.Fill(messageDigest, 0x0f);

            byte[] otsHashAddress = XmssAddress.OtsHashAddress(0, 0L, 0);

            WotsPlus wotsPlus = NewWotsPlus();
            wotsPlus.ImportKeys(secretKeySeed, publicSeed);

            int len = wotsPlus.Params.Len;
            byte[][] signature = wotsPlus.Sign(messageDigest, otsHashAddress);
            for (int i = 0; i != len; i++)
            {
                for (int j = i + 1; j != len; j++)
                {
                    Assert.AreNotSame(signature[i], signature[j], "two blocks of one signature are the same array");
                }
            }

            WotsPlusPublicKeyParameters recovered =
                wotsPlus.GetPublicKeyFromSignature(messageDigest, signature, otsHashAddress);
            byte[][] before = BlocksOf(recovered);
            for (int i = 0; i != len; i++)
            {
                signature[i][0] ^= 0x01;
            }

            Assert.IsTrue(XmssUtilities.AreEqual(before, BlocksOf(recovered)),
                "a recovered public key shares storage with the signature it came from");
        }

        /// <summary>
        /// The one-time secret key is derived from the seed and the OTS hash address, so two leaves of the same
        /// tree must not share it.
        /// </summary>
        [Test]
        public void TestSecretKeyIsPerAddress()
        {
            byte[] secretKeySeed = new byte[N];
            Arrays.Fill(secretKeySeed, 0x05);

            WotsPlus wotsPlus = NewWotsPlus();

            byte[] first = wotsPlus.GetWotsPlusSecretKey(secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0));
            byte[] second = wotsPlus.GetWotsPlusSecretKey(secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 1));

            Assert.IsFalse(Arrays.AreEqual(first, second), "two leaves share a WOTS+ secret key");
        }

        // TestLenForStandardParameterSets: deferred to the task that adds XmssEngine (XmssEngine.GetWotsPlusLen).

        /// <summary>
        /// ImportKeys rejects a seed of the wrong length with the message the rest of the package uses for it,
        /// and an absent one rather than quietly substituting an all-zero seed.
        /// </summary>
        [Test]
        public void TestImportKeysRejectsWrongSizeAndAbsentSeeds()
        {
            string[] names = new string[]{ "secretKeySeed", "publicSeed" };
            int[] lengths = new int[]{ 0, N - 1, N + 1 };

            for (int i = 0; i != names.Length; i++)
            {
                for (int j = 0; j != lengths.Length; j++)
                {
                    byte[] secretKeySeed = new byte[i == 0 ? lengths[j] : N];
                    byte[] publicSeed = new byte[i == 0 ? N : lengths[j]];

                    var e = Assert.Throws<ArgumentException>(
                        () => NewWotsPlus().ImportKeys(secretKeySeed, publicSeed),
                        names[i] + " of " + lengths[j] + " bytes accepted");
                    Assert.AreEqual("size of " + names[i] + " needs to be equal to size of digest", e.Message);
                }

                // an absent seed is a caller error here, not an optional field: it must not be quietly replaced
                // by an all-zero one
                byte[] absentSecretKeySeed = i == 0 ? null : new byte[N];
                byte[] absentPublicSeed = i == 0 ? new byte[N] : null;
                Assert.Throws<ArgumentNullException>(
                    () => NewWotsPlus().ImportKeys(absentSecretKeySeed, absentPublicSeed),
                    "an absent " + names[i] + " was accepted");
            }
        }
    }
}
