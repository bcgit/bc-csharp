using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The BDS traversal state stored with a private key carries two collections the next authentication path reads
    /// from - the node kept when the path last passed a height, and the queue of retained right nodes - and a state
    /// that reached its index by signing always has the entries the next step will ask for. A state that arrived by
    /// import need not, and the reads say what is wrong rather than failing inside the hash function or the queue.
    /// </summary>
    /// <remarks>
    /// Every method of the Java fixture of this name goes through a generated key pair and <c>XMSSSigner</c>, so
    /// they arrive with the signer. What is here are the same checks one level down, on the state and its codec
    /// directly: a state walked to an index, taken through the codec as an import would take it, and advanced the
    /// way the signer advances it.
    /// </remarks>
    [TestFixture]
    public class CorruptedStateTests
    {
        private const int Height = 4;

        /// <summary>
        /// The harness itself, at both of the indices the corruptions below use: taking a state apart and putting
        /// it back together unchanged leaves a state that still advances.
        /// </summary>
        [Test]
        public void UntouchedStateStillAdvances_Bds()
        {
            int[] indices = new int[]{ 1, 7 };

            for (int i = 0; i != indices.Length; i++)
            {
                Bds state = ImportRebuilt(indices[i], null);

                Assert.AreEqual(indices[i], state.Index);
                Assert.AreEqual(indices[i] + 1, Advance(state).Index);
            }
        }

        /// <summary>
        /// Index 1 is the first index whose next authentication path reads the kept node - tau is 1 there, so the
        /// step needs keep[0], put there by the step at index 0.
        /// </summary>
        [Test]
        public void MissingKeepNodeReported_Bds()
        {
            CheckReported(1, "keep", "missing keep node in BDS state");
        }

        /// <summary>
        /// Index 7 is the first index whose next authentication path reaches into the retain queue - tau is 3
        /// there, and heights at or above treeHeight - k are served from retain rather than from a tree hash
        /// instance.
        /// </summary>
        [Test]
        public void MissingRetainQueueReported_Bds()
        {
            CheckReported(7, "retain", "missing retain node in BDS state");
        }

        /// <summary>A queue that is present but has nothing left in it.</summary>
        [Test]
        public void EmptyRetainQueueReported_Bds()
        {
            CheckReported(7, "retain-empty", "missing retain node in BDS state");
        }

        /// <summary>
        /// The state carries a checksum over itself bound to the owning key's public seed, and every single-bit
        /// change past its eight-byte header is refused by it. A change in the header is refused as well, by the
        /// magic and version check.
        /// </summary>
        [Test]
        public void EveryCorruptionOfTheStateBodyIsRefusedByTheChecksum_Codec()
        {
            XmssParameters p = new XmssParameters(Height, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = BdsStateSerializationTests.Seed(p, 0x00);
            byte[] encoded = BdsStateCodec.Encode(WalkedTo(p, 3), publicSeed);

            for (int i = 8; i != encoded.Length; i++)
            {
                byte[] corrupt = Arrays.Clone(encoded);
                corrupt[i] ^= 0x01;

                IOException e = Assert.Throws<IOException>(() => BdsStateCodec.DecodeBds(corrupt, publicSeed),
                    "corrupt state byte " + i + " accepted");
                Assert.AreEqual("BDS state checksum does not match", e.Message, "byte " + i);
            }

            for (int i = 0; i != 8; i++)
            {
                byte[] corrupt = Arrays.Clone(encoded);
                corrupt[i] ^= 0x01;

                Assert.Throws<IOException>(() => XmssUtilities.Deserialize(corrupt, typeof(Bds), publicSeed),
                    "corrupt state header byte " + i + " accepted");
            }

            // the harness: the encoding these were made from decodes and still advances
            Assert.AreEqual(4, Advance(BdsStateCodec.DecodeBds(encoded, publicSeed)).Index);
        }

        /// <summary>
        /// A state that is internally consistent, taken off a different key of the same parameters, is refused:
        /// the checksum is taken with the owning key's public seed in front of it.
        /// </summary>
        [Test]
        public void StateFromAnotherKeyIsRefused_Codec()
        {
            XmssParameters p = new XmssParameters(Height, NistObjectIdentifiers.IdSha256);
            byte[] theirSeed = BdsStateSerializationTests.Seed(p, 0x40);
            byte[] theirs = BdsStateCodec.Encode(WalkedTo(p, 3), theirSeed);

            IOException e = Assert.Throws<IOException>(
                () => BdsStateCodec.DecodeBds(theirs, BdsStateSerializationTests.Seed(p, 0x00)));
            Assert.AreEqual("BDS state checksum does not match", e.Message);
        }

        private static Bds WalkedTo(XmssParameters p, int index) =>
            new Bds(p, BdsStateSerializationTests.Seed(p, 0x00), BdsStateSerializationTests.Seed(p, 0x80),
                new byte[32], index);

        /// <summary>
        /// The next state, with the digest named first as a key import names it - a decoded state carries no
        /// WOTS+ parameters of its own.
        /// </summary>
        private static Bds Advance(Bds state)
        {
            XmssParameters p = new XmssParameters(Height, NistObjectIdentifiers.IdSha256);

            return state.WithWotsDigest(p.TreeDigestOid, p.TreeDigestSize).GetNextState(
                BdsStateSerializationTests.Seed(p, 0x00), BdsStateSerializationTests.Seed(p, 0x80), new byte[32]);
        }

        private static void CheckReported(int atIndex, string drop, string expected)
        {
            Bds state = ImportRebuilt(atIndex, drop);

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => Advance(state),
                "corrupt state advanced: " + drop);
            Assert.AreEqual(expected, e.Message);
        }

        /// <summary>
        /// A state walked to <paramref name="atIndex"/>, re-encoded with the named part of it removed, and decoded
        /// again as a key import decodes it.
        /// </summary>
        private static Bds ImportRebuilt(int atIndex, string drop)
        {
            XmssParameters p = new XmssParameters(Height, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = BdsStateSerializationTests.Seed(p, 0x00);
            Bds state = BdsStateCodec.DecodeBds(BdsStateCodec.Encode(WalkedTo(p, atIndex), publicSeed), publicSeed);

            Assert.AreEqual(atIndex, state.Index);

            // the state's own collections rather than copies of them, so each corruption replaces one and none of
            // them changes one in place; the field by field constructor below adopts what it is handed
            SortedDictionary<int, XmssNode> keep = state.LiveKeep;
            SortedDictionary<int, List<XmssNode>> retain = state.LiveRetain;

            if ("keep".Equals(drop))
            {
                Assert.IsFalse(keep.Count == 0, "nothing kept at index " + atIndex);
                keep = new SortedDictionary<int, XmssNode>();
            }
            else if ("retain".Equals(drop))
            {
                Assert.IsFalse(retain.Count == 0, "nothing retained at index " + atIndex);
                retain = new SortedDictionary<int, List<XmssNode>>();
            }
            else if ("retain-empty".Equals(drop))
            {
                SortedDictionary<int, List<XmssNode>> emptied = new SortedDictionary<int, List<XmssNode>>();
                foreach (int height in retain.Keys)
                {
                    emptied.Add(height, new List<XmssNode>());
                }

                Assert.IsFalse(emptied.Count == 0, "nothing retained at index " + atIndex);
                retain = emptied;
            }
            else if (drop != null)
            {
                Assert.Fail("unknown corruption: " + drop);
            }

            Bds rebuilt = new Bds(state.TreeHeight, state.K, state.MaxIndex, state.Index, state.IsUsed, state.Root,
                state.LiveAuthenticationPath, retain, state.LiveStack, state.LiveTreeHashInstances, keep);

            return BdsStateCodec.DecodeBds(BdsStateCodec.Encode(rebuilt, publicSeed), publicSeed);
        }
    }
}
