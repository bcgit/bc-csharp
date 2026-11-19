using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The BDS traversal state stored with a private key carries two collections the next authentication path reads
    /// from - the node kept when the path last passed a height, and the queue of retained right nodes - and a state
    /// that reached its index by signing always has the entries the next step will ask for. A state that arrived by
    /// import need not: the structural checks the encoding and the state's validation make reject entries that are
    /// present and wrong, but say nothing about ones that are simply absent, and the reads say what is wrong rather
    /// than failing inside the hash function or the queue.
    /// </summary>
    [TestFixture]
    public class CorruptedStateTests
    {
        private const int Height = 4;

        /// <summary>
        /// The harness itself: taking a key apart and putting it back together unchanged has to leave a key that
        /// still signs, or the corruption tests below would pass for the wrong reason. At both of the indices they
        /// use, since what each of them removes is read at one of the two.
        /// </summary>
        [Test]
        public void TestUntouchedStateStillSigns()
        {
            int[] indices = new int[]{ 1, 7 };

            for (int i = 0; i != indices.Length; i++)
            {
                XmssPrivateKeyParameters privKey = ImportRebuilt(indices[i], null);

                Assert.AreEqual(indices[i], privKey.Index);

                XmssSigner signer = new XmssSigner();

                signer.Init(true, privKey);
                signer.Update(9);
                signer.GenerateSignature();

                Assert.AreEqual(indices[i] + 1, ((XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey()).Index);
            }
        }

        /// <summary>
        /// Index 1 is the first index whose next authentication path reads the kept node - tau is 1 there, so the
        /// step needs keep[0], put there by the step at index 0.
        /// </summary>
        [Test]
        public void TestMissingKeepNodeReported()
        {
            CheckReported(1, "keep", "missing keep node in BDS state");
        }

        /// <summary>
        /// Index 7 is the first index whose next authentication path reaches into the retain queue - tau is 3 there,
        /// and heights at or above treeHeight - k are served from retain rather than from a tree hash instance.
        /// </summary>
        [Test]
        public void TestMissingRetainQueueReported()
        {
            CheckReported(7, "retain", "missing retain node in BDS state");
        }

        /// <summary>A queue that is present but has nothing left in it: structurally valid.</summary>
        [Test]
        public void TestEmptyRetainQueueReported()
        {
            CheckReported(7, "retain-empty", "missing retain node in BDS state");
        }

        /// <summary>
        /// The state carries a checksum over itself bound to the owning key's public seed, and every single-byte
        /// change past its eight-byte header is refused by it. The header is the other eight bytes: a change there is
        /// not recognised as a state encoding at all, and is refused for that.
        /// </summary>
        /// <remarks>
        /// What this is not is integrity protection - anyone able to rewrite the stored key recomputes it (github
        /// #2414).
        /// </remarks>
        [Test]
        public void TestEveryCorruptionOfTheStateBodyIsRefusedByTheChecksum()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            byte[] encoded = SignedTo(parameters, 3);
            int stateOffset = 4 + 4 * parameters.TreeDigestSize;

            for (int i = stateOffset + 8; i != encoded.Length; i++)
            {
                byte[] corrupt = Arrays.Clone(encoded);

                corrupt[i] ^= 0x01;

                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "corrupt state byte " + i + " accepted");
                Assert.AreEqual("BDS state checksum does not match", e.Message, "byte " + i);
            }

            for (int i = stateOffset; i != stateOffset + 8; i++)
            {
                byte[] corrupt = Arrays.Clone(encoded);

                corrupt[i] ^= 0x01;

                // refused by the magic and version check
                Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "corrupt state header byte " + i + " accepted");
            }

            // the harness: the encoding these were made from decodes and still signs, or every case above would be
            // passing for a reason of its own
            XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(encoded).Build();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, decoded);
            signer.Update(9);
            Assert.IsNotNull(signer.GenerateSignature());
        }

        /// <summary>
        /// A state that is internally consistent and brings its own matching root, taken off a different key of the
        /// same parameters, is refused too: the checksum is taken with the owning key's public seed in front of it,
        /// so it does not carry across keys.
        /// </summary>
        [Test]
        public void TestStateFromAnotherKeyIsRefused()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            byte[] mine = SignedTo(parameters, 3);
            byte[] theirs = SignedTo(parameters, 3);
            int stateOffset = 4 + 4 * parameters.TreeDigestSize;

            Assert.AreEqual(mine.Length, theirs.Length);

            byte[] transplant = Arrays.Clone(mine);

            Array.Copy(theirs, stateOffset, transplant, stateOffset, theirs.Length - stateOffset);

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(transplant).Build(),
                "state from a different key accepted");
            Assert.AreEqual("BDS state checksum does not match", e.Message);
        }

        /// <summary>A fresh key advanced by <paramref name="signatures"/> signatures, encoded.</summary>
        private static byte[] SignedTo(XmssParameters parameters, int signatures)
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssSigner signer = new XmssSigner();

            signer.Init(true, kpg.GenerateKeyPair().Private);

            for (int i = 0; i != signatures; i++)
            {
                signer.Update((byte)i);
                signer.GenerateSignature();
            }

            return ((XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey()).GetEncoded();
        }

        private static void CheckReported(int atIndex, string drop, string expected)
        {
            XmssPrivateKeyParameters privKey = ImportRebuilt(atIndex, drop);
            XmssSigner signer = new XmssSigner();

            signer.Init(true, privKey);
            signer.Update(9);

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => signer.GenerateSignature(),
                "corrupt state signed: " + drop);
            Assert.AreEqual(expected, e.Message);
        }

        /// <summary>
        /// A private key advanced to <paramref name="atIndex"/>, re-encoded with the named part of its BDS state
        /// removed, and imported again through the ordinary encoded-key path.
        /// </summary>
        private static XmssPrivateKeyParameters ImportRebuilt(int atIndex, string drop)
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);

            for (int i = 0; i != atIndex; i++)
            {
                signer.Update((byte)i);
                signer.GenerateSignature();
            }

            byte[] encoded = ((XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey()).GetEncoded();
            int n = parameters.TreeDigestSize;
            int prefix = 4 + 4 * n;
            byte[] head = Arrays.CopyOfRange(encoded, 0, prefix);
            // head is index(4) || secretKeySeed(n) || secretKeyPRF(n) || publicSeed(n) || root(n)
            byte[] publicSeed = Arrays.CopyOfRange(head, 4 + 2 * n, 4 + 3 * n);
            Bds state = BdsStateCodec.DecodeBds(Arrays.CopyOfRange(encoded, prefix, encoded.Length), publicSeed);

            Assert.AreEqual(atIndex, state.Index);

            // these are the state's own collections rather than copies of them, so each corruption replaces one and
            // none of them changes one in place. The field by field constructor below adopts what it is handed, so the
            // rebuilt state shares the uncorrupted four with the state read from the encoding - which is why that
            // state is not touched again: it is encoded through the rebuilt one on the next line and then dropped.
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

            return new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(Arrays.Concatenate(head, BdsStateCodec.Encode(rebuilt, publicSeed))).Build();
        }
    }
}
