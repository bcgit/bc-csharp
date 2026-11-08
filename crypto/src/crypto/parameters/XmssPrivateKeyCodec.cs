using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>The wire form an XMSS and an XMSS^MT private key share.</summary>
    /// <remarks>
    /// <para>
    /// Neither family's private key is a standardised encoding - RFC 8391 sec. 4.1.3 and sec. 4.2.2 describe what a
    /// private key holds and leave how it is stored to the implementation, and NIST SP 800-208 sec. 6 says only that
    /// the traversal state has to be stored with it - so this is BC's own layout, byte for byte the one bc-java
    /// writes:
    /// </para>
    /// <code>
    ///     index || secretKeySeed || secretKeyPRF || publicSeed || root || BDS traversal state
    /// </code>
    /// <para>
    /// The four seed and root fields are n bytes each and the traversal state is variable length and last, so only
    /// the head is fixed and only the head can be length checked. What differs between the families is the width
    /// of the index field: <see cref="XmssIndexSize"/>, and the XMSS^MT width beside it once that family exists.
    /// </para>
    /// <para>
    /// The equality and hash code both key classes share are here too, as <see cref="FieldsEqual"/> over a
    /// <see cref="Fields"/> snapshot and <see cref="StateEqual"/> over a <see cref="State"/> one.
    /// </para>
    /// </remarks>
    internal sealed class XmssPrivateKeyCodec
    {
        /// <summary>The width of an XMSS index field, four bytes whatever the tree height.</summary>
        /// <remarks>
        /// It always suffices: <see cref="XmssParameters.MaxHeight"/> is 30, so the largest index a key can hold -
        /// 2^h, the position an exhausted key sits at, one past its last leaf - is 2^30.
        /// </remarks>
        internal const int XmssIndexSize = 4;

        private readonly long m_index;
        private readonly byte[] m_secretKeySeed;
        private readonly byte[] m_secretKeyPrf;
        private readonly byte[] m_publicSeed;
        private readonly byte[] m_root;
        private readonly byte[] m_bdsState;

        private XmssPrivateKeyCodec(long index, byte[] secretKeySeed, byte[] secretKeyPrf, byte[] publicSeed,
            byte[] root, byte[] bdsState)
        {
            m_index = index;
            m_secretKeySeed = secretKeySeed;
            m_secretKeyPrf = secretKeyPrf;
            m_publicSeed = publicSeed;
            m_root = root;
            m_bdsState = bdsState;
        }

        /// <summary>Read a private key encoding, taking the index from a field of the given width.</summary>
        /// <remarks>
        /// Only the head is fixed - the serialized traversal state that follows it is variable length - so what can
        /// be checked here is that the head is all there.
        /// </remarks>
        /// <param name="privateKey">the encoding.</param>
        /// <param name="indexSize">the width of the index field, in bytes.</param>
        /// <param name="totalHeight">the height the index is bounded by.</param>
        /// <param name="n">the security parameter of the key's parameter set, in bytes.</param>
        internal static XmssPrivateKeyCodec Decode(byte[] privateKey, int indexSize, int totalHeight, int n)
        {
            if (privateKey.Length < indexSize + 4 * n)
                throw new ArgumentException("private key has wrong size");

            int position = 0;
            long index = (long)Pack.BE_To_UInt64_Low(privateKey, position, indexSize);
            if (!XmssEngine.IsStoredIndexValid(totalHeight, index))
                throw new ArgumentException("index out of bounds");

            position += indexSize;
            byte[] secretKeySeed = Arrays.CopyOfRange(privateKey, position, position + n);
            position += n;
            byte[] secretKeyPrf = Arrays.CopyOfRange(privateKey, position, position + n);
            position += n;
            byte[] publicSeed = Arrays.CopyOfRange(privateKey, position, position + n);
            position += n;
            byte[] root = Arrays.CopyOfRange(privateKey, position, position + n);
            position += n;
            byte[] bdsState = Arrays.CopyOfRange(privateKey, position, privateKey.Length);

            return new XmssPrivateKeyCodec(index, secretKeySeed, secretKeyPrf, publicSeed, root, bdsState);
        }

        /// <summary>
        /// The encoding of a key holding these fields, with the index written in a field of the given width.
        /// </summary>
        /// <remarks>
        /// The traversal state is encoded by the caller and passed in already serialized. An index the field cannot
        /// hold is refused rather than written narrowed: written narrowed, the exhausted position 2^h of an XMSS^MT
        /// key whose total height is a multiple of eight came back as zero, a key reporting a full tree of unused
        /// one-time keys.
        /// </remarks>
        /// <param name="index">the position the key is at.</param>
        /// <param name="indexSize">the width of the index field, in bytes.</param>
        /// <param name="bdsState">the encoded traversal state.</param>
        internal static byte[] Encode(long index, int indexSize, byte[] secretKeySeed, byte[] secretKeyPrf,
            byte[] publicSeed, byte[] root, byte[] bdsState)
        {
            // shifting by 8 * indexSize rather than comparing against 1L << (8 * indexSize), which at the eight byte
            // width would shift by 64 and produce 1
            if (indexSize < 8 && ((ulong)index >> (8 * indexSize)) != 0)
            {
                throw new InvalidOperationException("index " + index + " does not fit the " + indexSize
                    + " byte index field of a stored private key");
            }

            /* index || secretKeySeed || secretKeyPRF || publicSeed || root || bdsState */
            byte[] output = new byte[indexSize + secretKeySeed.Length + secretKeyPrf.Length + publicSeed.Length
                + root.Length + bdsState.Length];
            int position = 0;

            /* copy index */
            Pack.UInt64_To_BE_Low((ulong)index, output, position, indexSize);
            position += indexSize;
            /* copy secretKeySeed */
            Array.Copy(secretKeySeed, 0, output, position, secretKeySeed.Length);
            position += secretKeySeed.Length;
            /* copy secretKeyPRF */
            Array.Copy(secretKeyPrf, 0, output, position, secretKeyPrf.Length);
            position += secretKeyPrf.Length;
            /* copy publicSeed */
            Array.Copy(publicSeed, 0, output, position, publicSeed.Length);
            position += publicSeed.Length;
            /* copy root */
            Array.Copy(root, 0, output, position, root.Length);
            position += root.Length;
            /* copy bdsState */
            Array.Copy(bdsState, 0, output, position, bdsState.Length);

            return output;
        }

        internal long Index => m_index;

        internal byte[] SecretKeySeed => m_secretKeySeed;

        internal byte[] SecretKeyPrf => m_secretKeyPrf;

        internal byte[] PublicSeed => m_publicSeed;

        internal byte[] Root => m_root;

        internal byte[] BdsState => m_bdsState;

        /// <summary>
        /// A snapshot of everything a private key's Equals() decides on ahead of its traversal state, read from one
        /// key under that key's own lock.
        /// </summary>
        /// <remarks>
        /// A key's index and its usages remaining are read together, under the lock a signature is taken under,
        /// because both come from state a signature replaces. The four arrays are never written after construction
        /// (Destroy() aside, which zeroes them in place), so capturing the references says as much as copying the
        /// arrays would - which is what lets each key be read in one block of its own rather than one lock being held
        /// across both, where a.Equals(b) on one thread and b.Equals(a) on another could deadlock.
        /// </remarks>
        internal sealed class Fields
        {
            internal readonly DerObjectIdentifier m_treeDigestOid;
            internal readonly long m_index;
            internal readonly long m_usagesRemaining;
            internal readonly byte[] m_publicSeed;
            internal readonly byte[] m_root;
            internal readonly byte[] m_secretKeySeed;
            internal readonly byte[] m_secretKeyPrf;

            internal Fields(DerObjectIdentifier treeDigestOid, long index, long usagesRemaining, byte[] publicSeed,
                byte[] root, byte[] secretKeySeed, byte[] secretKeyPrf)
            {
                m_treeDigestOid = treeDigestOid;
                m_index = index;
                m_usagesRemaining = usagesRemaining;
                m_publicSeed = publicSeed;
                m_root = root;
                m_secretKeySeed = secretKeySeed;
                m_secretKeyPrf = secretKeyPrf;
            }
        }

        /// <summary>
        /// Whether two keys agree on all seven, with every array among them compared in constant time.
        /// </summary>
        /// <remarks>
        /// The chain is joined with <c>&amp;</c> rather than <c>&amp;&amp;</c>, so all of it is evaluated whatever the
        /// two keys are: short circuited, how long it takes would say which of the fields the two keys first disagree
        /// on, and two of those fields are secret material. What is left in the timing is the bit this decides, which
        /// says whether <see cref="StateEqual"/> runs at all; two keys that get there agree on both secret seeds.
        /// </remarks>
        internal static bool FieldsEqual(Fields a, Fields b)
        {
            return a.m_treeDigestOid.Equals(b.m_treeDigestOid)
                & a.m_index == b.m_index
                & a.m_usagesRemaining == b.m_usagesRemaining
                & Arrays.FixedTimeEquals(a.m_publicSeed, b.m_publicSeed)
                & Arrays.FixedTimeEquals(a.m_root, b.m_root)
                & Arrays.FixedTimeEquals(a.m_secretKeySeed, b.m_secretKeySeed)
                & Arrays.FixedTimeEquals(a.m_secretKeyPrf, b.m_secretKeyPrf);
        }

        /// <summary>
        /// A snapshot of a key's traversal state as an encoding of it would carry it, beside the position that state
        /// is the state for.
        /// </summary>
        /// <remarks>
        /// The state is the one part of a key's content <see cref="FieldsEqual"/> cannot reach: it carries a mark
        /// saying the one-time key at its index has already signed, and no accessor reports it. It is read under the
        /// key's own lock, the one a signature is held under.
        /// </remarks>
        internal sealed class State
        {
            private readonly long m_index;
            private readonly byte[] m_encoded;

            internal State(long index, byte[] encoded)
            {
                m_index = index;
                m_encoded = encoded;
            }

            internal long Index => m_index;

            internal byte[] Encoded => m_encoded;
        }

        /// <summary>
        /// Whether two keys are at one position holding one traversal state, the two state encodings compared in
        /// constant time.
        /// </summary>
        internal static bool StateEqual(State a, State b) =>
            a.Index == b.Index & Arrays.FixedTimeEquals(a.Encoded, b.Encoded);

        /// <summary>
        /// The hash of the fields that do not move as a key signs: the tree digest, the root and the public seed.
        /// Keys <see cref="FieldsEqual"/> and <see cref="StateEqual"/> call equal agree on all three. The secret
        /// seeds are left out: a hash of secret material is a commitment to it, published wherever the hash goes.
        /// </summary>
        internal static int GetHashCode(DerObjectIdentifier treeDigestOid, byte[] root, byte[] publicSeed)
        {
            int hc = treeDigestOid.GetHashCode();
            hc = 31 * hc + Arrays.GetHashCode(root);
            hc = 31 * hc + Arrays.GetHashCode(publicSeed);
            return hc;
        }
    }
}
