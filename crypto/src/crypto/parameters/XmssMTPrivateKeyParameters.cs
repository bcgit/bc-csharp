using System;
using System.IO;
using System.Threading;

using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// XMSS^MT private key (RFC 8391 sec. 4.2.2), with the per-layer BDS traversal states that make it stateful.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every one-time key under the hypertree may be used once only (RFC 8391 sec. 1.1). The position this key has
    /// reached is recorded twice - in its index, and in the per-layer traversal states beside it - and the two are
    /// compared when the key is built, every time it moves and before it is encoded. Signing, <see cref="RollKey"/>
    /// and <see cref="ExtractKeyShard"/> all move both under this object's lock, which is the lock a signature is
    /// taken under.
    /// </para>
    /// <para>
    /// The encoding <see cref="GetEncoded"/> produces holds the secret seeds and the position; a key restored from an
    /// encoding taken before a signature signs again at an index already used. Store the key after each use.
    /// </para>
    /// </remarks>
    public sealed class XmssMTPrivateKeyParameters
        : XmssMTKeyParameters, IEncodable
    {
        private readonly XmssMTParameters m_params;
        /// <summary>Secret for the derivation of WOTS+ secret keys.</summary>
        private readonly byte[] m_secretKeySeed;
        /// <summary>Secret for the randomization of message digests during signature creation.</summary>
        private readonly byte[] m_secretKeyPrf;
        /// <summary>Public seed for the randomization of hashes.</summary>
        private readonly byte[] m_publicSeed;
        /// <summary>Public root of the top layer's tree.</summary>
        private readonly byte[] m_root;

        /// <summary>
        /// The global index; written under this object's lock and read through <see cref="Interlocked"/>, so a
        /// reader on a 32-bit runtime never sees half of one write.
        /// </summary>
        private long m_index;
        /// <summary>BDS state map.</summary>
        private volatile BdsStateMap m_bdsState;

        private volatile bool m_destroyed;

        private XmssMTPrivateKeyParameters(Builder builder)
            : base(true, builder.m_params)
        {
            m_params = builder.m_params;

            int n = m_params.TreeDigestSize;
            byte[] privateKey = builder.m_privateKey;
            if (privateKey != null)
            {
                /* import */
                int totalHeight = m_params.Height;
                XmssPrivateKeyCodec codec = XmssPrivateKeyCodec.Decode(privateKey,
                    XmssPrivateKeyCodec.MtIndexSize(totalHeight), totalHeight, n);

                m_index = codec.Index;
                m_secretKeySeed = codec.SecretKeySeed;
                m_secretKeyPrf = codec.SecretKeyPrf;
                m_publicSeed = codec.PublicSeed;
                m_root = codec.Root;
                byte[] bdsStateBinary = codec.BdsState;

                try
                {
                    BdsStateMap bdsImport = XmssEngine.GetBdsStateMapFromEncoding(bdsStateBinary, m_publicSeed);

                    // bc-java marks a state map written before the maximum index was recorded with a negative one,
                    // to be resolved here against the parameter set. Only its legacy Java-serialized form can carry
                    // that, and that form is not read here, but the resolution is kept beside the builder's.
                    long stateMaxIndex = (bdsImport.MaxIndex < 0) ? (1L << totalHeight) - 1 : bdsImport.MaxIndex;

                    // the WOTS+ parameters are not part of what was serialized, so the digest goes back on - in the
                    // same copy that carries the maximum index. Nothing is done with the decoded map before this.
                    XmssParameters xmss = m_params.XmssParameters;

                    m_bdsState = bdsImport.WithMaxIndex(stateMaxIndex, xmss.TreeDigestOid, xmss.TreeDigestSize);
                    m_bdsState.Validate(m_params, m_index, m_publicSeed, m_secretKeySeed);
                    m_bdsState.ValidateRoot(m_params, m_root);
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (InvalidOperationException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
            }
            else
            {
                /* set */
                m_index = builder.m_index;
                // copies of the builder's arrays rather than the arrays themselves: a builder can build more than one
                // key, and keys sharing their secret arrays would share a Destroy() - one key's would wipe the seeds
                // the other goes on signing with, spending its indices on signatures that do not verify
                byte[] tmpSecretKeySeed = builder.m_secretKeySeed;
                m_secretKeySeed = Arrays.Clone(XmssEngine.ValidateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed"));
                byte[] tmpSecretKeyPrf = builder.m_secretKeyPrf;
                m_secretKeyPrf = Arrays.Clone(XmssEngine.ValidateOrAllocate(tmpSecretKeyPrf, n, "secretKeyPRF"));
                byte[] tmpPublicSeed = builder.m_publicSeed;
                m_publicSeed = Arrays.Clone(XmssEngine.ValidateOrAllocate(tmpPublicSeed, n, "publicSeed"));
                byte[] tmpRoot = builder.m_root;
                m_root = Arrays.Clone(XmssEngine.ValidateOrAllocate(tmpRoot, n, "root"));
                BdsStateMap tmpBdsState = builder.m_bdsState;
                if (tmpBdsState != null)
                {
                    // likewise the traversal state map, whose layers a signature marks and installs into in place: a
                    // map handed to the builder is copied for each key built, and only a map built for this one key
                    // is adopted, once
                    if (builder.m_bdsStateOwned)
                    {
                        m_bdsState = tmpBdsState;
                        builder.m_bdsStateOwned = false;
                    }
                    else
                    {
                        m_bdsState = tmpBdsState.WithMaxIndex(tmpBdsState.MaxIndex, m_params.TreeDigestOid,
                            m_params.TreeDigestSize);
                    }
                }
                else
                {
                    m_bdsState = XmssEngine.CreateBdsStateMap(m_params, tmpPublicSeed, tmpSecretKeySeed,
                        builder.m_index);
                }
                if (builder.m_maxIndex >= 0 && builder.m_maxIndex != m_bdsState.MaxIndex)
                    throw new ArgumentException("maxIndex set but not reflected in state");
                // whatever the state came from: with a state map, the index check below compares only the low bits of
                // each layer's position, and an empty map compares nothing, so a negative index or one past the end
                // would otherwise build a key that signs outside its range
                if (!XmssEngine.IsStoredIndexValid(m_params.Height, builder.m_index)
                    || builder.m_index > m_bdsState.MaxIndex + 1)
                {
                    throw new ArgumentException("index out of bounds");
                }

                try
                {
                    m_bdsState.Validate(m_params, builder.m_index, m_publicSeed, m_secretKeySeed);
                    // a map built here from the seeds has its top layer, whose root is the one they compute, so a
                    // wrong root is refused whichever way the map arrived; only a spent key's empty map has none
                    m_bdsState.ValidateRoot(m_params, builder.m_root);
                }
                catch (InvalidOperationException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
            }
        }

        /// <summary>The encoding of this key, its traversal state map included.</summary>
        /// <exception cref="InvalidOperationException">If the key has been destroyed, or if its index is the
        /// exhausted position of a hypertree whose total height is a multiple of eight, which the index field of the
        /// encoding is one bit too narrow for.</exception>
        public byte[] GetEncoded()
        {
            lock (this)
            {
                CheckDestroyed();

                // the two records of the position are about to be written out beside each other, and a stored key
                // that disagrees with itself is refused on the way back in, so say so here rather than persisting one
                // that cannot be read
                ValidateIndex();

                XmssPrivateKeyCodec.State state = GetState();

                return XmssPrivateKeyCodec.Encode(state.Index, XmssPrivateKeyCodec.MtIndexSize(m_params.Height),
                    m_secretKeySeed, m_secretKeyPrf, m_publicSeed, m_root, state.Encoded);
            }
        }

        /// <remarks>
        /// The builder keeps copies of the secret seeds, and of an encoding, so that it can build more than one key;
        /// they live as long as the builder does, which is best kept short.
        /// </remarks>
        public sealed class Builder
        {
            /* mandatory */
            internal readonly XmssMTParameters m_params;
            /* optional */
            internal long m_index = 0L;
            internal long m_maxIndex = -1L;
            internal byte[] m_secretKeySeed = null;
            internal byte[] m_secretKeyPrf = null;
            internal byte[] m_publicSeed = null;
            internal byte[] m_root = null;
            internal BdsStateMap m_bdsState = null;
            internal bool m_bdsStateOwned = false;
            internal byte[] m_privateKey = null;

            /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
            public Builder(XmssMTParameters parameters)
            {
                m_params = parameters ?? throw new ArgumentNullException(nameof(parameters), "params == null");
            }

            /// <summary>
            /// The index to rebuild a lost traversal state at, from the seeds: the hypertree is walked to it, so it is
            /// bounded by 2^h first.
            /// </summary>
            /// <remarks>
            /// <para>
            /// The walk advances the traversal state one index at a time, so its cost grows with the index: rebuilding
            /// deep into a large hypertree can take far longer than signing there.
            /// </para>
            /// <para>
            /// A key rebuilt at an index signs from that index on: rebuilding at one already used signs a second
            /// message with the same one-time key, which RFC 8391 sec. 1.1 makes a private key compromise.
            /// </para>
            /// </remarks>
            public Builder WithIndex(long val)
            {
                m_index = val;
                return this;
            }

            /// <summary>
            /// The maximum index the state map must carry. Only a map supplied inside the assembly can carry one short
            /// of the last leaf, so a public caller has no use for it.
            /// </summary>
            internal Builder WithMaxIndex(long val)
            {
                m_maxIndex = val;
                return this;
            }

            public Builder WithSecretKeySeed(byte[] val)
            {
                m_secretKeySeed = Arrays.Clone(val);
                return this;
            }

            public Builder WithSecretKeyPrf(byte[] val)
            {
                m_secretKeyPrf = Arrays.Clone(val);
                return this;
            }

            public Builder WithPublicSeed(byte[] val)
            {
                m_publicSeed = Arrays.Clone(val);
                return this;
            }

            public Builder WithRoot(byte[] val)
            {
                m_root = Arrays.Clone(val);
                return this;
            }

            /// <summary>Copy, do not adopt, the traversal state map.</summary>
            /// <remarks>
            /// Rolling the key replaces its state map rather than advancing the one it holds, but signing still
            /// installs subtree states into that map as it descends the layers, so a caller that keeps the map it
            /// passed - or passes one taken off another key - would leave two keys reading authentication paths out
            /// of one map while each sits at its own index. The copy names this key's tree digest, so a state map
            /// that has just been decoded, and carries no WOTS+ instances yet, is given them here.
            /// </remarks>
            internal Builder WithBdsState(BdsStateMap val)
            {
                m_bdsState = val.WithMaxIndex(MaxIndexFor(val), m_params.TreeDigestOid, m_params.TreeDigestSize);
                m_bdsStateOwned = false;
                return this;
            }

            /// <summary>
            /// As <see cref="WithBdsState"/>, for a state map the caller has just built and shares with nothing: it
            /// is adopted rather than copied a second time - by the first key built; a further Build() copies it. The
            /// maximum index arrives with the map.
            /// </summary>
            internal Builder WithOwnedBdsState(BdsStateMap val)
            {
                m_bdsState = val;
                m_bdsStateOwned = true;
                return this;
            }

            /// <summary>
            /// The maximum index a state map handed to this builder should end up with: its own, or - for one marked
            /// as written before the maximum index was recorded - the last leaf of the key's own hypertree.
            /// </summary>
            private long MaxIndexFor(BdsStateMap val) =>
                (val.MaxIndex < 0) ? (1L << m_params.Height) - 1 : val.MaxIndex;

            public Builder WithPrivateKey(byte[] privateKeyVal)
            {
                m_privateKey = Arrays.Clone(privateKeyVal);
                return this;
            }

            /// <summary>
            /// Wipe the builder's own copies of the secret seeds and of an encoding, for a caller inside the assembly
            /// that is done with it: every key built has copies of its own, so this leaves them whole. A builder
            /// cleared builds nothing further.
            /// </summary>
            internal void ClearSecrets()
            {
                m_secretKeySeed = XmssEngine.Wipe(m_secretKeySeed);
                m_secretKeyPrf = XmssEngine.Wipe(m_secretKeyPrf);
                m_privateKey = XmssEngine.Wipe(m_privateKey);
            }

            /// <remarks>
            /// An encoding given with <see cref="WithPrivateKey"/> supplies every field, and the other inputs are
            /// then ignored.
            /// </remarks>
            /// <exception cref="InvalidOperationException">If neither an encoding nor both seeds and the root were
            /// given.</exception>
            /// <exception cref="ArgumentException">If a field, the encoding or the index is not valid for the
            /// parameter set, or the root is not the one the seeds compute.</exception>
            public XmssMTPrivateKeyParameters Build()
            {
                if (!((m_privateKey != null) || (m_publicSeed != null && m_secretKeySeed != null)))
                    throw new InvalidOperationException("publicSeed or secretKeySeed is null");
                // the root keys H_msg, so a key without one would spend its one-time keys on signatures that verify
                // under no public key
                if (m_privateKey == null && m_root == null)
                    throw new InvalidOperationException("root is null");

                return new XmssMTPrivateKeyParameters(this);
            }
        }

        /// <summary>
        /// Compare the two records of this key's position - the index, and the per-layer traversal states - and
        /// refuse a key whose two disagree.
        /// </summary>
        /// <exception cref="InvalidOperationException">If they disagree.</exception>
        internal void ValidateIndex()
        {
            lock (this)
            {
                m_bdsState.ValidateIndex(m_params, Index, m_publicSeed, m_secretKeySeed);
            }
        }

        /// <summary>The global index of the next one-time key this key will sign with.</summary>
        public long Index => Interlocked.Read(ref m_index);

        /// <summary>The number of signatures this key can still make.</summary>
        public long GetUsagesRemaining()
        {
            lock (this)
            {
                return m_bdsState.MaxIndex - Index + 1;
            }
        }

        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public byte[] GetSecretKeySeed() => CloneWithCheck(m_secretKeySeed);

        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public byte[] GetSecretKeyPrf() => CloneWithCheck(m_secretKeyPrf);

        public byte[] GetPublicSeed() => Arrays.Clone(m_publicSeed);

        public byte[] GetRoot() => Arrays.Clone(m_root);

        internal BdsStateMap GetBdsState() => m_bdsState;

        /// <summary>A key for this key's current index alone; this key moves on past it.</summary>
        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public XmssMTPrivateKeyParameters GetNextKey()
        {
            lock (this)
            {
                return ExtractKeyShard(1);
            }
        }

        /// <summary>Move this key on to its next index, in place, and return it.</summary>
        /// <remarks>
        /// <para>
        /// Past the last leaf the key is left on an empty state map one past its maximum index, where it reports no
        /// usages remaining rather than wrapping round.
        /// </para>
        /// <para>
        /// The advanced state comes back as a new map rather than being applied to the one held, so the index and
        /// the state move together: nothing is assigned unless the walk completed. The map given up is wiped once
        /// its successor is in place - it can hold the WOTS+ secret key of a leaf this key has yet to sign with - and
        /// the two records of the position are compared again, so a roll that advanced one and not the other is
        /// refused here rather than surfacing as a one-time key signing twice.
        /// </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public XmssMTPrivateKeyParameters RollKey()
        {
            lock (this)
            {
                CheckDestroyed();

                BdsStateMap replaced = m_bdsState;
                long index = Index;

                if (index < replaced.MaxIndex)
                {
                    m_bdsState = XmssEngine.GetNextBdsStateMap(replaced, m_params, index, m_publicSeed,
                        m_secretKeySeed);
                    Interlocked.Exchange(ref m_index, index + 1);
                }
                else
                {
                    Interlocked.Exchange(ref m_index, replaced.MaxIndex + 1);
                    m_bdsState = new BdsStateMap(replaced.MaxIndex);
                }

                // wiped only now, its successor installed: that is built from it, and a roll that throws keeps it -
                // the order is required, do not move this above the install
                XmssEngine.ClearSecrets(replaced);

                ValidateIndex();

                return this;
            }
        }

        /// <summary>Return a key that can be used usageCount times.</summary>
        /// <remarks>
        /// This will use the range [index...index + usageCount) for the current key, which moves on to
        /// index + usageCount.
        /// </remarks>
        /// <param name="usageCount">the number of usages the key should have.</param>
        /// <returns>a key based on the current key that can be used usageCount times.</returns>
        /// <exception cref="ArgumentException">If <paramref name="usageCount"/> is less than one or more than this
        /// key has left.</exception>
        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public XmssMTPrivateKeyParameters ExtractKeyShard(int usageCount)
        {
            lock (this)
            {
                CheckDestroyed();

                // inside the lock because the count it is checked against is this key's
                XmssEngine.ValidateShardSize(usageCount, GetUsagesRemaining());

                /* prepare authentication path for next leaf */
                long index = Index;
                Builder builder = new Builder(m_params)
                    .WithSecretKeySeed(m_secretKeySeed).WithSecretKeyPrf(m_secretKeyPrf)
                    .WithPublicSeed(m_publicSeed).WithRoot(m_root)
                    .WithIndex(index)
                    .WithOwnedBdsState(new BdsStateMap(m_bdsState, index + usageCount - 1));
                XmssMTPrivateKeyParameters keyParams;
                try
                {
                    keyParams = builder.Build();
                }
                finally
                {
                    // a Build() that throws has still been handed the secrets
                    builder.ClearSecrets();
                }

                // each roll wipes the map it gives up; the shard's map is a copy whose every layer has a WOTS+
                // instance of its own, so that leaves it whole
                for (int i = 0; i != usageCount; i++)
                {
                    RollKey();
                }

                return keyParams;
            }
        }

        /// <summary>
        /// Whether these are the same key at the same position, which for a stateful key means the same traversal
        /// state too.
        /// </summary>
        /// <remarks>
        /// Each key's fields are read under its own lock, never both at once; the state is compared only when the
        /// fields agree, because producing it means encoding a whole state map on both keys.
        /// </remarks>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(this, obj))
                return true;
            if (!(obj is XmssMTPrivateKeyParameters that))
                return false;

            return XmssPrivateKeyCodec.FieldsEqual(this.GetFields(), that.GetFields())
                && XmssPrivateKeyCodec.StateEqual(this.GetState(), that.GetState());
        }

        /// <summary>
        /// The values <see cref="XmssPrivateKeyCodec.FieldsEqual"/> decides on, read from this key under its own
        /// lock. The index and the usages remaining are both taken from state a signature replaces, so they are read
        /// in one block.
        /// </summary>
        private XmssPrivateKeyCodec.Fields GetFields()
        {
            lock (this)
            {
                return new XmssPrivateKeyCodec.Fields(m_params.TreeDigestOid, Index, GetUsagesRemaining(),
                    m_publicSeed, m_root, m_secretKeySeed, m_secretKeyPrf);
            }
        }

        /// <summary>
        /// This key's traversal state map, encoded, beside the index it is the state for - the pair
        /// <see cref="GetEncoded"/> writes out and the pair <see cref="Equals(object)"/> ends on.
        /// </summary>
        private XmssPrivateKeyCodec.State GetState()
        {
            lock (this)
            {
                try
                {
                    return new XmssPrivateKeyCodec.State(Index,
                        XmssEngine.GetEncodedBdsState(m_bdsState, m_publicSeed));
                }
                catch (IOException e)
                {
                    throw new InvalidOperationException("error encoding BDS state map", e);
                }
            }
        }

        /// <summary>
        /// The fields that do not move as this key signs, hashed: the tree digest, the root and the public seed.
        /// </summary>
        public override int GetHashCode() => XmssPrivateKeyCodec.GetHashCode(m_params.TreeDigestOid, m_root,
            m_publicSeed);

        /// <summary>
        /// Destroy this key, zeroizing the secret key material it holds: the seed the WOTS+ secret keys are derived
        /// from, the PRF key that randomizes message digests, and the WOTS+ secret keys the per-layer BDS traversal
        /// states retain for the leaves they last processed.
        /// </summary>
        /// <remarks>
        /// The public seed, the root, the index and the traversal states' tree nodes are retained - none of them is
        /// secret. After destruction <see cref="IsDestroyed"/> is true and <see cref="GetSecretKeySeed"/>,
        /// <see cref="GetSecretKeyPrf"/>, <see cref="GetEncoded"/>, <see cref="RollKey"/>, <see cref="GetNextKey"/>
        /// and <see cref="ExtractKeyShard"/> throw <see cref="InvalidOperationException"/>; a signature attempt fails
        /// before the index is advanced. Keys previously split off this one hold their own copies of the seeds and
        /// are unaffected.
        /// </remarks>
        public void Destroy()
        {
            lock (this)
            {
                if (!m_destroyed)
                {
                    m_destroyed = true;
                    Arrays.ZeroMemory(m_secretKeySeed);
                    Arrays.ZeroMemory(m_secretKeyPrf);
                    XmssEngine.ClearSecrets(m_bdsState);
                }
            }
        }

        /// <summary>Whether <see cref="Destroy"/> has been called.</summary>
        public bool IsDestroyed => m_destroyed;

        /// <summary>The secret key seed this key holds, by reference rather than as a checked copy.</summary>
        /// <remarks>For a test asserting <see cref="Destroy"/> wiped it; nothing else may use it.</remarks>
        internal byte[] LiveSecretKeySeed => m_secretKeySeed;

        /// <summary>The PRF key this key holds, by reference rather than as a checked copy.</summary>
        /// <remarks>For a test asserting <see cref="Destroy"/> wiped it; nothing else may use it.</remarks>
        internal byte[] LiveSecretKeyPrf => m_secretKeyPrf;

        private byte[] CloneWithCheck(byte[] fieldValue)
        {
            // under the lock Destroy() takes, so a copy is never taken of an array part way through being wiped
            lock (this)
            {
                CheckDestroyed();

                return Arrays.Clone(fieldValue);
            }
        }

        private void CheckDestroyed()
        {
            if (m_destroyed)
                throw new InvalidOperationException("key destroyed");
        }
    }
}
