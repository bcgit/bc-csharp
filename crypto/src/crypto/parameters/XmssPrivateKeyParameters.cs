using System;
using System.IO;

using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>XMSS private key (RFC 8391 sec. 4.1.3), with the BDS traversal state that makes it stateful.</summary>
    /// <remarks>
    /// <para>
    /// Every one-time key under the tree may be used once only (RFC 8391 sec. 1.1). The position this key has
    /// reached is its traversal state's index; signing, <see cref="RollKey"/> and <see cref="ExtractKeyShard"/> all
    /// replace that state under this object's lock, which is the lock a signature is taken under.
    /// </para>
    /// <para>
    /// The encoding <see cref="GetEncoded"/> produces holds the secret seeds and the position; a key restored from an
    /// encoding taken before a signature signs again at an index already used. Store the key after each use.
    /// </para>
    /// </remarks>
    public sealed class XmssPrivateKeyParameters
        : XmssKeyParameters, IEncodable
    {
        private readonly XmssParameters m_params;
        /// <summary>Secret for the derivation of WOTS+ secret keys.</summary>
        private readonly byte[] m_secretKeySeed;
        /// <summary>Secret for the randomization of message digests during signature creation.</summary>
        private readonly byte[] m_secretKeyPrf;
        /// <summary>Public seed for the randomization of hashes.</summary>
        private readonly byte[] m_publicSeed;
        /// <summary>Public root of binary tree.</summary>
        private readonly byte[] m_root;
        /// <summary>BDS state.</summary>
        private volatile Bds m_bdsState;

        private volatile bool m_destroyed;

        private XmssPrivateKeyParameters(Builder builder)
            : base(true, builder.m_params)
        {
            m_params = builder.m_params;
            int n = m_params.TreeDigestSize;
            byte[] privateKey = builder.m_privateKey;
            if (privateKey != null)
            {
                /* import */
                XmssPrivateKeyCodec codec = XmssPrivateKeyCodec.Decode(privateKey, XmssPrivateKeyCodec.XmssIndexSize,
                    m_params.Height, n);

                // the codec answers in the width the XMSS^MT index needs; this family's is an int everywhere else in
                // the class, and the index check the codec has already made bounds it by 2^30, so nothing is lost
                // narrowing it here
                int index = (int)codec.Index;
                m_secretKeySeed = codec.SecretKeySeed;
                m_secretKeyPrf = codec.SecretKeyPrf;
                m_publicSeed = codec.PublicSeed;
                m_root = codec.Root;
                byte[] bdsStateBinary = codec.BdsState;
                try
                {
                    Bds bdsImport = XmssEngine.GetBdsFromEncoding(bdsStateBinary, m_publicSeed);
                    // a decoded state carries no WOTS+ instance until it is given the digest its key names; nothing
                    // is done with it before this
                    m_bdsState = bdsImport.WithWotsDigest(m_params.TreeDigestOid, m_params.TreeDigestSize);
                    m_bdsState.Validate(m_params, index);
                    m_bdsState.ValidateRoot(m_root);
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
                Bds tmpBdsState = builder.m_bdsState;
                if (tmpBdsState != null)
                {
                    // likewise the traversal state, which a signature marks in place: a state handed to the builder
                    // is copied for each key built, and only a state built for this one key is adopted, once
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
                    m_bdsState = XmssEngine.CreateBds(m_params, tmpPublicSeed, tmpSecretKeySeed, builder.m_index);
                }
                if (builder.m_maxIndex >= 0 && builder.m_maxIndex != m_bdsState.MaxIndex)
                    throw new ArgumentException("maxIndex set but not reflected in state");

                try
                {
                    m_bdsState.Validate(m_params, builder.m_index);
                    // a state built here from the seeds carries the root they compute, so a wrong root is refused
                    // whichever way the state arrived; only the placeholder of a spent key has no root to compare
                    m_bdsState.ValidateRoot(builder.m_root);
                }
                catch (InvalidOperationException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
            }
        }

        /// <summary>The number of signatures this key can still make.</summary>
        public long GetUsagesRemaining()
        {
            lock (this)
            {
                return m_bdsState.MaxIndex - Index + 1;
            }
        }

        /// <summary>The encoding of this key, its traversal state included.</summary>
        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public byte[] GetEncoded()
        {
            lock (this)
            {
                CheckDestroyed();

                XmssPrivateKeyCodec.State state = GetState();

                return XmssPrivateKeyCodec.Encode(state.Index, XmssPrivateKeyCodec.XmssIndexSize, m_secretKeySeed,
                    m_secretKeyPrf, m_publicSeed, m_root, state.Encoded);
            }
        }

        /// <summary>Move this key on to its next index, in place, and return it.</summary>
        /// <remarks>
        /// Past the last leaf the key is left on the placeholder state for a spent key, one past its maximum index,
        /// where it reports no usages remaining rather than wrapping round.
        /// </remarks>
        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public XmssPrivateKeyParameters RollKey()
        {
            lock (this)
            {
                CheckDestroyed();

                Bds replaced = m_bdsState;

                /* prepare authentication path for next leaf */
                if (replaced.Index < replaced.MaxIndex)
                {
                    m_bdsState = XmssEngine.GetNextBdsState(replaced, m_publicSeed, m_secretKeySeed);
                }
                else
                {
                    // no more nodes left.
                    m_bdsState = new Bds(m_params, replaced.MaxIndex, replaced.MaxIndex + 1);
                }

                // the state given up can still hold the WOTS+ secret key of a leaf this key has yet to sign with
                XmssEngine.ClearSecrets(replaced);

                return this;
            }
        }

        /// <summary>A key for this key's current index alone; this key moves on past it.</summary>
        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public XmssPrivateKeyParameters GetNextKey()
        {
            lock (this)
            {
                return ExtractKeyShard(1);
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
        public XmssPrivateKeyParameters ExtractKeyShard(int usageCount)
        {
            lock (this)
            {
                CheckDestroyed();

                // inside the lock because the count it is checked against is this key's, and a signature landing
                // between the check and the shard would leave the shard covering a leaf already spent.
                long usagesRemaining = GetUsagesRemaining();

                XmssEngine.ValidateShardSize(usageCount, usagesRemaining);

                /* prepare authentication path for next leaf */
                Builder builder = new Builder(m_params)
                    .WithSecretKeySeed(m_secretKeySeed).WithSecretKeyPrf(m_secretKeyPrf)
                    .WithPublicSeed(m_publicSeed).WithRoot(m_root)
                    .WithIndex(Index)
                    .WithOwnedBdsState(m_bdsState.WithMaxIndex(m_bdsState.Index + usageCount - 1,
                        m_params.TreeDigestOid, m_params.TreeDigestSize));
                XmssPrivateKeyParameters keyParams;
                try
                {
                    keyParams = builder.Build();
                }
                finally
                {
                    // a Build() that throws has still been handed the secrets
                    builder.ClearSecrets();
                }

                // each state given up can still hold the WOTS+ secret key of a leaf yet to sign with; the shard's
                // state is a copy with a WOTS+ instance of its own, so wiping these leaves it whole
                if (usageCount == usagesRemaining)
                {
                    // we're finished.
                    Bds replaced = m_bdsState;
                    m_bdsState = new Bds(m_params, replaced.MaxIndex, replaced.Index + usageCount);
                    XmssEngine.ClearSecrets(replaced);
                }
                else
                {
                    // update the tree to the new index.
                    for (int i = 0; i != usageCount; i++)
                    {
                        Bds replaced = m_bdsState;
                        m_bdsState = XmssEngine.GetNextBdsState(replaced, m_publicSeed, m_secretKeySeed);
                        XmssEngine.ClearSecrets(replaced);
                    }
                }

                return keyParams;
            }
        }

        /// <remarks>
        /// The builder keeps copies of the secret seeds, and of an encoding, so that it can build more than one key;
        /// they live as long as the builder does, which is best kept short.
        /// </remarks>
        public sealed class Builder
        {
            /* mandatory */
            internal readonly XmssParameters m_params;
            /* optional */
            internal int m_index = 0;
            internal int m_maxIndex = -1;
            internal byte[] m_secretKeySeed = null;
            internal byte[] m_secretKeyPrf = null;
            internal byte[] m_publicSeed = null;
            internal byte[] m_root = null;
            internal Bds m_bdsState = null;
            internal bool m_bdsStateOwned = false;
            internal byte[] m_privateKey = null;

            /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
            public Builder(XmssParameters parameters)
            {
                m_params = parameters ?? throw new ArgumentNullException(nameof(parameters), "params == null");
            }

            /// <summary>
            /// The index to rebuild a lost traversal state at, from the seeds: the tree is walked to it, so it is
            /// bounded by 2^h first.
            /// </summary>
            /// <remarks>
            /// A key rebuilt at an index signs from that index on: rebuilding at one already used signs a second
            /// message with the same one-time key, which RFC 8391 sec. 1.1 makes a private key compromise.
            /// </remarks>
            public Builder WithIndex(int val)
            {
                m_index = val;
                return this;
            }

            /// <summary>
            /// The maximum index the state must carry. Only a state supplied inside the assembly can carry one short
            /// of the last leaf, so a public caller has no use for it.
            /// </summary>
            internal Builder WithMaxIndex(int val)
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

            /// <summary>Copy, do not adopt, the traversal state.</summary>
            /// <remarks>
            /// Rolling the key replaces its state rather than advancing the one it holds, but a signature still marks
            /// the state it spent in place, so two keys sharing one state would share that record: one key's
            /// signature would mark the other's state, and a caller keeping the state it passed in would see it
            /// marked by a key it handed it to.
            /// </remarks>
            internal Builder WithBdsState(Bds valBds)
            {
                m_bdsState = valBds.WithMaxIndex(valBds.MaxIndex, m_params.TreeDigestOid, m_params.TreeDigestSize);
                m_bdsStateOwned = false;
                return this;
            }

            /// <summary>
            /// As <see cref="WithBdsState"/>, for a state the caller has just built and shares with nothing: it is
            /// adopted rather than copied a second time - by the first key built; a further Build() copies it.
            /// </summary>
            internal Builder WithOwnedBdsState(Bds valBds)
            {
                m_bdsState = valBds;
                m_bdsStateOwned = true;
                return this;
            }

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
            public XmssPrivateKeyParameters Build()
            {
                if (!((m_privateKey != null) || (m_publicSeed != null && m_secretKeySeed != null)))
                    throw new InvalidOperationException("publicSeed or secretKeySeed is null");
                // the root keys H_msg, so a key without one would spend its one-time keys on signatures that verify
                // under no public key
                if (m_privateKey == null && m_root == null)
                    throw new InvalidOperationException("root is null");

                return new XmssPrivateKeyParameters(this);
            }
        }

        /// <summary>The index of the next one-time key this key will sign with.</summary>
        public int Index => m_bdsState.Index;

        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public byte[] GetSecretKeySeed() => CloneWithCheck(m_secretKeySeed);

        /// <exception cref="InvalidOperationException">If the key has been destroyed.</exception>
        public byte[] GetSecretKeyPrf() => CloneWithCheck(m_secretKeyPrf);

        public byte[] GetPublicSeed() => Arrays.Clone(m_publicSeed);

        public byte[] GetRoot() => Arrays.Clone(m_root);

        internal Bds GetBdsState() => m_bdsState;

        /// <summary>
        /// Whether these are the same key at the same position, which for a stateful key means the same traversal
        /// state too.
        /// </summary>
        /// <remarks>
        /// Each key's fields are read under its own lock, never both at once; the state is compared only when the
        /// fields agree, because producing it means encoding a whole traversal state on both keys.
        /// </remarks>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(this, obj))
                return true;
            if (!(obj is XmssPrivateKeyParameters that))
                return false;

            return XmssPrivateKeyCodec.FieldsEqual(this.GetFields(), that.GetFields())
                && XmssPrivateKeyCodec.StateEqual(this.GetState(), that.GetState());
        }

        /// <summary>
        /// The values <see cref="XmssPrivateKeyCodec.FieldsEqual"/> decides on, read from this key under its own
        /// lock. The index and the usages remaining are both taken from the state a signature replaces, so they are
        /// read in one block.
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
        /// This key's traversal state, encoded, beside the index it is the state for - the pair
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
                    throw new InvalidOperationException("error encoding BDS state", e);
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
        /// from, the PRF key that randomizes message digests, and the WOTS+ secret key its BDS traversal state
        /// retains for the leaf it last processed.
        /// </summary>
        /// <remarks>
        /// The public seed, the root, the index and the traversal state's tree nodes are retained - none of them is
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
