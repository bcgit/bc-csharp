using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>The per-layer BDS traversal states of one XMSS^MT key, keyed by layer.</summary>
    /// <remarks>
    /// <para>
    /// Every read and every write of the map below is taken under this object's own lock, and one fact is behind
    /// all of them: a signature descends the layers installing the states it builds lazily into the map it is
    /// signing with, while the map can be read from another thread through the key that holds it. An insertion
    /// rebalances the dictionary underneath, so anything walking or looking up outside the lock reads a tree part
    /// way through being restructured. Holding the lock for the whole of an operation, rather than once per lookup,
    /// is also what makes an answer coherent rather than merely intact: the engine holds this same lock for a whole
    /// descent, so what an operation here sees is every layer from before that signature or every layer from after
    /// it, never a mixture. The lock order is always key, then map.
    /// </para>
    /// <para>
    /// The map is a <see cref="SortedDictionary{TKey, TValue}"/>, which iterates in ascending layer order as
    /// Java's <c>TreeMap</c> does, and <see cref="BdsStateCodec"/> writes the layers in that order. Java's
    /// object-serialization support is not ported; the state map is written and read only through the codec.
    /// </para>
    /// <para>
    /// A layer state this map replaces - one a layer is advanced past, or one a new subtree is rebuilt over - is
    /// wiped once its successor is in place: it can hold the WOTS+ secret key of a leaf yet to sign with. No layer
    /// state is ever shared between two maps; every way of copying a map copies each layer.
    /// </para>
    /// </remarks>
    internal sealed class BdsStateMap
    {
        private readonly SortedDictionary<int, Bds> m_bdsState = new SortedDictionary<int, Bds>();

        private readonly long m_maxIndex;

        internal BdsStateMap(long maxIndex)
        {
            m_maxIndex = maxIndex;
        }

        /// <summary>
        /// Copy the states of another map, under that map's own lock for the whole walk - which is what makes this
        /// safe to run against a map a key is signing with.
        /// </summary>
        /// <remarks>
        /// Each layer is copied rather than shared. A signature marks the layer zero state it spent in place, and
        /// this has two callers, <see cref="GetNextState"/> and the key's ExtractKeyShard(), the second of which
        /// leaves two live keys holding maps built from one map: a shared layer zero would be those two keys sharing
        /// one record of whether the one-time key at that leaf has been spent.
        /// </remarks>
        internal BdsStateMap(BdsStateMap stateMap, long maxIndex)
        {
            lock (stateMap)
            {
                foreach (var entry in stateMap.m_bdsState)
                {
                    m_bdsState.Add(entry.Key, new Bds(entry.Value));
                }
            }
            m_maxIndex = maxIndex;
        }

        /// <summary>A state map rebuilt from the seeds at a global index, by walking the hypertree to it.</summary>
        /// <remarks>
        /// At index 0 there is no walk, and the map is the one key generation makes: the top layer alone, whose root
        /// is the public root, with every layer below built by the first signature. bc-java leaves the map empty
        /// there, which its signer refuses as not initialized, so a key restored from its seeds before its first
        /// signature could not sign.
        /// </remarks>
        internal BdsStateMap(XmssMTParameters parameters, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
        {
            m_maxIndex = (1L << parameters.Height) - 1;
            if (globalIndex == 0)
            {
                int topLayer = parameters.Layers - 1;
                Put(topLayer, new Bds(parameters.XmssParameters, publicSeed, secretKeySeed,
                    XmssAddress.OtsHashAddress(topLayer, 0L, 0)));
            }
            for (long index = 0; index < globalIndex; index++)
            {
                UpdateState(parameters, index, publicSeed, secretKeySeed);
            }
        }

        internal long MaxIndex => m_maxIndex;

        /// <summary>
        /// Zeroize the secret material retained by every layer's state; see <see cref="Bds.ClearSecrets"/>.
        /// </summary>
        internal void ClearSecrets()
        {
            lock (this)
            {
                foreach (Bds state in m_bdsState.Values)
                {
                    state.ClearSecrets();
                }
            }
        }

        /// <summary>
        /// The traversal state for the leaf after <paramref name="globalIndex"/>, as a new state map: the one this is
        /// called on is left where it is, which is what lets the owning key move its index and its state as one.
        /// </summary>
        internal BdsStateMap GetNextState(XmssMTParameters parameters, long globalIndex, byte[] publicSeed,
            byte[] secretKeySeed)
        {
            BdsStateMap next = new BdsStateMap(this, m_maxIndex);

            next.UpdateState(parameters, globalIndex, publicSeed, secretKeySeed);

            return next;
        }

        /// <summary>
        /// Advance this state map in place, for a map that is not yet anyone's: the constructor building a state up
        /// to an index, and the copy <see cref="GetNextState"/> has just taken. The state a key holds is advanced by
        /// being replaced, never through here.
        /// </summary>
        private void UpdateState(XmssMTParameters parameters, long globalIndex, byte[] publicSeed,
            byte[] secretKeySeed)
        {
            XmssParameters xmssParams = parameters.XmssParameters;
            int xmssHeight = xmssParams.Height;

            //
            // set up state for next signature
            //
            long indexTree = XmssUtilities.GetTreeIndex(globalIndex, xmssHeight);
            int indexLeaf = XmssUtilities.GetLeafIndex(globalIndex, xmssHeight);

            byte[] otsAddress = XmssAddress.OtsHashAddress(0, indexTree, indexLeaf);

            /* prepare authentication path for next leaf */
            if (indexLeaf < ((1 << xmssHeight) - 1))
            {
                if (Get(0) == null || indexLeaf == 0)
                {
                    Put(0, new Bds(xmssParams, publicSeed, secretKeySeed, otsAddress));
                }

                Update(0, publicSeed, secretKeySeed, otsAddress);
            }

            /* loop over remaining layers */
            for (int layer = 1; layer < parameters.Layers; layer++)
            {
                /* get root of layer - 1 */
                indexLeaf = XmssUtilities.GetLeafIndex(indexTree, xmssHeight);
                indexTree = XmssUtilities.GetTreeIndex(indexTree, xmssHeight);
                /* adjust addresses */
                otsAddress = XmssAddress.OtsHashAddress(layer, indexTree, indexLeaf);

                /* prepare authentication path for next leaf */
                if (Get(layer) == null || XmssUtilities.IsNewBdsInitNeeded(globalIndex, xmssHeight, layer))
                {
                    Put(layer, new Bds(xmssParams, publicSeed, secretKeySeed, otsAddress));
                }

                if (indexLeaf < ((1 << xmssHeight) - 1)
                    && XmssUtilities.IsNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer))
                {
                    Update(layer, publicSeed, secretKeySeed, otsAddress);
                }
            }
        }

        internal bool IsEmpty
        {
            get
            {
                lock (this)
                {
                    return m_bdsState.Count == 0;
                }
            }
        }

        /// <summary>
        /// The layer to state mapping, as a snapshot rather than the map itself: the encoder walks what it is given,
        /// and the map this is taken from can be one a key is signing with.
        /// </summary>
        internal SortedDictionary<int, Bds> GetStateMap()
        {
            lock (this)
            {
                return new SortedDictionary<int, Bds>(m_bdsState);
            }
        }

        internal void Validate(XmssMTParameters parameters)
        {
            lock (this)
            {
                long maxIndexLimit = (1L << parameters.Height) - 1;
                if (m_maxIndex < 0 || m_maxIndex > maxIndexLimit || m_bdsState.Count > parameters.Layers)
                    throw new InvalidOperationException("BDS state map does not match XMSSMT parameters");

                XmssParameters xmssParams = parameters.XmssParameters;
                foreach (var entry in m_bdsState)
                {
                    int layer = entry.Key;
                    if (layer < 0 || layer >= parameters.Layers)
                        throw new InvalidOperationException("BDS state map has invalid layer");

                    Bds state = entry.Value;
                    if (state == null)
                        throw new InvalidOperationException("BDS state map has null state");

                    state.Validate(xmssParams);
                }
            }
        }

        /// <summary>
        /// Confirm the top layer's root is the one the enclosing private key declares - the top tree's root is the
        /// public root. A layer with no state yet is built lazily at signing time and so is not compared
        /// (bc-java github #2414).
        /// </summary>
        /// <remarks>
        /// Under this map's own lock, as every other read here is: this is the check that decides whether a key is
        /// built around the map at all, so a lookup answering with a null or with another layer's state is what
        /// would decide it.
        /// </remarks>
        /// <param name="parameters">the parameters of the enclosing key.</param>
        /// <param name="expectedRoot">the root the private key declares.</param>
        internal void ValidateRoot(XmssMTParameters parameters, byte[] expectedRoot)
        {
            lock (this)
            {
                if (m_bdsState.TryGetValue(parameters.Layers - 1, out Bds top))
                {
                    top.ValidateRoot(expectedRoot);
                }
            }
        }

        /// <summary>
        /// Validate as <see cref="Validate(XmssMTParameters)"/> and additionally tie each layer's traversal state to
        /// the enclosing private key's index.
        /// </summary>
        /// <remarks>
        /// RFC 8391 sec. 1.1 requires each one-time key to be used once, and the global index and the per-layer
        /// states are two records of the same position, so a stored key whose index has been rolled back while its
        /// state stayed advanced is detectable and must be refused: it would otherwise sign a second message under a
        /// one-time key already used, and the signature would verify.
        /// </remarks>
        /// <param name="parameters">the parameters of the enclosing key.</param>
        /// <param name="globalIndex">the index the enclosing key declares.</param>
        /// <param name="publicSeed">the enclosing key's public seed.</param>
        /// <param name="secretKeySeed">the enclosing key's secret seed.</param>
        internal void Validate(XmssMTParameters parameters, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
        {
            Validate(parameters);
            ValidateIndex(parameters, globalIndex, publicSeed, secretKeySeed);
        }

        /// <summary>
        /// The index half of <see cref="Validate(XmssMTParameters, long, byte[], byte[])"/> on its own: tie each
        /// layer's traversal state to the index its enclosing key declares, without re-walking the structure of every
        /// state.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Separate because the two halves answer at different times: the structure of a state can only be wrong on
        /// the way in, while the index pair can go wrong every time the key moves, so this half runs on every roll
        /// and before every encoding. Under this map's own lock for the whole walk, so it never compares some layers
        /// from before a signature against others from after it.
        /// </para>
        /// <para>
        /// Every layer state must sit on the leaf the index names at that layer, with one exception. On the first leaf
        /// of a subtree a layer has just moved into a new subtree and its state has not been advanced into it:
        /// UpdateState skips the advance on the last leaf of a subtree and the signer rebuilds the state when it next
        /// signs there. So a state on the last leaf is accepted where the index names leaf 0 - but only the state of
        /// the subtree just before the one the index names. A leaf index cannot tell subtrees apart, and a key whose
        /// index has been moved back to the start of an earlier subtree would otherwise sign again at indices it has
        /// already used. The subtree is recognised by recomputing one node of it from the seeds: the last leaf's
        /// authentication path opens with its sibling leaf, whose value depends on the subtree's address. bc-java
        /// accepts the last leaf whatever the subtree.
        /// </para>
        /// </remarks>
        /// <param name="parameters">the parameters of the enclosing key.</param>
        /// <param name="globalIndex">the index the enclosing key declares.</param>
        /// <param name="publicSeed">the enclosing key's public seed.</param>
        /// <param name="secretKeySeed">the enclosing key's secret seed, which the subtree check derives one WOTS+ key
        /// from.</param>
        internal void ValidateIndex(XmssMTParameters parameters, long globalIndex, byte[] publicSeed,
            byte[] secretKeySeed)
        {
            lock (this)
            {
                XmssParameters xmssParams = parameters.XmssParameters;
                int xmssHeight = xmssParams.Height;
                int lastLeaf = (1 << xmssHeight) - 1;
                long treeIndex = globalIndex;

                for (int layer = 0; layer < parameters.Layers; layer++)
                {
                    // the same walk down the layers the signer and UpdateState perform
                    int expectedLeaf = XmssUtilities.GetLeafIndex(treeIndex, xmssHeight);
                    treeIndex = XmssUtilities.GetTreeIndex(treeIndex, xmssHeight);

                    if (!m_bdsState.TryGetValue(layer, out Bds state))
                    {
                        // a layer's state is built lazily, on the first signature that needs it
                        continue;
                    }

                    int actual = state.Index;
                    bool ok = (actual == expectedLeaf)
                        || (expectedLeaf == 0 && actual == lastLeaf
                            && IsLastLeafOfSubtree(xmssParams, layer, treeIndex - 1, state, publicSeed,
                                secretKeySeed));

                    if (!ok)
                    {
                        throw new InvalidOperationException("BDS state has wrong index for layer " + layer
                            + ": expected " + expectedLeaf + " but state is at " + actual);
                    }
                }
            }
        }

        /// <summary>
        /// Whether <paramref name="state"/>, which sits on the last leaf of a subtree of <paramref name="layer"/>,
        /// belongs to the subtree at <paramref name="tree"/> - a negative one being none at all.
        /// </summary>
        private static bool IsLastLeafOfSubtree(XmssParameters xmssParams, int layer, long tree, Bds state,
            byte[] publicSeed, byte[] secretKeySeed)
        {
            if (tree < 0)
                return false;

            List<XmssNode> authenticationPath = state.GetAuthenticationPath();
            if (authenticationPath.Count == 0)
                return false;

            // the last leaf is odd, so the first node of its authentication path is the leaf before it
            int sibling = (1 << xmssParams.Height) - 2;
            byte[] expected = LeafNode(xmssParams, XmssAddress.OtsHashAddress(layer, tree, sibling), publicSeed,
                secretKeySeed);

            return Arrays.FixedTimeEquals(expected, authenticationPath[0].GetValue());
        }

        /// <summary>
        /// The value of the leaf at <paramref name="otsAddress"/>: the L-tree compression of the WOTS+ public key
        /// there, as <see cref="Bds"/> computes it when it walks a tree.
        /// </summary>
        private static byte[] LeafNode(XmssParameters xmssParams, byte[] otsAddress, byte[] publicSeed,
            byte[] secretKeySeed)
        {
            int n = xmssParams.TreeDigestSize;
            WotsPlus wotsPlus = new WotsPlus(new WotsPlusParameters(xmssParams.TreeDigestOid, n));
            byte[] lTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.LTreeType);
            Pack.UInt32_To_BE((uint)XmssAddress.OtsAddressOf(otsAddress), lTreeAddress,
                XmssAddress.LTreeAddressOffset);

            byte[] wotsPlusSecretKey = wotsPlus.GetWotsPlusSecretKey(secretKeySeed, otsAddress);
            try
            {
                wotsPlus.ImportKeys(wotsPlusSecretKey, publicSeed);
                WotsPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.GetPublicKey(otsAddress);
                return XmssNodeUtilities.LTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, new byte[n],
                    new byte[2 * n]).GetValue();
            }
            finally
            {
                Arrays.ZeroMemory(wotsPlusSecretKey);
                wotsPlus.ClearSecretKeySeed();
            }
        }

        internal Bds Get(int index)
        {
            lock (this)
            {
                return m_bdsState.TryGetValue(index, out Bds state) ? state : null;
            }
        }

        /// <summary>
        /// Record that the one-time key the layer zero state is sitting on has signed. Only layer zero is marked: its
        /// leaf signs the message digest, while the leaves above it sign the root of the subtree below, which does
        /// not change while that subtree is being signed through.
        /// </summary>
        internal void MarkUsed()
        {
            lock (this)
            {
                // the state is put in place before the signature is built, but the signature can fail before that
                // happens and this runs from the finally that covers it
                Get(0)?.MarkUsed();
            }
        }

        /// <summary>
        /// Whether the layer zero state is sitting on a one-time key it has already signed with, the record
        /// <see cref="MarkUsed"/> leaves. A map whose layer zero is absent has nothing to answer for, since the
        /// signer builds that layer fresh.
        /// </summary>
        internal bool IsUsed
        {
            get
            {
                lock (this)
                {
                    Bds layerZero = Get(0);

                    return layerZero != null && layerZero.IsUsed;
                }
            }
        }

        /// <summary>Advance one layer's state a leaf, replacing it; the state replaced is wiped.</summary>
        /// <returns>the state replaced.</returns>
        internal Bds Update(int index, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
        {
            lock (this)
            {
                Bds replaced = m_bdsState[index];
                m_bdsState[index] = replaced.GetNextState(publicSeed, secretKeySeed, otsAddress);
                replaced.ClearSecrets();
                return replaced;
            }
        }

        /// <summary>Install a layer's state; a different state it replaces is wiped.</summary>
        internal void Put(int index, Bds bds)
        {
            lock (this)
            {
                m_bdsState.TryGetValue(index, out Bds replaced);
                m_bdsState[index] = bds;
                if (replaced != null && replaced != bds)
                {
                    replaced.ClearSecrets();
                }
            }
        }

        internal BdsStateMap WithWotsDigest(DerObjectIdentifier digestName) => WithWotsDigest(digestName, -1);

        internal BdsStateMap WithWotsDigest(DerObjectIdentifier digestName, int digestSize) =>
            WithMaxIndex(m_maxIndex, digestName, digestSize);

        /// <summary>
        /// As <see cref="WithWotsDigest(DerObjectIdentifier, int)"/>, and with a maximum index of the caller's rather
        /// than this map's - what the key builder copies a state map with, so that a state installed in a key is
        /// always one whose WOTS+ parameters the key's own parameter set named. Only the map's own maximum index is
        /// the caller's: each layer keeps the one its subtree fixes.
        /// </summary>
        /// <param name="maxIndex">the maximum index the copy is to carry.</param>
        /// <param name="digestName">the tree digest of the key the copy belongs to.</param>
        /// <param name="digestSize">its output length in bytes, where the digest does not fix one.</param>
        internal BdsStateMap WithMaxIndex(long maxIndex, DerObjectIdentifier digestName, int digestSize)
        {
            BdsStateMap newStateMap = new BdsStateMap(maxIndex);

            lock (this)
            {
                foreach (var entry in m_bdsState)
                {
                    newStateMap.m_bdsState.Add(entry.Key, entry.Value.WithWotsDigest(digestName, digestSize));
                }
            }

            return newStateMap;
        }
    }
}
