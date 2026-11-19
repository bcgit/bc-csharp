using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>BDS.</summary>
    /// <remarks>
    /// <para>
    /// The stack is a <see cref="List{T}"/> whose last element is the top, rather than a <see cref="Stack{T}"/>:
    /// <see cref="BdsStateCodec"/> writes it out bottom to top, which is the order Java's <c>Stack</c> iterates
    /// in, and a .NET <see cref="Stack{T}"/> enumerates top to bottom. The retain and keep maps are
    /// <see cref="SortedDictionary{TKey, TValue}"/>s, which iterate in ascending key order as Java's
    /// <c>TreeMap</c> does; the codec writes them in that order too.
    /// </para>
    /// <para>
    /// Java's object-serialization support (<c>readObject</c>/<c>writeObject</c>) is not ported; the state is
    /// written and read only through <see cref="BdsStateCodec"/>.
    /// </para>
    /// </remarks>
    internal sealed class Bds
    {
        private readonly WotsPlus m_wotsPlus;

        private readonly int m_treeHeight;
        private readonly List<BdsTreeHash> m_treeHashInstances;
        private readonly int m_k;
        private XmssNode m_root;
        private readonly List<XmssNode> m_authenticationPath;
        private readonly SortedDictionary<int, List<XmssNode>> m_retain;
        private readonly List<XmssNode> m_stack;

        private readonly SortedDictionary<int, XmssNode> m_keep;
        private int m_index;
        private bool m_used;

        private int m_maxIndex;

        /// <summary>Place holder BDS for when state is exhausted.</summary>
        /// <param name="parameters">tree parameters</param>
        /// <param name="maxIndex">the maximum index of the state.</param>
        /// <param name="index">the index that has been reached.</param>
        internal Bds(XmssParameters parameters, int maxIndex, int index)
            : this(NewWotsPlus(parameters), parameters.Height, parameters.K, index)
        {
            m_maxIndex = maxIndex;
            m_index = index;
            m_used = true;
        }

        /// <summary>Set up constructor.</summary>
        /// <param name="parameters">tree parameters</param>
        /// <param name="publicSeed">public seed for tree</param>
        /// <param name="secretKeySeed">secret seed for tree</param>
        /// <param name="otsAddress">the 32-byte encoding of the OTS hash address the tree starts at; read and never
        /// written, see <see cref="Initialize"/>.</param>
        internal Bds(XmssParameters parameters, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
            : this(NewWotsPlus(parameters), parameters.Height, parameters.K, (1 << parameters.Height) - 1)
        {
            Initialize(publicSeed, secretKeySeed, otsAddress);
        }

        /// <summary>Set up constructor for a tree where the original BDS state was lost.</summary>
        /// <param name="parameters">tree parameters</param>
        /// <param name="publicSeed">public seed for tree</param>
        /// <param name="secretKeySeed">secret seed for tree</param>
        /// <param name="otsAddress">the 32-byte encoding of the OTS hash address the tree starts at; read and never
        /// written, see <see cref="Initialize"/>.</param>
        /// <param name="index">index counter for the state to be at.</param>
        internal Bds(XmssParameters parameters, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress,
            int index)
            : this(NewWotsPlus(parameters), parameters.Height, parameters.K, (1 << parameters.Height) - 1)
        {
            Initialize(publicSeed, secretKeySeed, otsAddress);

            while (m_index < index)
            {
                NextAuthenticationPath(publicSeed, secretKeySeed, otsAddress);
                m_used = false;
            }
        }

        private Bds(WotsPlus wotsPlus, int treeHeight, int k, int maxIndex)
        {
            m_wotsPlus = wotsPlus;
            m_treeHeight = treeHeight;
            m_maxIndex = maxIndex;
            m_k = k;
            if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0)
                throw new ArgumentException("illegal value for BDS parameter k");

            m_authenticationPath = new List<XmssNode>();
            m_retain = new SortedDictionary<int, List<XmssNode>>();
            m_stack = new List<XmssNode>();

            m_treeHashInstances = new List<BdsTreeHash>();
            for (int height = 0; height < (treeHeight - k); height++)
            {
                m_treeHashInstances.Add(new BdsTreeHash(height));
            }

            m_keep = new SortedDictionary<int, XmssNode>();
            m_index = 0;
            m_used = false;
        }

        /// <summary>A state assembled field by field, for a decoder that has just read one.</summary>
        /// <remarks>
        /// The five collections are adopted rather than copied, so the caller hands them over and must not go on
        /// using them. That is what a decoder is holding: <see cref="BdsStateCodec"/> makes each of them a node at
        /// a time out of the encoding and has the only reference to it. The constructors that carry a state on
        /// from another one still copy, because there the other one goes on being used.
        /// </remarks>
        internal Bds(int treeHeight, int k, int maxIndex, int index, bool used, XmssNode root,
            List<XmssNode> authenticationPath, SortedDictionary<int, List<XmssNode>> retain, List<XmssNode> stack,
            List<BdsTreeHash> treeHashInstances, SortedDictionary<int, XmssNode> keep)
        {
            m_wotsPlus = null;
            m_treeHeight = treeHeight;
            m_k = k;
            m_maxIndex = maxIndex;
            m_index = index;
            m_used = used;
            m_root = root;
            m_authenticationPath = authenticationPath;
            m_retain = retain;
            m_stack = stack;
            m_treeHashInstances = treeHashInstances;
            m_keep = keep;
            Validate();
        }

        /// <summary>
        /// The copy the four "carry on from a previous state" constructors below all make, written once. Each of
        /// them differs from the others only in the WOTS+ instance it ends up with, whether it keeps the maximum
        /// index and the used mark of the state it copies, and what it does after the copy.
        /// </summary>
        private Bds(Bds last, WotsPlus wotsPlus, int maxIndex, bool used)
        {
            m_wotsPlus = wotsPlus;
            m_treeHeight = last.m_treeHeight;
            m_k = last.m_k;
            m_root = last.m_root;
            m_authenticationPath = CloneAuthenticationPath(last.m_authenticationPath);
            m_retain = CloneRetain(last.m_retain);
            m_stack = CloneStack(last.m_stack);
            m_treeHashInstances = CloneTreeHashInstances(last.m_treeHashInstances);
            m_keep = new SortedDictionary<int, XmssNode>(last.m_keep);
            m_index = last.m_index;
            m_maxIndex = maxIndex;
            m_used = used;
        }

        /// <summary>A plain copy of a state, its WOTS+ instance included where there is one to copy.</summary>
        /// <remarks>
        /// There need not be: a state that has just been decoded carries none until <see cref="WithWotsDigest(
        /// DerObjectIdentifier, int)"/> names the digest and builds them. A copy of a state that has not been
        /// given its digest yet can be given one exactly as the original could.
        /// </remarks>
        internal Bds(Bds last)
            : this(last, (last.m_wotsPlus != null) ? new WotsPlus(last.m_wotsPlus.Params) : null, last.m_maxIndex,
                last.m_used)
        {
        }

        private Bds(Bds last, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
            // the state being built is the one after last, and it has signed nothing yet
            : this(last, new WotsPlus(last.m_wotsPlus.Params), last.m_maxIndex, false)
        {
            NextAuthenticationPath(publicSeed, secretKeySeed, otsAddress);
        }

        private Bds(Bds last, DerObjectIdentifier digest, int digestSize)
            : this(last, NewWotsPlus(digest, digestSize), last.m_maxIndex, last.m_used)
        {
            Validate();
        }

        private Bds(Bds last, int maxIndex, DerObjectIdentifier digest, int digestSize)
            : this(last, NewWotsPlus(digest, digestSize), maxIndex, last.m_used)
        {
            Validate();
        }

        /// <summary>
        /// The WOTS+ instance for a parameter set; the same instance Java's <c>XMSSEngine.newWOTSPlus</c> makes.
        /// </summary>
        private static WotsPlus NewWotsPlus(XmssParameters parameters) =>
            new WotsPlus(new WotsPlusParameters(parameters.TreeDigestOid, parameters.TreeDigestSize));

        /// <summary>
        /// The WOTS+ instance the two constructors that rebuild a state around a named digest make - a decoded
        /// state carries no WOTS+ parameters of its own, so they cannot take last's. An explicit size is needed for
        /// the digests whose output length is not fixed by their name.
        /// </summary>
        private static WotsPlus NewWotsPlus(DerObjectIdentifier digest, int digestSize)
        {
            return new WotsPlus(digestSize > 0
                ? new WotsPlusParameters(digest, digestSize)
                : new WotsPlusParameters(digest));
        }

        private static List<XmssNode> CloneAuthenticationPath(List<XmssNode> authenticationPath) =>
            new List<XmssNode>(authenticationPath);

        private static SortedDictionary<int, List<XmssNode>> CloneRetain(SortedDictionary<int, List<XmssNode>> retain)
        {
            var clone = new SortedDictionary<int, List<XmssNode>>();
            foreach (var entry in retain)
            {
                clone.Add(entry.Key, new List<XmssNode>(entry.Value));
            }
            return clone;
        }

        private static List<XmssNode> CloneStack(List<XmssNode> stack) => new List<XmssNode>(stack);

        private static List<BdsTreeHash> CloneTreeHashInstances(List<BdsTreeHash> treeHashInstances)
        {
            var clone = new List<BdsTreeHash>(treeHashInstances.Count);
            foreach (BdsTreeHash treeHash in treeHashInstances)
            {
                clone.Add(treeHash.Clone());
            }
            return clone;
        }

        /// <summary>The top of a stack held as a list whose last element is the top.</summary>
        internal static XmssNode Peek(List<XmssNode> stack) => stack[stack.Count - 1];

        /// <summary>Remove and return the top of a stack held as a list whose last element is the top.</summary>
        internal static XmssNode Pop(List<XmssNode> stack)
        {
            int last = stack.Count - 1;
            XmssNode node = stack[last];
            stack.RemoveAt(last);
            return node;
        }

        internal Bds GetNextState(byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress) =>
            new Bds(this, publicSeed, secretKeySeed, otsAddress);

        /// <summary>
        /// Zeroize the secret material this state retains: the WOTS+ secret key its hash-function instance
        /// imported for the last leaf it processed, which is a future leaf's one-time key while the tree is not
        /// exhausted. The tree nodes are kept - they are not secret. Called when the enclosing private key is
        /// destroyed.
        /// </summary>
        /// <remarks>
        /// The instance can be absent: a state that has just been decoded carries none until it is rebuilt around
        /// the digest its key names.
        /// </remarks>
        internal void ClearSecrets()
        {
            m_wotsPlus?.ClearSecretKeySeed();
        }

        /// <summary>
        /// Walk the whole tree, leaf by leaf, and leave this state holding its root and the authentication path of
        /// leaf zero (RFC 8391 sec. 4.1.6 algorithm 9).
        /// </summary>
        /// <param name="publicSeed">the key's public seed.</param>
        /// <param name="secretSeed">the key's secret seed.</param>
        /// <param name="otsAddress">the 32-byte encoding of the OTS hash address the tree starts at. Read and never
        /// written: the walk steps a copy of it, because a caller may go on to use the same starting
        /// address.</param>
        private void Initialize(byte[] publicSeed, byte[] secretSeed, byte[] otsAddress)
        {
            /* prepare addresses - one encoding each for the whole walk, with the words that change written into
             * them as it goes. The two below the leaf's are the same tree as it, so they are taken from its
             * encoding rather than assembled beside it. */
            byte[] leafAddress = Arrays.Clone(otsAddress);
            byte[] lTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.LTreeType);
            byte[] hashTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.HashTreeType);
            /* and one pair of working buffers for every node hashed below, L-tree and tree alike; see
             * XmssNodeUtilities.RandomizeHash for why one pair serves a whole walk */
            int n = m_wotsPlus.Params.TreeDigestSize;
            byte[] nodeKey = new byte[n];
            byte[] nodeMask = new byte[2 * n];

            /* iterate indexes */
            for (int indexLeaf = 0; indexLeaf < (1 << m_treeHeight); indexLeaf++)
            {
                /* generate leaf - the one word of the OTS encoding a leaf is named by, stepped through the walk's
                 * own copy of it. What the previous leaf's chains left in the three words below it is cleared by
                 * GetWotsPlusSecretKey, which says so. */
                Pack.UInt32_To_BE((uint)indexLeaf, leafAddress, XmssAddress.OtsAddressOffset);
                /*
                 * import WOTSPlusSecretKey as its needed to calculate the public
                 * key on the fly
                 */
                byte[] wotsPlusSecretKey = m_wotsPlus.GetWotsPlusSecretKey(secretSeed, leafAddress);
                m_wotsPlus.ImportKeys(wotsPlusSecretKey, publicSeed);
                // the instance keeps its own copy; this one would otherwise outlive the walk
                Arrays.ZeroMemory(wotsPlusSecretKey);
                WotsPlusPublicKeyParameters wotsPlusPublicKey = m_wotsPlus.GetPublicKey(leafAddress);
                Pack.UInt32_To_BE((uint)indexLeaf, lTreeAddress, XmssAddress.LTreeAddressOffset);
                XmssNode node = XmssNodeUtilities.LTree(m_wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey,
                    nodeMask);

                // the two words of the hash tree encoding the climb below moves, kept beside it so that stepping
                // one is an increment rather than a read back out of the bytes. The height goes back to 0 for the
                // new leaf rather than being carried over.
                int hashTreeHeight = 0;
                int hashTreeIndex = indexLeaf;
                Pack.UInt32_To_BE((uint)hashTreeHeight, hashTreeAddress, XmssAddress.TreeHeightOffset);
                Pack.UInt32_To_BE((uint)hashTreeIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
                while (m_stack.Count > 0 && Peek(m_stack).Height == node.Height)
                {
                    /* add to authenticationPath if leafIndex == 1 */
                    int indexOnHeight = indexLeaf / (1 << node.Height);
                    if (indexOnHeight == 1)
                    {
                        m_authenticationPath.Add(node);
                    }
                    /* store next right authentication node */
                    if (indexOnHeight == 3 && node.Height < (m_treeHeight - m_k))
                    {
                        m_treeHashInstances[node.Height].SetNode(node);
                    }
                    if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.Height >= (m_treeHeight - m_k)
                        && node.Height <= (m_treeHeight - 2))
                    {
                        if (!m_retain.TryGetValue(node.Height, out var queue))
                        {
                            queue = new List<XmssNode>();
                            queue.Add(node);
                            m_retain.Add(node.Height, queue);
                        }
                        else
                        {
                            queue.Add(node);
                        }
                    }
                    hashTreeIndex = (hashTreeIndex - 1) / 2;
                    Pack.UInt32_To_BE((uint)hashTreeIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
                    node = XmssNodeUtilities.RandomizeHash(m_wotsPlus, Pop(m_stack), node, hashTreeAddress, nodeKey,
                        nodeMask);
                    node = node.IncrementHeight();
                    Pack.UInt32_To_BE((uint)++hashTreeHeight, hashTreeAddress, XmssAddress.TreeHeightOffset);
                }
                /* push to stack */
                m_stack.Add(node);
            }
            m_root = Pop(m_stack);
        }

        /// <summary>Advance this state one leaf (RFC 8391 sec. 4.1.6 algorithm 11).</summary>
        /// <param name="publicSeed">the key's public seed.</param>
        /// <param name="secretSeed">the key's secret seed.</param>
        /// <param name="otsAddress">the 32-byte encoding of the OTS hash address the tree starts at. Read and never
        /// written, as in <see cref="Initialize"/>: the leaf branch below and the tree hash updates that close the
        /// method both step a copy of it.</param>
        private void NextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, byte[] otsAddress)
        {
            if (m_used)
                throw new InvalidOperationException("index already used");
            if (m_index > m_maxIndex - 1)
                throw new InvalidOperationException("index out of bounds");

            /* determine tau */
            int tau = XmssUtilities.CalculateTau(m_index, m_treeHeight);
            /* parent of leaf on height tau+1 is a left node */
            if (((m_index >> (tau + 1)) & 1) == 0 && (tau < (m_treeHeight - 1)))
            {
                m_keep[tau] = m_authenticationPath[tau];
            }

            /* prepare addresses - the two below the leaf's name the same tree as it, so they are taken from its
             * encoding rather than assembled beside it */
            byte[] leafAddress = Arrays.Clone(otsAddress);
            byte[] lTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.LTreeType);
            byte[] hashTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.HashTreeType);
            /* and one pair of working buffers for whichever of the two branches below runs; see
             * XmssNodeUtilities.RandomizeHash */
            int n = m_wotsPlus.Params.TreeDigestSize;
            byte[] nodeKey = new byte[n];
            byte[] nodeMask = new byte[2 * n];

            /* leaf is a left node */
            if (tau == 0)
            {
                Pack.UInt32_To_BE((uint)m_index, leafAddress, XmssAddress.OtsAddressOffset);
                /*
                 * import WOTSPlusSecretKey as its needed to calculate the public
                 * key on the fly
                 */
                byte[] wotsPlusSecretKey = m_wotsPlus.GetWotsPlusSecretKey(secretSeed, leafAddress);
                m_wotsPlus.ImportKeys(wotsPlusSecretKey, publicSeed);
                // the instance keeps its own copy; this one would otherwise outlive the walk
                Arrays.ZeroMemory(wotsPlusSecretKey);
                WotsPlusPublicKeyParameters wotsPlusPublicKey = m_wotsPlus.GetPublicKey(leafAddress);
                Pack.UInt32_To_BE((uint)m_index, lTreeAddress, XmssAddress.LTreeAddressOffset);
                XmssNode node = XmssNodeUtilities.LTree(m_wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey,
                    nodeMask);
                m_authenticationPath[0] = node;
            }
            else
            {
                /* add new left node on height tau to authentication path */
                Pack.UInt32_To_BE((uint)(tau - 1), hashTreeAddress, XmssAddress.TreeHeightOffset);
                Pack.UInt32_To_BE((uint)(m_index >> tau), hashTreeAddress, XmssAddress.TreeIndexOffset);
                // the public seed, and a placeholder where the one-time secret key goes. Nothing on this branch
                // derives a WOTS+ key: RandomizeHash below takes the public seed and the keyed hash functions off
                // this object and reads nothing else, so the zero placeholder leaves no one-time key material
                // behind in an object that has no use for it.
                m_wotsPlus.ImportKeys(new byte[n], publicSeed);
                // the node this state kept the last time the path passed height tau - 1. One that reached this
                // index by signing always has it; one that arrived by import need not, and that is a corrupt
                // state rather than a failure inside the hash.
                if (!m_keep.TryGetValue(tau - 1, out XmssNode keptNode) || keptNode == null)
                    throw new InvalidOperationException("missing keep node in BDS state");

                XmssNode node = XmssNodeUtilities.RandomizeHash(m_wotsPlus, m_authenticationPath[tau - 1],
                    keptNode, hashTreeAddress, nodeKey, nodeMask);
                node = node.IncrementHeight();
                m_authenticationPath[tau] = node;
                m_keep.Remove(tau - 1);

                /* add new right nodes to authentication path */
                for (int height = 0; height < tau; height++)
                {
                    if (height < (m_treeHeight - m_k))
                    {
                        m_authenticationPath[height] = m_treeHashInstances[height].TailNode;
                    }
                    else
                    {
                        // as for the kept node above: an imported state can be missing the queue for this
                        // height, or carry it empty, and either is a corrupt state
                        if (!m_retain.TryGetValue(height, out var retained) || retained == null
                            || retained.Count == 0)
                        {
                            throw new InvalidOperationException("missing retain node in BDS state");
                        }
                        m_authenticationPath[height] = retained[0];
                        retained.RemoveAt(0);
                    }
                }

                /* reinitialize treehash instances */
                int minHeight = System.Math.Min(tau, m_treeHeight - m_k);
                for (int height = 0; height < minHeight; height++)
                {
                    int startIndex = m_index + 1 + (3 * (1 << height));
                    if (startIndex < (1 << m_treeHeight))
                    {
                        m_treeHashInstances[height].Initialize(startIndex);
                    }
                }
            }

            /* update treehash instances */
            for (int i = 0; i < (m_treeHeight - m_k) >> 1; i++)
            {
                BdsTreeHash treeHash = GetBdsTreeHashInstanceForUpdate();
                if (treeHash != null)
                {
                    treeHash.Update(m_stack, m_wotsPlus, publicSeed, secretSeed, leafAddress);
                }
            }

            m_index++;
        }

        internal bool IsUsed => m_used;

        internal void MarkUsed()
        {
            m_used = true;
        }

        private BdsTreeHash GetBdsTreeHashInstanceForUpdate()
        {
            BdsTreeHash ret = null;
            foreach (BdsTreeHash treeHash in m_treeHashInstances)
            {
                if (treeHash.IsFinished || !treeHash.IsInitialized)
                {
                    continue;
                }
                if (ret == null)
                {
                    ret = treeHash;
                    continue;
                }
                if (treeHash.Height < ret.Height)
                {
                    ret = treeHash;
                    continue;
                }
                if (treeHash.Height == ret.Height)
                {
                    if (treeHash.IndexLeaf < ret.IndexLeaf)
                    {
                        ret = treeHash;
                    }
                }
            }
            return ret;
        }

        internal void Validate()
        {
            if (m_authenticationPath == null)
                throw new InvalidOperationException("authenticationPath == null");
            if (m_retain == null)
                throw new InvalidOperationException("retain == null");
            if (m_stack == null)
                throw new InvalidOperationException("stack == null");
            if (m_treeHashInstances == null)
                throw new InvalidOperationException("treeHashInstances == null");
            if (m_keep == null)
                throw new InvalidOperationException("keep == null");
            if (m_treeHeight < 2 || m_treeHeight > XmssParameters.MaxHeight)
                throw new InvalidOperationException("treeHeight in BDS state out of bounds");
            if (m_k > m_treeHeight || m_k < 2 || ((m_treeHeight - m_k) & 1) != 0)
                throw new InvalidOperationException("k in BDS state out of bounds");

            int maxIndexLimit = (1 << m_treeHeight) - 1;
            if (m_maxIndex < 0 || m_maxIndex > maxIndexLimit || m_index < 0 || m_index > m_maxIndex + 1)
                throw new InvalidOperationException("index in BDS state out of bounds");

            if (m_root == null)
            {
                if (m_authenticationPath.Count != 0)
                    throw new InvalidOperationException("authenticationPath present without root");
            }
            else
            {
                if (m_root.Height != m_treeHeight || m_authenticationPath.Count != m_treeHeight)
                    throw new InvalidOperationException("inconsistent root or authenticationPath in BDS state");
            }
            if (m_treeHashInstances.Count != m_treeHeight - m_k || m_retain.Count > m_k - 1
                || m_stack.Count > m_treeHeight || m_keep.Count > m_treeHeight)
            {
                throw new InvalidOperationException("inconsistent collection size in BDS state");
            }
        }

        internal void Validate(XmssParameters parameters)
        {
            Validate();
            if (m_treeHeight != parameters.Height || m_k != parameters.K)
                throw new InvalidOperationException("BDS state does not match XMSS parameters");

            int digestSize = parameters.TreeDigestSize;
            ValidateNode(m_root, digestSize, m_treeHeight, m_treeHeight);
            for (int i = 0; i < m_authenticationPath.Count; i++)
            {
                ValidateRequiredNode(m_authenticationPath[i], digestSize, i, i);
            }

            foreach (var entry in m_retain)
            {
                int height = entry.Key;
                if (height < m_treeHeight - m_k || height > m_treeHeight - 2)
                    throw new InvalidOperationException("retain height in BDS state out of bounds");

                List<XmssNode> nodes = entry.Value;
                int maximumRetained = (1 << (m_treeHeight - height - 1)) - 1;
                if (nodes == null || nodes.Count > maximumRetained)
                    throw new InvalidOperationException("retain queue in BDS state out of bounds");

                ValidateNodes(nodes, digestSize, height, height);
            }

            ValidateNodes(m_stack, digestSize, 0, m_treeHeight);
            for (int i = 0; i < m_treeHashInstances.Count; i++)
            {
                BdsTreeHash treeHash = m_treeHashInstances[i];
                if (treeHash == null || treeHash.InitialHeight != i || treeHash.RawHeight < 0
                    || treeHash.RawHeight > i || treeHash.IndexLeaf < 0
                    || treeHash.IndexLeaf > (1 << m_treeHeight) - 1)
                {
                    throw new InvalidOperationException("tree hash in BDS state out of bounds");
                }
                ValidateNode(treeHash.TailNode, digestSize, 0, i);
            }

            foreach (var entry in m_keep)
            {
                int height = entry.Key;
                if (height < 0 || height > m_treeHeight - 2)
                    throw new InvalidOperationException("keep height in BDS state out of bounds");

                ValidateRequiredNode(entry.Value, digestSize, height, height);
            }
        }

        /// <summary>
        /// Confirm the root this state carries is the one the enclosing private key declares. The two are
        /// independent copies of the same value in one encoding and always agree on a genuine key, so a
        /// disagreement means the stored key has been corrupted.
        /// </summary>
        /// <remarks>
        /// A null root on either side is not compared: <see cref="Validate()"/> tolerates an absent root node, and
        /// a key built without one carries zeros.
        /// </remarks>
        /// <param name="expectedRoot">the root the private key declares.</param>
        internal void ValidateRoot(byte[] expectedRoot)
        {
            if (m_root == null || expectedRoot == null)
                return;

            if (!Arrays.AreEqual(m_root.GetValue(), expectedRoot))
                throw new InvalidOperationException("BDS state root does not match the private key root");
        }

        internal void Validate(XmssParameters parameters, int expectedIndex)
        {
            Validate(parameters);
            // RFC 8391 Section 1.1 requires each secret-key state to be used only once. Tie restored BDS state to
            // the enclosing private-key index so stale or mismatched traversal state is rejected.
            if (m_index != expectedIndex)
                throw new InvalidOperationException("BDS state has wrong index");
        }

        private static void ValidateNodes(IEnumerable<XmssNode> nodes, int digestSize, int minimumHeight,
            int maximumHeight)
        {
            foreach (XmssNode node in nodes)
            {
                ValidateRequiredNode(node, digestSize, minimumHeight, maximumHeight);
            }
        }

        private static void ValidateRequiredNode(XmssNode node, int digestSize, int minimumHeight,
            int maximumHeight)
        {
            if (node == null)
                throw new InvalidOperationException("null XMSS node in BDS state");

            ValidateNode(node, digestSize, minimumHeight, maximumHeight);
        }

        private static void ValidateNode(XmssNode node, int digestSize, int minimumHeight, int maximumHeight)
        {
            if (node != null)
            {
                if (node.Height < minimumHeight || node.Height > maximumHeight || !node.HasValueLength(digestSize))
                    throw new InvalidOperationException("XMSS node in BDS state out of bounds");
            }
        }

        internal int TreeHeight => m_treeHeight;

        internal XmssNode Root => m_root;

        /// <summary>
        /// The authentication path, as a copy: the one accessor here that still makes one, because what the
        /// engine does with it is put it in a signature that outlives the call.
        /// </summary>
        internal List<XmssNode> GetAuthenticationPath() => new List<XmssNode>(m_authenticationPath);

        /// <summary>
        /// Whether this state has an authentication path yet, which is what says whether the key holding it can
        /// sign: a key decoded from an encoding that carried no traversal state has none.
        /// </summary>
        internal bool IsAuthenticationPathEmpty => m_authenticationPath.Count == 0;

        internal int Index => m_index;

        internal int MaxIndex => m_maxIndex;

        internal int K => m_k;

        /*
         * The state's own five collections, by reference rather than as a copy of each. BdsStateCodec.WriteBds is
         * the caller - it asks each one its size and iterates it, writing every one of them to a stream and none of
         * them to itself. These five are filled inside constructors and never after: advancing means building the
         * successor (GetNextState), and Initialize() and NextAuthenticationPath() are both private and reached only
         * from a constructor, over collections it has already copied. Anything that needs one of them to hold still
         * wants the copy Bds(Bds) makes rather than one of its own, because the depth is not obvious -
         * CloneRetain() reaches the queues NextAuthenticationPath() removes from, and CloneTreeHashInstances() each
         * instance it updates.
         */

        internal List<XmssNode> LiveAuthenticationPath => m_authenticationPath;

        internal SortedDictionary<int, List<XmssNode>> LiveRetain => m_retain;

        internal List<XmssNode> LiveStack => m_stack;

        internal List<BdsTreeHash> LiveTreeHashInstances => m_treeHashInstances;

        internal SortedDictionary<int, XmssNode> LiveKeep => m_keep;

        internal Bds WithWotsDigest(DerObjectIdentifier digestName) => new Bds(this, digestName, -1);

        internal Bds WithWotsDigest(DerObjectIdentifier digestName, int digestSize) =>
            new Bds(this, digestName, digestSize);

        internal Bds WithMaxIndex(int maxIndex, DerObjectIdentifier digestName) =>
            new Bds(this, maxIndex, digestName, -1);

        internal Bds WithMaxIndex(int maxIndex, DerObjectIdentifier digestName, int digestSize) =>
            new Bds(this, maxIndex, digestName, digestSize);
    }
}
