using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    internal sealed class BdsTreeHash
    {
        private XmssNode m_tailNode;
        private readonly int m_initialHeight;
        private int m_height;
        private int m_nextIndex;
        private bool m_initialized;
        private bool m_finished;

        internal BdsTreeHash(int initialHeight)
        {
            m_initialHeight = initialHeight;
            m_initialized = false;
            m_finished = false;
        }

        internal BdsTreeHash(int initialHeight, int height, int nextIndex, bool initialized, bool finished,
            XmssNode tailNode)
        {
            m_initialHeight = initialHeight;
            m_height = height;
            m_nextIndex = nextIndex;
            m_initialized = initialized;
            m_finished = finished;
            m_tailNode = tailNode;
        }

        internal void Initialize(int nextIndex)
        {
            m_tailNode = null;
            m_height = m_initialHeight;
            m_nextIndex = nextIndex;
            m_initialized = true;
            m_finished = false;
        }

        /// <summary>Take this tree hash instance one leaf further (RFC 8391 sec. 4.1.6 algorithm 10).</summary>
        /// <param name="stack">the BDS state's node stack; the last element is the top.</param>
        /// <param name="wotsPlus">the BDS state's WOTS+ instance.</param>
        /// <param name="publicSeed">the key's public seed.</param>
        /// <param name="secretSeed">the key's secret seed.</param>
        /// <param name="otsAddress">the 32-byte encoding of the OTS hash address the tree starts at. This writes the
        /// OTS address word of it, naming the leaf below, and WOTS+ the three words after that; the only caller is
        /// the walk in <see cref="Bds"/>'s next authentication path step, over the copy it owns, and it calls this
        /// several times running - each of which names its own leaf here before anything is derived from the
        /// encoding.</param>
        internal void Update(List<XmssNode> stack, WotsPlus wotsPlus, byte[] publicSeed, byte[] secretSeed,
            byte[] otsAddress)
        {
            if (m_finished || !m_initialized)
                throw new InvalidOperationException("finished or not initialized");

            /* prepare addresses */
            Pack.UInt32_To_BE((uint)m_nextIndex, otsAddress, XmssAddress.OtsAddressOffset);
            /* the leaf's own two addresses, taken from the tree its encoding names and then named for the same leaf
             * a second and a third time */
            byte[] lTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.LTreeType);
            Pack.UInt32_To_BE((uint)m_nextIndex, lTreeAddress, XmssAddress.LTreeAddressOffset);
            byte[] hashTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.HashTreeType);
            Pack.UInt32_To_BE((uint)m_nextIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
            /* the two words of that encoding this climb moves, kept alongside it so stepping one is an increment
             * rather than a read back out of the bytes */
            int hashTreeHeight = 0;
            int hashTreeIndex = m_nextIndex;
            /* and one pair of working buffers for every node hashed below; see XmssNodeUtilities.RandomizeHash for
             * why one pair serves a whole walk */
            int n = wotsPlus.Params.TreeDigestSize;
            byte[] nodeKey = new byte[n];
            byte[] nodeMask = new byte[2 * n];
            /* calculate leaf node */
            byte[] wotsPlusSecretKey = wotsPlus.GetWotsPlusSecretKey(secretSeed, otsAddress);
            wotsPlus.ImportKeys(wotsPlusSecretKey, publicSeed);
            // the instance keeps its own copy; this one would otherwise outlive the walk
            Arrays.ZeroMemory(wotsPlusSecretKey);
            WotsPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.GetPublicKey(otsAddress);
            XmssNode node = XmssNodeUtilities.LTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey, nodeMask);

            while (stack.Count > 0 && Bds.Peek(stack).Height == node.Height
                && Bds.Peek(stack).Height != m_initialHeight)
            {
                hashTreeIndex = (hashTreeIndex - 1) / 2;
                Pack.UInt32_To_BE((uint)hashTreeIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
                node = XmssNodeUtilities.RandomizeHash(wotsPlus, Bds.Pop(stack), node, hashTreeAddress, nodeKey,
                    nodeMask);
                node = node.IncrementHeight();
                Pack.UInt32_To_BE((uint)++hashTreeHeight, hashTreeAddress, XmssAddress.TreeHeightOffset);
            }

            if (m_tailNode == null)
            {
                m_tailNode = node;
            }
            else
            {
                if (m_tailNode.Height == node.Height)
                {
                    hashTreeIndex = (hashTreeIndex - 1) / 2;
                    Pack.UInt32_To_BE((uint)hashTreeIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
                    node = XmssNodeUtilities.RandomizeHash(wotsPlus, m_tailNode, node, hashTreeAddress, nodeKey,
                        nodeMask);
                    node = node.IncrementHeight();
                    m_tailNode = node;
                    // the last step of the same climb the loop above makes - parent, hash, then name the level
                    // above. This is the final climb, so nothing reads the result; it is kept so both merges read
                    // alike and so the code still matches the unconditional increment that closes the loop of
                    // RFC 8391 sec. 4.1.6 algorithm 9.
                    Pack.UInt32_To_BE((uint)++hashTreeHeight, hashTreeAddress, XmssAddress.TreeHeightOffset);
                }
                else
                {
                    stack.Add(node);
                }
            }

            if (m_tailNode.Height == m_initialHeight)
            {
                m_finished = true;
            }
            else
            {
                m_height = node.Height;
                m_nextIndex++;
            }
        }

        internal int Height
        {
            get
            {
                if (!m_initialized || m_finished)
                    return int.MaxValue;

                return m_height;
            }
        }

        internal int IndexLeaf => m_nextIndex;

        internal int InitialHeight => m_initialHeight;

        internal int RawHeight => m_height;

        internal void SetNode(XmssNode node)
        {
            m_tailNode = node;
            m_height = node.Height;
            if (m_height == m_initialHeight)
            {
                m_finished = true;
            }
        }

        internal bool IsFinished => m_finished;

        internal bool IsInitialized => m_initialized;

        internal XmssNode TailNode => m_tailNode;

        internal BdsTreeHash Clone()
        {
            BdsTreeHash th = new BdsTreeHash(m_initialHeight);

            th.m_tailNode = m_tailNode;
            th.m_height = m_height;
            th.m_nextIndex = m_nextIndex;
            th.m_initialized = m_initialized;
            th.m_finished = m_finished;

            return th;
        }
    }
}
