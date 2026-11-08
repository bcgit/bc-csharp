using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    internal static class XmssVerifierUtilities
    {
        /// <summary>Compute a root node from a tree signature.</summary>
        /// <remarks>
        /// The length check holds a boundary: a digest of the wrong length is not rejected downstream but silently
        /// truncated by the base-w conversion. Every messageDigest reaching here is a keyed hash function output -
        /// H_msg at the two entry points, or a node this method itself returned one layer down.
        /// </remarks>
        /// <param name="wotsPlus">the WOTS+ instance, with the public seed imported.</param>
        /// <param name="height">the height of the tree.</param>
        /// <param name="messageDigest">Message digest.</param>
        /// <param name="signature">XMSS signature.</param>
        /// <param name="otsAddress">the 32-byte encoding of the OTS hash address the signing key was at. The OTS
        /// address word of it names the leaf, and is read out before GetPublicKeyFromSignature below writes the
        /// three words after it.</param>
        /// <param name="indexLeaf">the index of the leaf in the tree.</param>
        /// <returns>Root node calculated from signature.</returns>
        internal static XmssNode GetRootNodeFromSignature(WotsPlus wotsPlus, int height, byte[] messageDigest,
            XmssReducedSignature signature, byte[] otsAddress, int indexLeaf)
        {
            if (messageDigest.Length != wotsPlus.Params.TreeDigestSize)
                throw new ArgumentException("size of messageDigest needs to be equal to size of digest");

            /* prepare adresses */
            int otsIndex = XmssAddress.OtsAddressOf(otsAddress);
            byte[] lTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.LTreeType);
            Pack.UInt32_To_BE((uint)otsIndex, lTreeAddress, XmssAddress.LTreeAddressOffset);
            byte[] hashTreeAddress = XmssAddress.SubtreeAddressOf(otsAddress, XmssAddress.HashTreeType);
            Pack.UInt32_To_BE((uint)otsIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
            /* the tree index of that encoding, kept alongside it as the climb halves it */
            int hashTreeIndex = otsIndex;
            /* and one pair of working buffers for every node hashed below, L-tree and climb alike; see
             * XmssNodeUtilities.RandomizeHash for why one pair serves a whole walk */
            int n = wotsPlus.Params.TreeDigestSize;
            byte[] nodeKey = new byte[n];
            byte[] nodeMask = new byte[2 * n];
            /*
             * calculate WOTS+ public key and compress to obtain original leaf hash
             */
            WotsPlusPublicKeyParameters wotsPlusPK = wotsPlus.GetPublicKeyFromSignature(messageDigest,
                signature.GetWotsPlusSignature(), otsAddress);
            XmssNode[] node = new XmssNode[2];
            node[0] = XmssNodeUtilities.LTree(wotsPlus, wotsPlusPK, lTreeAddress, nodeKey, nodeMask);

            for (int k = 0; k < height; k++)
            {
                Pack.UInt32_To_BE((uint)k, hashTreeAddress, XmssAddress.TreeHeightOffset);
                if ((indexLeaf / (1 << k)) % 2 == 0)
                {
                    hashTreeIndex = hashTreeIndex / 2;
                    Pack.UInt32_To_BE((uint)hashTreeIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
                    node[1] = XmssNodeUtilities.RandomizeHash(wotsPlus, node[0], signature.AuthPath[k],
                        hashTreeAddress, nodeKey, nodeMask);
                }
                else
                {
                    hashTreeIndex = (hashTreeIndex - 1) / 2;
                    Pack.UInt32_To_BE((uint)hashTreeIndex, hashTreeAddress, XmssAddress.TreeIndexOffset);
                    node[1] = XmssNodeUtilities.RandomizeHash(wotsPlus, signature.AuthPath[k], node[0],
                        hashTreeAddress, nodeKey, nodeMask);
                }
                node[1] = node[1].IncrementHeight();
                node[0] = node[1];
            }
            return node[0];
        }
    }
}
