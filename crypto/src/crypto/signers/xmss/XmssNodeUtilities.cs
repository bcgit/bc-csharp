using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    internal static class XmssNodeUtilities
    {
        /// <summary>Compresses a WOTS+ public key to a single n-byte string.</summary>
        /// <remarks>
        /// The key and the length it is walked with must come from the same <see cref="WotsPlus"/> instance; that
        /// pairing is this method's real precondition and it is the caller's to keep.
        /// </remarks>
        /// <param name="wotsPlus">the WOTS+ instance the key was taken from.</param>
        /// <param name="publicKey">WOTS+ public key to compress.</param>
        /// <param name="address">the 32-byte encoding of this leaf's L-tree address. The caller owns it and has set
        /// the L-tree address word; this walk writes the tree height and tree index words of it, and
        /// <see cref="RandomizeHash"/> writes key-and-mask.</param>
        /// <param name="key">an n-byte buffer the caller owns, handed on to <see cref="RandomizeHash"/>.</param>
        /// <param name="tmpMask">a 2n-byte buffer the caller owns, handed on likewise.</param>
        /// <returns>Compressed n-byte string of public key.</returns>
        internal static XmssNode LTree(WotsPlus wotsPlus, WotsPlusPublicKeyParameters publicKey, byte[] address,
            byte[] key, byte[] tmpMask)
        {
            int len = wotsPlus.Params.Len;
            /* the key's blocks as the leaves of the L-tree, and the walk overwrites the array, not them */
            XmssNode[] publicKeyNodes = publicKey.ToNodes();
            int treeHeight = 0;
            Pack.UInt32_To_BE((uint)treeHeight, address, XmssAddress.TreeHeightOffset);
            while (len > 1)
            {
                for (int i = 0; i < len / 2; i++)
                {
                    Pack.UInt32_To_BE((uint)i, address, XmssAddress.TreeIndexOffset);
                    publicKeyNodes[i] = RandomizeHash(wotsPlus, publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1],
                        address, key, tmpMask);
                }
                if (len % 2 == 1)
                {
                    publicKeyNodes[len / 2] = publicKeyNodes[len - 1];
                }
                len = (int)System.Math.Ceiling((double)len / 2);
                Pack.UInt32_To_BE((uint)++treeHeight, address, XmssAddress.TreeHeightOffset);
            }
            return publicKeyNodes[0];
        }

        /// <summary>Randomization of nodes in binary tree.</summary>
        /// <param name="wotsPlus">the WOTS+ instance supplying the public seed and the keyed hash functions.</param>
        /// <param name="left">Left node.</param>
        /// <param name="right">Right node.</param>
        /// <param name="address">the 32-byte encoding of the address of the node being computed. The caller owns
        /// it and has written the words that name that node; this method writes the key-and-mask word of it, once
        /// before each of the three hashes below.</param>
        /// <param name="key">an n-byte buffer the caller owns, for the PRF result H reads as a key.</param>
        /// <param name="tmpMask">a 2n-byte buffer the caller owns, for the two bitmasks.</param>
        /// <returns>Randomized hash of parent of left / right node.</returns>
        internal static XmssNode RandomizeHash(WotsPlus wotsPlus, XmssNode left, XmssNode right, byte[] address,
            byte[] key, byte[] tmpMask)
        {
            if (left.Height != right.Height)
                throw new InvalidOperationException("height of both nodes must be equal");

            byte[] publicSeed = wotsPlus.PublicSeed;
            KeyedHashFunctions khf = wotsPlus.Khf;
            int n = wotsPlus.Params.TreeDigestSize;

            // The three PRFs differ in the key-and-mask word alone, written in before each (RFC 8391 sec. 4.1.5).
            // PRF fills all n bytes of key and both n-byte halves of tmpMask before either is read, so nothing
            // carries between nodes; only out has to be this call's own, as it becomes the returned node's value.
            Pack.UInt32_To_BE(0U, address, XmssAddress.KeyAndMaskOffset);
            khf.Prf(publicSeed, address, key);

            Pack.UInt32_To_BE(1U, address, XmssAddress.KeyAndMaskOffset);
            khf.Prf(publicSeed, address, tmpMask, 0);

            Pack.UInt32_To_BE(2U, address, XmssAddress.KeyAndMaskOffset);
            khf.Prf(publicSeed, address, tmpMask, n);

            left.MaskInto(n, tmpMask, 0);
            right.MaskInto(n, tmpMask, n);

            byte[] output = new byte[n];
            khf.H(key, tmpMask, output);
            return new XmssNode(left.Height, output);
        }
    }
}
