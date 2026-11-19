using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>XMSS address.</summary>
    /// <remarks>
    /// <para>
    /// An address is 32 bytes and nothing holds one as an object: what the methods here produce and read is the
    /// encoding itself, which is what this package hands around and steps.
    /// </para>
    /// <para>
    /// Of the three address types RFC 8391 sec. 2.5 defines only the OTS hash address is made from parts, by
    /// <see cref="OtsHashAddress(int, long, int)"/>. An L-tree address and a hash tree address are made from one of
    /// those by <see cref="SubtreeAddressOf(byte[], int)"/> and then written into by the walk that carries them.
    /// All three are the one 32-byte frame with its words numbered the same way, and the type word says what the
    /// three words below it mean.
    /// </para>
    /// </remarks>
    internal static class XmssAddress
    {
        /// <summary>
        /// Offset of the type word in the 32-byte encoding, and so also the length of what comes before it: the
        /// layer address and the two words of the tree address.
        /// </summary>
        internal const int TypeOffset = 12;

        /// <summary>The type word of an OTS hash address.</summary>
        private const int OtsHashType = 0x00;

        /// <summary>The type word of an L-tree address.</summary>
        internal const int LTreeType = 0x01;

        /// <summary>
        /// The type word of a hash tree address. The padding word this type puts where an L-tree address puts its
        /// index is zero, which is what <see cref="SubtreeAddressOf(byte[], int)"/> leaves it at, and no walk
        /// writes it.
        /// </summary>
        internal const int HashTreeType = 0x02;

        /// <summary>
        /// Offsets of the word below the type word under the two types that name a leaf in it - the OTS hash
        /// address of a leaf's one-time key, and the L-tree address of the walk that compresses that key.
        /// </summary>
        internal const int OtsAddressOffset = 16;
        internal const int LTreeAddressOffset = 16;

        /// <summary>
        /// Offsets of the tree height and tree index words in the 32-byte encoding, under the L-tree and hash tree
        /// address types.
        /// </summary>
        internal const int TreeHeightOffset = 20;
        internal const int TreeIndexOffset = 24;

        /// <summary>
        /// Offsets of those same two words under the OTS hash address type, where they are the chain address and
        /// the hash address.
        /// </summary>
        internal const int ChainAddressOffset = 20;
        internal const int HashAddressOffset = 24;

        /// <summary>Offset of the key-and-mask word in the 32-byte encoding.</summary>
        internal const int KeyAndMaskOffset = 28;

        /// <summary>
        /// The encoding of the OTS hash address of a leaf: which leaf, and the tree the three words above it name.
        /// </summary>
        /// <remarks>
        /// The chain address, the hash address and the key-and-mask are not parameters: a walk steps them through
        /// the encoding it already holds. All three are zero in what this produces.
        /// </remarks>
        /// <param name="layerAddress">which layer of an XMSS^MT hypertree the leaf's tree is on; zero for XMSS,
        /// and for the bottom layer of an XMSS^MT.</param>
        /// <param name="treeAddress">which tree of that layer; zero where the layer holds one.</param>
        /// <param name="otsAddress">which leaf of that tree.</param>
        /// <returns>a fresh 32-byte encoding of that address.</returns>
        internal static byte[] OtsHashAddress(int layerAddress, long treeAddress, int otsAddress)
        {
            byte[] address = new byte[32];
            Pack.UInt32_To_BE((uint)layerAddress, address, 0);
            Pack.UInt64_To_BE((ulong)treeAddress, address, 4);
            Pack.UInt32_To_BE((uint)OtsHashType, address, TypeOffset);
            Pack.UInt32_To_BE((uint)otsAddress, address, OtsAddressOffset);
            return address;
        }

        /// <summary>The OTS address word of an OTS hash address encoding.</summary>
        /// <param name="address">the 32-byte encoding of an OTS hash address.</param>
        /// <returns>its OTS address.</returns>
        internal static int OtsAddressOf(byte[] address) => (int)Pack.BE_To_UInt32(address, OtsAddressOffset);

        /// <summary>
        /// The encoding of the address of the given type in the same tree as the given encoding: the twelve bytes
        /// before the type word copied across, that word set, and everything after it left at zero. This is
        /// copy_subtree_addr followed by set_type of RFC 8391 sec. 2.5.
        /// </summary>
        /// <remarks>
        /// Where the copy stops is the point of it: the three words below the type word mean something different
        /// per type, and none of what an OTS hash address holds there may reach a sibling address.
        /// </remarks>
        /// <param name="address">a 32-byte address encoding.</param>
        /// <param name="type">the type word wanted, <see cref="LTreeType"/> or <see cref="HashTreeType"/>.</param>
        /// <returns>a fresh 32-byte encoding of that address.</returns>
        internal static byte[] SubtreeAddressOf(byte[] address, int type)
        {
            byte[] subtreeAddress = new byte[32];
            Array.Copy(address, 0, subtreeAddress, 0, TypeOffset);
            Pack.UInt32_To_BE((uint)type, subtreeAddress, TypeOffset);
            return subtreeAddress;
        }
    }
}
