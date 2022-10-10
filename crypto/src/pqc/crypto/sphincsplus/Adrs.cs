using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class Adrs
    {
        internal static uint WOTS_HASH = 0;
        internal static uint WOTS_PK = 1;
        internal static uint TREE = 2;
        internal static uint FORS_TREE = 3;
        internal static uint FORS_PK = 4;
        internal static uint WOTS_PRF = 5;
        internal static uint FORS_PRF = 6;

        internal static int OFFSET_LAYER = 0;
        internal static int OFFSET_TREE = 4;
        internal static int OFFSET_TREE_HGT = 24;
        internal static int OFFSET_TREE_INDEX = 28;
        internal static int OFFSET_TYPE = 16;
        internal static int OFFSET_KP_ADDR = 20;
        internal static int OFFSET_CHAIN_ADDR = 24;
        internal static int OFFSET_HASH_ADDR = 28;

        internal readonly byte[] value = new byte[32];

        internal Adrs()
        {
        }

        internal Adrs(Adrs adrs)
        {
            Array.Copy(adrs.value, 0, value, 0, adrs.value.Length);
        }

        internal void SetLayerAddress(uint layer)
        {
            Pack.UInt32_To_BE(layer, value, OFFSET_LAYER);
        }

        internal uint GetLayerAddress()
        {
            return Pack.BE_To_UInt32(value, OFFSET_LAYER);
        }

        internal void SetTreeAddress(ulong tree)
        {
            // tree address is 12 bytes
            Pack.UInt64_To_BE(tree, value, OFFSET_TREE + 4);
        }

        internal ulong GetTreeAddress()
        {
            // tree address is 12 bytes
            return Pack.BE_To_UInt64(value, OFFSET_TREE + 4);
        }

        internal void SetTreeHeight(uint height)
        {
            Pack.UInt32_To_BE(height, value, OFFSET_TREE_HGT);
        }

        internal uint GetTreeHeight()
        {
            return Pack.BE_To_UInt32(value, OFFSET_TREE_HGT);
        }

        internal void SetTreeIndex(uint index)
        {
            Pack.UInt32_To_BE(index, value, OFFSET_TREE_INDEX);
        }

        internal uint GetTreeIndex()
        {
            return Pack.BE_To_UInt32(value, OFFSET_TREE_INDEX);
        }

        // resets part of value to zero in line with 2.7.3
        internal void SetAdrsType(uint adrsType)
        {
            Pack.UInt32_To_BE(adrsType, value, OFFSET_TYPE);

            Arrays.Fill(value, OFFSET_TYPE + 4, value.Length, 0x00);
        }

        internal void ChangeAdrsType(uint adrsType)
        {
            Pack.UInt32_To_BE(adrsType, value, OFFSET_TYPE);
        }

        internal uint GetAdrsType()
        {
            return Pack.BE_To_UInt32(value, OFFSET_TYPE);
        }

        internal void SetKeyPairAddress(uint keyPairAddr)
        {
            Pack.UInt32_To_BE(keyPairAddr, value, OFFSET_KP_ADDR);
        }

        internal uint GetKeyPairAddress()
        {
            return Pack.BE_To_UInt32(value, OFFSET_KP_ADDR);
        }

        internal void SetHashAddress(uint hashAddr)
        {
            Pack.UInt32_To_BE(hashAddr, value, OFFSET_HASH_ADDR);
        }

        public void SetChainAddress(uint chainAddr)
        {
            Pack.UInt32_To_BE(chainAddr, value, OFFSET_CHAIN_ADDR);
        }
    }
}
