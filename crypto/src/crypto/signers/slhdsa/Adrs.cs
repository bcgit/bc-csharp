using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class Adrs
    {
        internal const uint WotsHash = 0;
        internal const uint WotsPK = 1;
        internal const uint Tree = 2;
        internal const uint ForsTree = 3;
        internal const uint ForsPK = 4;
        internal const uint WotsPrf = 5;
        internal const uint ForsPrf = 6;

        internal const int OffsetLayer = 0;
        internal const int OffsetTree = 4;
        internal const int OffsetTreeHgt = 24;
        internal const int OffsetTreeIndex = 28;
        internal const int OffsetType = 16;
        internal const int OffsetKPAddr = 20;
        internal const int OffsetChainAddr = 24;
        internal const int OffsetHashAddr = 28;

        private readonly byte[] m_value = new byte[32];

        internal Adrs()
        {
        }

        internal Adrs(uint adrsType)
        {
            SetType(adrsType);
        }

        internal Adrs(Adrs adrs)
        {
            Array.Copy(adrs.m_value, 0, m_value, 0, 32);
        }

        internal Adrs(Adrs adrs, uint adrsType)
        {
            Array.Copy(adrs.m_value, 0, m_value, 0, OffsetType);
            SetType(adrsType);
        }

        internal void SetLayerAddress(uint layer) => Pack.UInt32_To_BE(layer, m_value, OffsetLayer);

        internal void SetTreeAddress(ulong tree) => Pack.UInt64_To_BE(tree, m_value, OffsetTree + 4);

        internal void SetTreeHeight(uint height) => Pack.UInt32_To_BE(height, m_value, OffsetTreeHgt);

        internal void SetTreeIndex(uint index) => Pack.UInt32_To_BE(index, m_value, OffsetTreeIndex);

        internal uint GetTreeIndex() => Pack.BE_To_UInt32(m_value, OffsetTreeIndex);

        internal void SetType(uint adrsType) => Pack.UInt32_To_BE(adrsType, m_value, OffsetType);

        // resets part of value to zero in line with 2.7.3
        internal void SetTypeAndClear(uint adrsType)
        {
            SetType(adrsType);
            Arrays.Fill(m_value, OffsetType + 4, 32, 0x00);
        }

        internal void SetKeyPairAddress(uint keyPairAddr) => Pack.UInt32_To_BE(keyPairAddr, m_value, OffsetKPAddr);

        internal uint GetKeyPairAddress() => Pack.BE_To_UInt32(m_value, OffsetKPAddr);

        internal void SetHashAddress(uint hashAddr) => Pack.UInt32_To_BE(hashAddr, m_value, OffsetHashAddr);

        internal void SetChainAddress(uint chainAddr) => Pack.UInt32_To_BE(chainAddr, m_value, OffsetChainAddr);

        internal byte[] Value => m_value;
    }
}
