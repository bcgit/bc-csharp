using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    internal static class Utils
    {
        internal static void StoreGF(byte[] dest, int offset, ushort a)
        {
            Pack.UInt16_To_LE(a, dest, offset);
        }

        internal static ushort LoadGF(byte[] src, int offset, int gfmask)
        {
            return (ushort)(Pack.LE_To_UInt16(src, offset) & gfmask);
        }

        internal static uint Load4(byte[] input, int offset)
        {
            return Pack.LE_To_UInt32(input, offset);
        }

        internal static void Store8(byte[] output, int offset, ulong input)
        {
            Pack.UInt64_To_LE(input, output, offset);
        }

        internal static void Store8(byte[] output, int offset, ulong[] input, int inOff, int inLen)
        {
            Pack.UInt64_To_LE(input, inOff, inLen, output, offset);
        }

        internal static ulong Load8(byte[] input, int offset)
        {
            return Pack.LE_To_UInt64(input, offset);
        }

        internal static void Load8(byte[] input, int offset, ulong[] output, int outOff, int outLen)
        {
            Pack.LE_To_UInt64(input, offset, output, outOff, outLen);
        }

        internal static ushort Bitrev(ushort a, int GFBITS)
        {
            return (ushort)(Integers.Reverse((uint)a) >> (32 - GFBITS));
        }
    }
}
