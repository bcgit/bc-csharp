using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    internal class Utils
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
            a = (ushort) (((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8));
            a = (ushort) (((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4));
            a = (ushort) (((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2));
            a = (ushort) (((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1));
            return (ushort)(a >> (16 - GFBITS));
        }
    }
}
