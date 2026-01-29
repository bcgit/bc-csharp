#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
#endif

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal static class Cbd
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Eta2(Span<short> r, ReadOnlySpan<byte> bytes)
#else
        internal static void Eta2(short[] r, byte[] bytes)
#endif
        {
            for (int i = 0; i < MLKemEngine.N / 8; i++)
            {
                uint t = Pack.LE_To_UInt32(bytes, 4 * i);
                uint d = t & 0x55555555;
                d += (t >> 1) & 0x55555555;
                for (int j = 0; j < 8; j++)
                {
                    short a = (short)((d >> (4 * j + 0)) & 0x3);
                    short b = (short)((d >> (4 * j + 2)) & 0x3);
                    r[8 * i + j] = (short)(a - b);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Eta3(Span<short> r, ReadOnlySpan<byte> bytes)
#else
        internal static void Eta3(short[] r, byte[] bytes)
#endif
        {
            for (int i = 0; i < MLKemEngine.N / 4; i++)
            {
                uint t = Pack.LE_To_UInt24(bytes, 3 * i);
                uint d = t & 0x00249249;
                d += (t >> 1) & 0x00249249;
                d += (t >> 2) & 0x00249249;

                for (int j = 0; j < 4; j++)
                {
                    short a = (short)((d >> (6 * j + 0)) & 0x7);
                    short b = (short)((d >> (6 * j + 3)) & 0x7);
                    r[4 * i + j] = (short)(a - b);
                }
            }
        }
    }
}
