
using System;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    internal abstract class Benes
    {
        private static readonly ulong[] TransposeMasks = { 0x5555555555555555UL, 0x3333333333333333UL,
            0x0F0F0F0F0F0F0F0FUL, 0x00FF00FF00FF00FFUL, 0x0000FFFF0000FFFFUL, 0x00000000FFFFFFFFUL };

        protected readonly int SYS_N;
        protected readonly int SYS_T;
        protected readonly int GFBITS;

        internal Benes(int n, int t, int m)
        {
            SYS_N = n;
            SYS_T = t;
            GFBITS = m;
        }

        /* input: in, a 64x64 matrix over GF(2) */
        /* outputput: output, transpose of in */
        internal static void Transpose64x64(ulong[] output, ulong[] input)
        {
            Transpose64x64(output, input, 0);
        }

        internal static void Transpose64x64(ulong[] output, ulong[] input, int offset)
        {
            Array.Copy(input, offset, output, offset, 64);

            int d = 5;
            do
            {
                ulong m = TransposeMasks[d];
                int s = 1 << d;
                for (int i = offset; i < offset + 64; i += s * 2)
                {
                    for (int j = i; j < i + s; j += 4)
                    {
                        Bits.BitPermuteStep2(ref output[j + s + 0], ref output[j + 0], m, s);
                        Bits.BitPermuteStep2(ref output[j + s + 1], ref output[j + 1], m, s);
                        Bits.BitPermuteStep2(ref output[j + s + 2], ref output[j + 2], m, s);
                        Bits.BitPermuteStep2(ref output[j + s + 3], ref output[j + 3], m, s);
                    }
                }
            }
            while (--d >= 2);

            do
            {
                ulong m = TransposeMasks[d];
                int s = 1 << d;
                for (int i = offset; i < offset + 64; i += s * 2)
                {
                    for (int j = i; j < i + s; ++j)
                    {
                        Bits.BitPermuteStep2(ref output[j + s], ref output[j], m, s);
                    }
                }
            }
            while (--d >= 0);
        }

        internal abstract void SupportGen(ushort[] s, byte[] c);
    }
}
