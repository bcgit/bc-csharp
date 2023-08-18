using System;
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    internal static class Wnaf
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void GetSignedVar(ReadOnlySpan<uint> n, int width, Span<sbyte> ws)
#else
        internal static void GetSignedVar(uint[] n, int width, sbyte[] ws)
#endif
        {
            Debug.Assert(2 <= width && width <= 8);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> t = n.Length <= 64
                ? stackalloc uint[n.Length * 2]
                : new uint[n.Length * 2];
#else
            uint[] t = new uint[n.Length * 2];
#endif
            {
                uint c = 0U - (n[n.Length - 1] >> 31);
                int tPos = t.Length, i = n.Length;
                while (--i >= 0)
                {
                    uint next = n[i];
                    t[--tPos] = (next >> 16) | (c << 16);
                    t[--tPos] = c = next;
                }
            }

            int j = 0, lead = 32 - width, sign = 0;

            for (int i = 0; i < t.Length; ++i, j -= 16)
            {
                uint word = t[i];
                while (j < 16)
                {
                    int word16 = (int)(word >> j);

                    int skip = Integers.NumberOfTrailingZeros((sign ^ word16) | (1 << 16));
                    if (skip > 0)
                    {
                        j += skip;
                        continue;
                    }

                    int digit = (word16 | 1) << lead;
                    sign = digit >> 31;

                    ws[(i << 4) + j] = (sbyte)(digit >> lead);

                    j += width;
                }
            }

            Debug.Assert(sign == (int)n[n.Length - 1] >> 31);
        }
    }
}
