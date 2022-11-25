using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#endif

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    internal static class ScalarUtilities
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void AddShifted_NP(int last, int s, Span<uint> Nu, ReadOnlySpan<uint> Nv, Span<uint> _p)
#else
        internal static void AddShifted_NP(int last, int s, uint[] Nu, uint[] Nv, uint[] _p)
#endif
        {
            int sWords = s >> 5, sBits = s & 31;

            ulong cc__p = 0UL;
            ulong cc_Nu = 0UL;

            if (sBits == 0)
            {
                for (int i = sWords; i <= last; ++i)
                {
                    cc_Nu += Nu[i];
                    cc_Nu += _p[i - sWords];

                    cc__p += _p[i];
                    cc__p += Nv[i - sWords];
                    _p[i]  = (uint)cc__p; cc__p >>= 32;

                    cc_Nu += _p[i - sWords];
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
            else
            {
                uint prev_p = 0U;
                uint prev_q = 0U;
                uint prev_v = 0U;

                for (int i = sWords; i <= last; ++i)
                {
                    uint next_p = _p[i - sWords];
                    uint p_s = (next_p << sBits) | (prev_p >> -sBits);
                    prev_p = next_p;

                    cc_Nu += Nu[i];
                    cc_Nu += p_s;

                    uint next_v = Nv[i - sWords];
                    uint v_s = (next_v << sBits) | (prev_v >> -sBits);
                    prev_v = next_v;

                    cc__p += _p[i];
                    cc__p += v_s;
                    _p[i]  = (uint)cc__p; cc__p >>= 32;

                    uint next_q = _p[i - sWords];
                    uint q_s = (next_q << sBits) | (prev_q >> -sBits);
                    prev_q = next_q;

                    cc_Nu += q_s;
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void AddShifted_UV(int last, int s, Span<uint> u0, Span<uint> u1, ReadOnlySpan<uint> v0,
            ReadOnlySpan<uint> v1)
#else
        internal static void AddShifted_UV(int last, int s, uint[] u0, uint[] u1, uint[] v0, uint[] v1)
#endif
        {
            int sWords = s >> 5, sBits = s & 31;

            ulong cc_u0 = 0UL;
            ulong cc_u1 = 0UL;

            if (sBits == 0)
            {
                for (int i = sWords; i <= last; ++i)
                {
                    cc_u0 += u0[i];
                    cc_u1 += u1[i];
                    cc_u0 += v0[i - sWords];
                    cc_u1 += v1[i - sWords];
                    u0[i]  = (uint)cc_u0; cc_u0 >>= 32;
                    u1[i]  = (uint)cc_u1; cc_u1 >>= 32;
                }
            }
            else
            {
                uint prev_v0 = 0U;
                uint prev_v1 = 0U;

                for (int i = sWords; i <= last; ++i)
                {
                    uint next_v0 = v0[i - sWords];
                    uint next_v1 = v1[i - sWords];
                    uint v0_s = (next_v0 << sBits) | (prev_v0 >> -sBits);
                    uint v1_s = (next_v1 << sBits) | (prev_v1 >> -sBits);
                    prev_v0 = next_v0;
                    prev_v1 = next_v1;

                    cc_u0 += u0[i];
                    cc_u1 += u1[i];
                    cc_u0 += v0_s;
                    cc_u1 += v1_s;
                    u0[i]  = (uint)cc_u0; cc_u0 >>= 32;
                    u1[i]  = (uint)cc_u1; cc_u1 >>= 32;
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int GetBitLength(int last, ReadOnlySpan<uint> x)
#else
        internal static int GetBitLength(int last, uint[] x)
#endif
        {
            int i = last;
            uint sign = (uint)((int)x[i] >> 31);
            while (i > 0 && x[i] == sign)
            {
                --i;
            }
            return i * 32 + 32 - Integers.NumberOfLeadingZeros((int)(x[i] ^ sign));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int GetBitLengthPositive(int last, ReadOnlySpan<uint> x)
#else
        internal static int GetBitLengthPositive(int last, uint[] x)
#endif
        {
            int i = last;
            while (i > 0 && x[i] == 0)
            {
                --i;
            }
            return i * 32 + 32 - Integers.NumberOfLeadingZeros((int)x[i]);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool LessThan(int last, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
#else
        internal static bool LessThan(int last, uint[] x, uint[] y)
#endif
        {
            int i = last;
            if ((int)x[i] < (int)y[i])
                return true;
            if ((int)x[i] > (int)y[i])
                return false;
            while (--i >= 0)
            {
                if (x[i] < y[i])
                    return true;
                if (x[i] > y[i])
                    return false;
            }
            return false;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void SubShifted_NP(int last, int s, Span<uint> Nu, ReadOnlySpan<uint> Nv, Span<uint> _p)
#else
        internal static void SubShifted_NP(int last, int s, uint[] Nu, uint[] Nv, uint[] _p)
#endif
        {
            int sWords = s >> 5, sBits = s & 31;

            long cc__p = 0L;
            long cc_Nu = 0L;

            if (sBits == 0)
            {
                for (int i = sWords; i <= last; ++i)
                {
                    cc_Nu += Nu[i];
                    cc_Nu -= _p[i - sWords];

                    cc__p += _p[i];
                    cc__p -= Nv[i - sWords];
                    _p[i]  = (uint)cc__p; cc__p >>= 32;

                    cc_Nu -= _p[i - sWords];
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
            else
            {
                uint prev_p = 0U;
                uint prev_q = 0U;
                uint prev_v = 0U;

                for (int i = sWords; i <= last; ++i)
                {
                    uint next_p = _p[i - sWords];
                    uint p_s = (next_p << sBits) | (prev_p >> -sBits);
                    prev_p = next_p;

                    cc_Nu += Nu[i];
                    cc_Nu -= p_s;

                    uint next_v = Nv[i - sWords];
                    uint v_s = (next_v << sBits) | (prev_v >> -sBits);
                    prev_v = next_v;

                    cc__p += _p[i];
                    cc__p -= v_s;
                    _p[i]  = (uint)cc__p; cc__p >>= 32;

                    uint next_q = _p[i - sWords];
                    uint q_s = (next_q << sBits) | (prev_q >> -sBits);
                    prev_q = next_q;

                    cc_Nu -= q_s;
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void SubShifted_UV(int last, int s, Span<uint> u0, Span<uint> u1, ReadOnlySpan<uint> v0,
            ReadOnlySpan<uint> v1)
#else
        internal static void SubShifted_UV(int last, int s, uint[] u0, uint[] u1, uint[] v0, uint[] v1)
#endif
        {
            int sWords = s >> 5, sBits = s & 31;

            long cc_u0 = 0L;
            long cc_u1 = 0L;

            if (sBits == 0)
            {
                for (int i = sWords; i <= last; ++i)
                {
                    cc_u0 += u0[i];
                    cc_u1 += u1[i];
                    cc_u0 -= v0[i - sWords];
                    cc_u1 -= v1[i - sWords];
                    u0[i]  = (uint)cc_u0; cc_u0 >>= 32;
                    u1[i]  = (uint)cc_u1; cc_u1 >>= 32;
                }
            }
            else
            {
                uint prev_v0 = 0U;
                uint prev_v1 = 0U;

                for (int i = sWords; i <= last; ++i)
                {
                    uint next_v0 = v0[i - sWords];
                    uint next_v1 = v1[i - sWords];
                    uint v0_s = (next_v0 << sBits) | (prev_v0 >> -sBits);
                    uint v1_s = (next_v1 << sBits) | (prev_v1 >> -sBits);
                    prev_v0 = next_v0;
                    prev_v1 = next_v1;

                    cc_u0 += u0[i];
                    cc_u1 += u1[i];
                    cc_u0 -= v0_s;
                    cc_u1 -= v1_s;
                    u0[i]  = (uint)cc_u0; cc_u0 >>= 32;
                    u1[i]  = (uint)cc_u1; cc_u1 >>= 32;
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Swap(ref Span<uint> x, ref Span<uint> y)
#else
        internal static void Swap(ref uint[] x, ref uint[] y)
#endif
        {
            var t = x; x = y; y = t;
        }
    }
}
