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
        internal static void AddShifted_NP(int last, int s, Span<uint> Nu, ReadOnlySpan<uint> Nv, Span<uint> p, Span<uint> t)
#else
        internal static void AddShifted_NP(int last, int s, uint[] Nu, uint[] Nv, uint[] p, uint[] t)
#endif
        {
            ulong cc_p = 0UL;
            ulong cc_Nu = 0UL;

            if (s == 0)
            {
                for (int i = 0; i <= last; ++i)
                {
                    uint p_i = p[i];

                    cc_Nu += Nu[i];
                    cc_Nu += p_i;

                    cc_p += p_i;
                    cc_p += Nv[i];
                    p_i   = (uint)cc_p; cc_p >>= 32;
                    p[i]  = p_i;

                    cc_Nu += p_i;
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
            else if (s < 32)
            {
                uint prev_p = 0U;
                uint prev_q = 0U;
                uint prev_v = 0U;

                for (int i = 0; i <= last; ++i)
                {
                    uint p_i = p[i];
                    uint p_s = (p_i << s) | (prev_p >> -s);
                    prev_p = p_i;

                    cc_Nu += Nu[i];
                    cc_Nu += p_s;

                    uint next_v = Nv[i];
                    uint v_s = (next_v << s) | (prev_v >> -s);
                    prev_v = next_v;

                    cc_p += p_i;
                    cc_p += v_s;
                    p_i   = (uint)cc_p; cc_p >>= 32;
                    p[i]  = p_i;

                    uint q_s = (p_i << s) | (prev_q >> -s);
                    prev_q = p_i;

                    cc_Nu += q_s;
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
            else
            {
                // Copy the low limbs of the original p
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                t[..last].CopyFrom(p);
#else
                Array.Copy(p, 0, t, 0, last);
#endif

                int sWords = s >> 5, sBits = s & 31;
                if (sBits == 0)
                {
                    for (int i = sWords; i <= last; ++i)
                    {
                        cc_Nu += Nu[i];
                        cc_Nu += t[i - sWords];

                        cc_p += p[i];
                        cc_p += Nv[i - sWords];
                        p[i]  = (uint)cc_p; cc_p >>= 32;

                        cc_Nu += p[i - sWords];
                        Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                    }
                }
                else
                {
                    uint prev_t = 0U;
                    uint prev_q = 0U;
                    uint prev_v = 0U;

                    for (int i = sWords; i <= last; ++i)
                    {
                        uint next_t = t[i - sWords];
                        uint t_s = (next_t << sBits) | (prev_t >> -sBits);
                        prev_t = next_t;

                        cc_Nu += Nu[i];
                        cc_Nu += t_s;

                        uint next_v = Nv[i - sWords];
                        uint v_s = (next_v << sBits) | (prev_v >> -sBits);
                        prev_v = next_v;

                        cc_p += p[i];
                        cc_p += v_s;
                        p[i]  = (uint)cc_p; cc_p >>= 32;

                        uint next_q = p[i - sWords];
                        uint q_s = (next_q << sBits) | (prev_q >> -sBits);
                        prev_q = next_q;

                        cc_Nu += q_s;
                        Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                    }
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
            do
            {
                if (x[i] < y[i])
                    return true;
                if (x[i] > y[i])
                    return false;
            }
            while (--i >= 0);
            return false;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void SubShifted_NP(int last, int s, Span<uint> Nu, ReadOnlySpan<uint> Nv, Span<uint> p, Span<uint> t)
#else
        internal static void SubShifted_NP(int last, int s, uint[] Nu, uint[] Nv, uint[] p, uint[] t)
#endif
        {
            long cc_p = 0L;
            long cc_Nu = 0L;

            if (s == 0)
            {
                for (int i = 0; i <= last; ++i)
                {
                    uint p_i = p[i];

                    cc_Nu += Nu[i];
                    cc_Nu -= p_i;

                    cc_p += p_i;
                    cc_p -= Nv[i];
                    p_i   = (uint)cc_p; cc_p >>= 32;
                    p[i]  = p_i;

                    cc_Nu -= p_i;
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
            else if (s < 32)
            {
                uint prev_p = 0U;
                uint prev_q = 0U;
                uint prev_v = 0U;

                for (int i = 0; i <= last; ++i)
                {
                    uint p_i = p[i];
                    uint p_s = (p_i << s) | (prev_p >> -s);
                    prev_p = p_i;

                    cc_Nu += Nu[i];
                    cc_Nu -= p_s;

                    uint next_v = Nv[i];
                    uint v_s = (next_v << s) | (prev_v >> -s);
                    prev_v = next_v;

                    cc_p += p_i;
                    cc_p -= v_s;
                    p_i   = (uint)cc_p; cc_p >>= 32;
                    p[i]  = p_i;

                    uint q_s = (p_i << s) | (prev_q >> -s);
                    prev_q = p_i;

                    cc_Nu -= q_s;
                    Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                }
            }
            else
            {
                // Copy the low limbs of the original p
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                t[..last].CopyFrom(p);
#else
                Array.Copy(p, 0, t, 0, last);
#endif

                int sWords = s >> 5, sBits = s & 31;
                if (sBits == 0)
                {
                    for (int i = sWords; i <= last; ++i)
                    {
                        cc_Nu += Nu[i];
                        cc_Nu -= t[i - sWords];

                        cc_p += p[i];
                        cc_p -= Nv[i - sWords];
                        p[i]  = (uint)cc_p; cc_p >>= 32;

                        cc_Nu -= p[i - sWords];
                        Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                    }
                }
                else
                {
                    uint prev_t = 0U;
                    uint prev_q = 0U;
                    uint prev_v = 0U;

                    for (int i = sWords; i <= last; ++i)
                    {
                        uint next_t = t[i - sWords];
                        uint t_s = (next_t << sBits) | (prev_t >> -sBits);
                        prev_t = next_t;

                        cc_Nu += Nu[i];
                        cc_Nu -= t_s;

                        uint next_v = Nv[i - sWords];
                        uint v_s = (next_v << sBits) | (prev_v >> -sBits);
                        prev_v = next_v;

                        cc_p += p[i];
                        cc_p -= v_s;
                        p[i]  = (uint)cc_p; cc_p >>= 32;

                        uint next_q = p[i - sWords];
                        uint q_s = (next_q << sBits) | (prev_q >> -sBits);
                        prev_q = next_q;

                        cc_Nu -= q_s;
                        Nu[i]  = (uint)cc_Nu; cc_Nu >>= 32;
                    }
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
