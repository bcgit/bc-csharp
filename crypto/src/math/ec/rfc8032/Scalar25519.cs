using System;
using System.Diagnostics;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    internal static class Scalar25519
    {
        internal const int Size = 8;

        private const long M08L = 0x000000FFL;
        private const long M28L = 0x0FFFFFFFL;
        private const long M32L = 0xFFFFFFFFL;

        private const int TargetLength = 254;

        private static readonly uint[] L = { 0x5CF5D3EDU, 0x5812631AU, 0xA2F79CD6U, 0x14DEF9DEU, 0x00000000U,
            0x00000000U, 0x00000000U, 0x10000000U };
        private static readonly uint[] LSq = { 0xAB128969U, 0xE2EDF685U, 0x2298A31DU, 0x68039276U, 0xD217F5BEU,
            0x3DCEEC73U, 0x1B7C309AU, 0xA1B39941U, 0x4B9EBA7DU, 0xCB024C63U, 0xD45EF39AU, 0x029BDF3BU, 0x00000000U,
            0x00000000U, 0x00000000U, 0x01000000U };

        private const int L0 = -0x030A2C13;     // L0:26/--
        private const int L1 =  0x012631A6;     // L1:24/22
        private const int L2 =  0x079CD658;     // L2:27/--
        private const int L3 = -0x006215D1;     // L3:23/--
        private const int L4 =  0x000014DF;     // L4:12/11

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static bool CheckVar(ReadOnlySpan<byte> s, Span<uint> n)
        {
            Decode(s, n);
            return !Nat.Gte(Size, n, L);
        }
#else
        internal static bool CheckVar(byte[] s, uint[] n)
        {
            Decode(s, n);
            return !Nat256.Gte(n, L);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Decode(ReadOnlySpan<byte> k, Span<uint> n)
        {
            Codec.Decode32(k, n[..Size]);
        }
#else
        internal static void Decode(byte[] k, uint[] n)
        {
            Codec.Decode32(k, 0, n, 0, Size);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void GetOrderWnafVar(int width, Span<sbyte> ws)
#else
        internal static void GetOrderWnafVar(int width, sbyte[] ws)
#endif
        {
            Wnaf.GetSignedVar(L, width, ws);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Multiply128Var(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y128, Span<uint> z)
        {
            Span<uint> tt = stackalloc uint[16];
            Nat.Mul(y128, x, tt);

            if ((y128[3] >> 31) != 0)
            {
                Nat.AddTo(8, L, tt[4..]);
                Nat.SubFrom(8, x, tt[4..]);
            }

            Span<byte> r = MemoryMarshal.AsBytes(tt);
            Reduce(r, r);
            tt[..8].CopyTo(z);
        }
#else
        internal static void Multiply128Var(uint[] x, uint[] y128, uint[] z)
        {
            uint[] tt = new uint[12];
            Nat.Mul(y128, 0, 4, x, 0, 8, tt, 0);

            if ((y128[3] >> 31) != 0)
            {
                Nat256.AddTo(L, 0, tt, 4, 0U);
                Nat256.SubFrom(x, 0, tt, 4);
            }

            byte[] bytes = new byte[64];
            Codec.Encode32(tt, 0, 12, bytes, 0);

            byte[] r = Reduce(bytes);
            Codec.Decode32(r, 0, z, 0, 8);
        }
#endif

        internal static byte[] Reduce(byte[] n)
        {
            byte[] r = new byte[64];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Reduce(n, r);
#else
            long x00 =  Codec.Decode32(n,  0)       & M32L;         // x00:32/--
            long x01 = (Codec.Decode24(n,  4) << 4) & M32L;         // x01:28/--
            long x02 =  Codec.Decode32(n,  7)       & M32L;         // x02:32/--
            long x03 = (Codec.Decode24(n, 11) << 4) & M32L;         // x03:28/--
            long x04 =  Codec.Decode32(n, 14)       & M32L;         // x04:32/--
            long x05 = (Codec.Decode24(n, 18) << 4) & M32L;         // x05:28/--
            long x06 =  Codec.Decode32(n, 21)       & M32L;         // x06:32/--
            long x07 = (Codec.Decode24(n, 25) << 4) & M32L;         // x07:28/--
            long x08 =  Codec.Decode32(n, 28)       & M32L;         // x08:32/--
            long x09 = (Codec.Decode24(n, 32) << 4) & M32L;         // x09:28/--
            long x10 =  Codec.Decode32(n, 35)       & M32L;         // x10:32/--
            long x11 = (Codec.Decode24(n, 39) << 4) & M32L;         // x11:28/--
            long x12 =  Codec.Decode32(n, 42)       & M32L;         // x12:32/--
            long x13 = (Codec.Decode24(n, 46) << 4) & M32L;         // x13:28/--
            long x14 =  Codec.Decode32(n, 49)       & M32L;         // x14:32/--
            long x15 = (Codec.Decode24(n, 53) << 4) & M32L;         // x15:28/--
            long x16 =  Codec.Decode32(n, 56)       & M32L;         // x16:32/--
            long x17 = (Codec.Decode24(n, 60) << 4) & M32L;         // x17:28/--
            long x18 =                 n[63]        & M08L;         // x18:08/--
            long t;

            //x18 += (x17 >> 28); x17 &= M28L;
            x09 -= x18 * L0;                            // x09:34/28
            x10 -= x18 * L1;                            // x10:33/30
            x11 -= x18 * L2;                            // x11:35/28
            x12 -= x18 * L3;                            // x12:32/31
            x13 -= x18 * L4;                            // x13:28/21

            x17 += (x16 >> 28); x16 &= M28L;            // x17:28/--, x16:28/--
            x08 -= x17 * L0;                            // x08:54/32
            x09 -= x17 * L1;                            // x09:52/51
            x10 -= x17 * L2;                            // x10:55/34
            x11 -= x17 * L3;                            // x11:51/36
            x12 -= x17 * L4;                            // x12:41/--

            //x16 += (x15 >> 28); x15 &= M28L;
            x07 -= x16 * L0;                            // x07:54/28
            x08 -= x16 * L1;                            // x08:54/53
            x09 -= x16 * L2;                            // x09:55/53
            x10 -= x16 * L3;                            // x10:55/52
            x11 -= x16 * L4;                            // x11:51/41

            x15 += (x14 >> 28); x14 &= M28L;            // x15:28/--, x14:28/--
            x06 -= x15 * L0;                            // x06:54/32
            x07 -= x15 * L1;                            // x07:54/53
            x08 -= x15 * L2;                            // x08:56/--
            x09 -= x15 * L3;                            // x09:55/54
            x10 -= x15 * L4;                            // x10:55/53

            //x14 += (x13 >> 28); x13 &= M28L;
            x05 -= x14 * L0;                            // x05:54/28
            x06 -= x14 * L1;                            // x06:54/53
            x07 -= x14 * L2;                            // x07:56/--
            x08 -= x14 * L3;                            // x08:56/51
            x09 -= x14 * L4;                            // x09:56/--

            x13 += (x12 >> 28); x12 &= M28L;            // x13:28/22, x12:28/--
            x04 -= x13 * L0;                            // x04:54/49
            x05 -= x13 * L1;                            // x05:54/53
            x06 -= x13 * L2;                            // x06:56/--
            x07 -= x13 * L3;                            // x07:56/52
            x08 -= x13 * L4;                            // x08:56/52

            x12 += (x11 >> 28); x11 &= M28L;            // x12:28/24, x11:28/--
            x03 -= x12 * L0;                            // x03:54/49
            x04 -= x12 * L1;                            // x04:54/51
            x05 -= x12 * L2;                            // x05:56/--
            x06 -= x12 * L3;                            // x06:56/52
            x07 -= x12 * L4;                            // x07:56/53

            x11 += (x10 >> 28); x10 &= M28L;            // x11:29/--, x10:28/--
            x02 -= x11 * L0;                            // x02:55/32
            x03 -= x11 * L1;                            // x03:55/--
            x04 -= x11 * L2;                            // x04:56/55
            x05 -= x11 * L3;                            // x05:56/52
            x06 -= x11 * L4;                            // x06:56/53

            x10 += (x09 >> 28); x09 &= M28L;            // x10:29/--, x09:28/--
            x01 -= x10 * L0;                            // x01:55/28
            x02 -= x10 * L1;                            // x02:55/54
            x03 -= x10 * L2;                            // x03:56/55
            x04 -= x10 * L3;                            // x04:57/--
            x05 -= x10 * L4;                            // x05:56/53

            x08 += (x07 >> 28); x07 &= M28L;            // x08:56/53, x07:28/--
            x09 += (x08 >> 28); x08 &= M28L;            // x09:29/25, x08:28/--

            t    = (x08 >> 27) & 1L;
            x09 += t;                                   // x09:29/26

            x00 -= x09 * L0;                            // x00:55/53
            x01 -= x09 * L1;                            // x01:55/54
            x02 -= x09 * L2;                            // x02:57/--
            x03 -= x09 * L3;                            // x03:57/--
            x04 -= x09 * L4;                            // x04:57/42

            x01 += (x00 >> 28); x00 &= M28L;
            x02 += (x01 >> 28); x01 &= M28L;
            x03 += (x02 >> 28); x02 &= M28L;
            x04 += (x03 >> 28); x03 &= M28L;
            x05 += (x04 >> 28); x04 &= M28L;
            x06 += (x05 >> 28); x05 &= M28L;
            x07 += (x06 >> 28); x06 &= M28L;
            x08 += (x07 >> 28); x07 &= M28L;
            x09  = (x08 >> 28); x08 &= M28L;

            x09 -= t;

            Debug.Assert(x09 == 0L || x09 == -1L);

            x00 += x09 & L0;
            x01 += x09 & L1;
            x02 += x09 & L2;
            x03 += x09 & L3;
            x04 += x09 & L4;

            x01 += (x00 >> 28); x00 &= M28L;
            x02 += (x01 >> 28); x01 &= M28L;
            x03 += (x02 >> 28); x02 &= M28L;
            x04 += (x03 >> 28); x03 &= M28L;
            x05 += (x04 >> 28); x04 &= M28L;
            x06 += (x05 >> 28); x05 &= M28L;
            x07 += (x06 >> 28); x06 &= M28L;
            x08 += (x07 >> 28); x07 &= M28L;

            Codec.Encode56((ulong)(x00 | (x01 << 28)), r, 0);
            Codec.Encode56((ulong)(x02 | (x03 << 28)), r, 7);
            Codec.Encode56((ulong)(x04 | (x05 << 28)), r, 14);
            Codec.Encode56((ulong)(x06 | (x07 << 28)), r, 21);
            Codec.Encode32((uint)x08, r, 28);
#endif

            return r;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Reduce(ReadOnlySpan<byte> n, Span<byte> r)
        {
            long x00 =  Codec.Decode32(n[ 0..])       & M32L;       // x00:32/--
            long x01 = (Codec.Decode24(n[ 4..]) << 4) & M32L;       // x01:28/--
            long x02 =  Codec.Decode32(n[ 7..])       & M32L;       // x02:32/--
            long x03 = (Codec.Decode24(n[11..]) << 4) & M32L;       // x03:28/--
            long x04 =  Codec.Decode32(n[14..])       & M32L;       // x04:32/--
            long x05 = (Codec.Decode24(n[18..]) << 4) & M32L;       // x05:28/--
            long x06 =  Codec.Decode32(n[21..])       & M32L;       // x06:32/--
            long x07 = (Codec.Decode24(n[25..]) << 4) & M32L;       // x07:28/--
            long x08 =  Codec.Decode32(n[28..])       & M32L;       // x08:32/--
            long x09 = (Codec.Decode24(n[32..]) << 4) & M32L;       // x09:28/--
            long x10 =  Codec.Decode32(n[35..])       & M32L;       // x10:32/--
            long x11 = (Codec.Decode24(n[39..]) << 4) & M32L;       // x11:28/--
            long x12 =  Codec.Decode32(n[42..])       & M32L;       // x12:32/--
            long x13 = (Codec.Decode24(n[46..]) << 4) & M32L;       // x13:28/--
            long x14 =  Codec.Decode32(n[49..])       & M32L;       // x14:32/--
            long x15 = (Codec.Decode24(n[53..]) << 4) & M32L;       // x15:28/--
            long x16 =  Codec.Decode32(n[56..])       & M32L;       // x16:32/--
            long x17 = (Codec.Decode24(n[60..]) << 4) & M32L;       // x17:28/--
            long x18 =                 n[63]          & M08L;       // x18:08/--
            long t;

            //x18 += (x17 >> 28); x17 &= M28L;
            x09 -= x18 * L0;                            // x09:34/28
            x10 -= x18 * L1;                            // x10:33/30
            x11 -= x18 * L2;                            // x11:35/28
            x12 -= x18 * L3;                            // x12:32/31
            x13 -= x18 * L4;                            // x13:28/21

            x17 += (x16 >> 28); x16 &= M28L;            // x17:28/--, x16:28/--
            x08 -= x17 * L0;                            // x08:54/32
            x09 -= x17 * L1;                            // x09:52/51
            x10 -= x17 * L2;                            // x10:55/34
            x11 -= x17 * L3;                            // x11:51/36
            x12 -= x17 * L4;                            // x12:41/--

            //x16 += (x15 >> 28); x15 &= M28L;
            x07 -= x16 * L0;                            // x07:54/28
            x08 -= x16 * L1;                            // x08:54/53
            x09 -= x16 * L2;                            // x09:55/53
            x10 -= x16 * L3;                            // x10:55/52
            x11 -= x16 * L4;                            // x11:51/41

            x15 += (x14 >> 28); x14 &= M28L;            // x15:28/--, x14:28/--
            x06 -= x15 * L0;                            // x06:54/32
            x07 -= x15 * L1;                            // x07:54/53
            x08 -= x15 * L2;                            // x08:56/--
            x09 -= x15 * L3;                            // x09:55/54
            x10 -= x15 * L4;                            // x10:55/53

            //x14 += (x13 >> 28); x13 &= M28L;
            x05 -= x14 * L0;                            // x05:54/28
            x06 -= x14 * L1;                            // x06:54/53
            x07 -= x14 * L2;                            // x07:56/--
            x08 -= x14 * L3;                            // x08:56/51
            x09 -= x14 * L4;                            // x09:56/--

            x13 += (x12 >> 28); x12 &= M28L;            // x13:28/22, x12:28/--
            x04 -= x13 * L0;                            // x04:54/49
            x05 -= x13 * L1;                            // x05:54/53
            x06 -= x13 * L2;                            // x06:56/--
            x07 -= x13 * L3;                            // x07:56/52
            x08 -= x13 * L4;                            // x08:56/52

            x12 += (x11 >> 28); x11 &= M28L;            // x12:28/24, x11:28/--
            x03 -= x12 * L0;                            // x03:54/49
            x04 -= x12 * L1;                            // x04:54/51
            x05 -= x12 * L2;                            // x05:56/--
            x06 -= x12 * L3;                            // x06:56/52
            x07 -= x12 * L4;                            // x07:56/53

            x11 += (x10 >> 28); x10 &= M28L;            // x11:29/--, x10:28/--
            x02 -= x11 * L0;                            // x02:55/32
            x03 -= x11 * L1;                            // x03:55/--
            x04 -= x11 * L2;                            // x04:56/55
            x05 -= x11 * L3;                            // x05:56/52
            x06 -= x11 * L4;                            // x06:56/53

            x10 += (x09 >> 28); x09 &= M28L;            // x10:29/--, x09:28/--
            x01 -= x10 * L0;                            // x01:55/28
            x02 -= x10 * L1;                            // x02:55/54
            x03 -= x10 * L2;                            // x03:56/55
            x04 -= x10 * L3;                            // x04:57/--
            x05 -= x10 * L4;                            // x05:56/53

            x08 += (x07 >> 28); x07 &= M28L;            // x08:56/53, x07:28/--
            x09 += (x08 >> 28); x08 &= M28L;            // x09:29/25, x08:28/--

            t    = (x08 >> 27) & 1L;
            x09 += t;                                   // x09:29/26

            x00 -= x09 * L0;                            // x00:55/53
            x01 -= x09 * L1;                            // x01:55/54
            x02 -= x09 * L2;                            // x02:57/--
            x03 -= x09 * L3;                            // x03:57/--
            x04 -= x09 * L4;                            // x04:57/42

            x01 += (x00 >> 28); x00 &= M28L;
            x02 += (x01 >> 28); x01 &= M28L;
            x03 += (x02 >> 28); x02 &= M28L;
            x04 += (x03 >> 28); x03 &= M28L;
            x05 += (x04 >> 28); x04 &= M28L;
            x06 += (x05 >> 28); x05 &= M28L;
            x07 += (x06 >> 28); x06 &= M28L;
            x08 += (x07 >> 28); x07 &= M28L;
            x09  = (x08 >> 28); x08 &= M28L;

            x09 -= t;

            Debug.Assert(x09 == 0L || x09 == -1L);

            x00 += x09 & L0;
            x01 += x09 & L1;
            x02 += x09 & L2;
            x03 += x09 & L3;
            x04 += x09 & L4;

            x01 += (x00 >> 28); x00 &= M28L;
            x02 += (x01 >> 28); x01 &= M28L;
            x03 += (x02 >> 28); x02 &= M28L;
            x04 += (x03 >> 28); x03 &= M28L;
            x05 += (x04 >> 28); x04 &= M28L;
            x06 += (x05 >> 28); x05 &= M28L;
            x07 += (x06 >> 28); x06 &= M28L;
            x08 += (x07 >> 28); x07 &= M28L;

            Codec.Encode56((ulong)(x00 | (x01 << 28)), r);
            Codec.Encode56((ulong)(x02 | (x03 << 28)), r[7..]);
            Codec.Encode56((ulong)(x04 | (x05 << 28)), r[14..]);
            Codec.Encode56((ulong)(x06 | (x07 << 28)), r[21..]);
            Codec.Encode32((uint)x08, r[28..]);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void ReduceBasisVar(ReadOnlySpan<uint> k, Span<uint> z0, Span<uint> z1)
        {
            /*
             * Split scalar k into two half-size scalars z0 and z1, such that z1 * k == z0 mod L.
             * 
             * See https://ia.cr/2020/454 (Pornin).
             */

            Span<uint> Nu = stackalloc uint[16];    LSq.CopyTo(Nu);
            Span<uint> Nv = stackalloc uint[16];    Nat.Square(8, k, Nv); Nat.AddWordTo(16, 1U, Nv);
            Span<uint> p  = stackalloc uint[16];    Nat.Mul(8, L, k, p);
            Span<uint> u0 = stackalloc uint[4];     u0.CopyFrom(L);
            Span<uint> u1 = stackalloc uint[4];
            Span<uint> v0 = stackalloc uint[4];     v0.CopyFrom(k);
            Span<uint> v1 = stackalloc uint[4];     v1[0] = 1U;

            int last = 15;
            int len_Nv = GetBitLengthPositive(last, Nv);

            while (len_Nv > TargetLength)
            {
                int len_p = GetBitLength(last, p);
                int s = len_p - len_Nv;
                s &= ~(s >> 31);

                if ((int)p[last] < 0)
                {
                    AddShifted_NP(last, s, Nu, Nv, p);
                    AddShifted_UV(3, s, u0, u1, v0, v1);
                }
                else
                {
                    SubShifted_NP(last, s, Nu, Nv, p);
                    SubShifted_UV(3, s, u0, u1, v0, v1);
                }

                if (LessThan(last, Nu, Nv))
                {
                    Swap(ref u0, ref v0);
                    Swap(ref u1, ref v1);
                    Swap(ref Nu, ref Nv);

                    last = len_Nv >> 5;
                    len_Nv = GetBitLengthPositive(last, Nv);
                }
            }

            // v1 * k == v0 mod L
            v0.CopyTo(z0);
            v1.CopyTo(z1);
        }
#else
        internal static void ReduceBasisVar(uint[] k, uint[] z0, uint[] z1)
        {
            /*
             * Split scalar k into two half-size scalars z0 and z1, such that z1 * k == z0 mod L.
             * 
             * See https://ia.cr/2020/454 (Pornin).
             */

            uint[] Nu = new uint[16];       Array.Copy(LSq, Nu, 16);
            uint[] Nv = new uint[16];       Nat.Square(8, k, Nv); Nat.AddWordTo(16, 1U, Nv);
            uint[] p  = new uint[16];       Nat.Mul(8, L, k, p);
            uint[] u0 = new uint[4];        Array.Copy(L, u0, 4);
            uint[] u1 = new uint[4];
            uint[] v0 = new uint[4];        Array.Copy(k, v0, 4);
            uint[] v1 = new uint[4];        v1[0] = 1U;

            int last = 15;
            int len_Nv = GetBitLengthPositive(last, Nv);

            while (len_Nv > TargetLength)
            {
                int len_p = GetBitLength(last, p);
                int s = len_p - len_Nv;
                s &= ~(s >> 31);

                if ((int)p[last] < 0)
                {
                    AddShifted_NP(last, s, Nu, Nv, p);
                    AddShifted_UV(3, s, u0, u1, v0, v1);
                }
                else
                {
                    SubShifted_NP(last, s, Nu, Nv, p);
                    SubShifted_UV(3, s, u0, u1, v0, v1);
                }

                if (LessThan(last, Nu, Nv))
                {
                    Swap(ref u0, ref v0);
                    Swap(ref u1, ref v1);
                    Swap(ref Nu, ref Nv);

                    last = len_Nv >> 5;
                    len_Nv = GetBitLengthPositive(last, Nv);
                }
            }

            // v1 * k == v0 mod L
            Array.Copy(v0, z0, 4);
            Array.Copy(v1, z1, 4);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void ToSignedDigits(ReadOnlySpan<uint> x, Span<uint> z)
#else
        internal static void ToSignedDigits(uint[] x, uint[] z)
#endif
        {
            uint c1 = Nat.CAdd(Size, ~(int)x[0] & 1, x, L, z);  Debug.Assert(c1 == 0U);
            uint c2 = Nat.ShiftDownBit(Size, z, 1U);            Debug.Assert(c2 == (1U << 31));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddShifted_NP(int last, int s, Span<uint> Nu, ReadOnlySpan<uint> Nv, Span<uint> _p)
#else
        private static void AddShifted_NP(int last, int s, uint[] Nu, uint[] Nv, uint[] _p)
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
        private static void AddShifted_UV(int last, int s, Span<uint> u0, Span<uint> u1, ReadOnlySpan<uint> v0,
            ReadOnlySpan<uint> v1)
#else
        private static void AddShifted_UV(int last, int s, uint[] u0, uint[] u1, uint[] v0, uint[] v1)
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
        private static int GetBitLength(int last, ReadOnlySpan<uint> x)
#else
        private static int GetBitLength(int last, uint[] x)
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
        private static int GetBitLengthPositive(int last, ReadOnlySpan<uint> x)
#else
        private static int GetBitLengthPositive(int last, uint[] x)
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
        private static bool LessThan(int last, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
#else
        private static bool LessThan(int last, uint[] x, uint[] y)
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
        private static void SubShifted_NP(int last, int s, Span<uint> Nu, ReadOnlySpan<uint> Nv, Span<uint> _p)
#else
        private static void SubShifted_NP(int last, int s, uint[] Nu, uint[] Nv, uint[] _p)
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
        private static void SubShifted_UV(int last, int s, Span<uint> u0, Span<uint> u1, ReadOnlySpan<uint> v0,
            ReadOnlySpan<uint> v1)
#else
        private static void SubShifted_UV(int last, int s, uint[] u0, uint[] u1, uint[] v0, uint[] v1)
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
        private static void Swap(ref Span<uint> x, ref Span<uint> y)
#else
        private static void Swap(ref uint[] x, ref uint[] y)
#endif
        {
            var t = x; x = y; y = t;
        }
    }
}
