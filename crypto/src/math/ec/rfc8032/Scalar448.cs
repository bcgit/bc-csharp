using System;
using System.Diagnostics;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#endif

using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    internal static class Scalar448
    {
        internal const int Size = 14;

        private const int ScalarBytes = Size * 4 + 1;

        private const ulong M26UL = 0x03FFFFFFUL;
        private const ulong M28UL = 0x0FFFFFFFUL;

        private const int TargetLength = 447;

        private static readonly uint[] L = { 0xAB5844F3U, 0x2378C292U, 0x8DC58F55U, 0x216CC272U, 0xAED63690U,
            0xC44EDB49U, 0x7CCA23E9U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
            0x3FFFFFFFU };
        private static readonly uint[] LSq = { 0x1BA1FEA9U, 0xC1ADFBB8U, 0x49E0A8B2U, 0xB91BF537U, 0xE764D815U,
            0x4525492BU, 0xA2B8716DU, 0x4AE17CF6U, 0xBA3C47C4U, 0xF1A9CC14U, 0x7E4D070AU, 0x92052BCBU, 0x9F823B72U,
            0xC3402A93U, 0x55AC2279U, 0x91BC6149U, 0x46E2C7AAU, 0x10B66139U, 0xD76B1B48U, 0xE2276DA4U, 0xBE6511F4U,
            0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x0FFFFFFFU };

        private const int L_0 = 0x04A7BB0D;     // L_0:26/24
        private const int L_1 = 0x0873D6D5;     // L_1:27/23
        private const int L_2 = 0x0A70AADC;     // L_2:27/26
        private const int L_3 = 0x03D8D723;     // L_3:26/--
        private const int L_4 = 0x096FDE93;     // L_4:27/25
        private const int L_5 = 0x0B65129C;     // L_5:27/26
        private const int L_6 = 0x063BB124;     // L_6:27/--
        private const int L_7 = 0x08335DC1;     // L_7:27/22

        private const int L4_0 = 0x029EEC34;    // L4_0:25/24
        private const int L4_1 = 0x01CF5B55;    // L4_1:25/--
        private const int L4_2 = 0x09C2AB72;    // L4_2:27/25
        private const int L4_3 = 0x0F635C8E;    // L4_3:28/--
        private const int L4_4 = 0x05BF7A4C;    // L4_4:26/25
        private const int L4_5 = 0x0D944A72;    // L4_5:28/--
        private const int L4_6 = 0x08EEC492;    // L4_6:27/24
        private const int L4_7 = 0x20CD7705;    // L4_7:29/24

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static bool CheckVar(ReadOnlySpan<byte> s, Span<uint> n)
        {
            if (s[ScalarBytes - 1] != 0x00)
                return false;

            Decode(s, n);
            return !Nat.Gte(Size, n, L);
        }
#else
        internal static bool CheckVar(byte[] s, uint[] n)
        {
            if (s[ScalarBytes - 1] != 0x00)
                return false;

            Decode(s, n);
            return !Nat.Gte(Size, n, L);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Decode(ReadOnlySpan<byte> k, Span<uint> n)
        {
            Debug.Assert(k[ScalarBytes - 1] == 0x00);

            Codec.Decode32(k, n[..Size]);
        }
#else
        internal static void Decode(byte[] k, uint[] n)
        {
            Debug.Assert(k[ScalarBytes - 1] == 0x00);

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
        internal static void Multiply225Var(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y225, Span<uint> z)
        {
            Debug.Assert((int)y225[7] >> 31 == (int)y225[7]);

            Span<uint> tt = stackalloc uint[22];
            Nat.Mul(y225, x, tt);

            if ((int)y225[7] < 0)
            {
                Nat.AddTo(Size, L, tt[8..]);
                Nat.SubFrom(Size, x, tt[8..]);
            }

            if (BitConverter.IsLittleEndian)
            {
                Span<byte> r = MemoryMarshal.AsBytes(tt);
                Reduce704(r, r);
                tt[..Size].CopyTo(z);
            }
            else
            {
                Span<byte> r = stackalloc byte[88];
                Codec.Encode32(tt, r);

                Reduce704(r, r);
                Decode(r, z);
            }
        }
#else
        internal static void Multiply225Var(uint[] x, uint[] y225, uint[] z)
        {
            Debug.Assert((int)y225[7] >> 31 == (int)y225[7]);

            uint[] tt = new uint[22];
            Nat.Mul(y225, 0, 8, x, 0, Size, tt, 0);

            if ((int)y225[7] < 0)
            {
                Nat.AddTo(Size, L, 0, tt, 8);
                Nat.SubFrom(Size, x, 0, tt, 8);
            }

            byte[] bytes = new byte[88];
            Codec.Encode32(tt, 0, 22, bytes, 0);

            byte[] r = Reduce704(bytes);
            Decode(r, z);
        }
#endif

        internal static byte[] Reduce704(byte[] n)
        {
            byte[] r = new byte[ScalarBytes];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Reduce704(n, r);
#else
            ulong x00 =  Codec.Decode32(n,   0);                // x00:32/--
            ulong x01 = (Codec.Decode24(n,   4) << 4);          // x01:28/--
            ulong x02 =  Codec.Decode32(n,   7);                // x02:32/--
            ulong x03 = (Codec.Decode24(n,  11) << 4);          // x03:28/--
            ulong x04 =  Codec.Decode32(n,  14);                // x04:32/--
            ulong x05 = (Codec.Decode24(n,  18) << 4);          // x05:28/--
            ulong x06 =  Codec.Decode32(n,  21);                // x06:32/--
            ulong x07 = (Codec.Decode24(n,  25) << 4);          // x07:28/--
            ulong x08 =  Codec.Decode32(n,  28);                // x08:32/--
            ulong x09 = (Codec.Decode24(n,  32) << 4);          // x09:28/--
            ulong x10 =  Codec.Decode32(n,  35);                // x10:32/--
            ulong x11 = (Codec.Decode24(n,  39) << 4);          // x11:28/--
            ulong x12 =  Codec.Decode32(n,  42);                // x12:32/--
            ulong x13 = (Codec.Decode24(n,  46) << 4);          // x13:28/--
            ulong x14 =  Codec.Decode32(n,  49);                // x14:32/--
            ulong x15 = (Codec.Decode24(n,  53) << 4);          // x15:28/--
            ulong x16 =  Codec.Decode32(n,  56);                // x16:32/--
            ulong x17 = (Codec.Decode24(n,  60) << 4);          // x17:28/--
            ulong x18 =  Codec.Decode32(n,  63);                // x18:32/--
            ulong x19 = (Codec.Decode24(n,  67) << 4);          // x19:28/--
            ulong x20 =  Codec.Decode32(n,  70);                // x20:32/--
            ulong x21 = (Codec.Decode24(n,  74) << 4);          // x21:28/--
            ulong x22 =  Codec.Decode32(n,  77);                // x22:32/--
            ulong x23 = (Codec.Decode24(n,  81) << 4);          // x23:28/--
            ulong x24 =  Codec.Decode32(n,  84);                // x24:32/--
            ulong x25 = 0UL;

            // TODO Fix bounds calculations which were copied from Reduce912

            x25 += (x24 >> 28); x24 &= M28UL;           // x25:28/--, x24:28/--
            x09 += x25 * L4_0;                          // x09:54/--
            x10 += x25 * L4_1;                          // x10:54/53
            x11 += x25 * L4_2;                          // x11:56/--
            x12 += x25 * L4_3;                          // x12:57/--
            x13 += x25 * L4_4;                          // x13:57/55
            x14 += x25 * L4_5;                          // x14:58/--
            x15 += x25 * L4_6;                          // x15:58/56
            x16 += x25 * L4_7;                          // x16:59/--

            x21 += (x20 >> 28); x20 &= M28UL;           // x21:58/--, x20:28/--
            x22 += (x21 >> 28); x21 &= M28UL;           // x22:57/54, x21:28/--
            x23 += (x22 >> 28); x22 &= M28UL;           // x23:45/42, x22:28/--
            x24 += (x23 >> 28); x23 &= M28UL;           // x24:28/18, x23:28/--

            x08 += x24 * L4_0;                          // x08:54/--
            x09 += x24 * L4_1;                          // x09:55/--
            x10 += x24 * L4_2;                          // x10:56/46
            x11 += x24 * L4_3;                          // x11:57/46
            x12 += x24 * L4_4;                          // x12:57/55
            x13 += x24 * L4_5;                          // x13:58/--
            x14 += x24 * L4_6;                          // x14:58/56
            x15 += x24 * L4_7;                          // x15:59/--

            x07 += x23 * L4_0;                          // x07:54/--
            x08 += x23 * L4_1;                          // x08:54/53
            x09 += x23 * L4_2;                          // x09:56/53
            x10 += x23 * L4_3;                          // x10:57/46
            x11 += x23 * L4_4;                          // x11:57/55
            x12 += x23 * L4_5;                          // x12:58/--
            x13 += x23 * L4_6;                          // x13:58/56
            x14 += x23 * L4_7;                          // x14:59/--

            x06 += x22 * L4_0;                          // x06:54/--
            x07 += x22 * L4_1;                          // x07:54/53
            x08 += x22 * L4_2;                          // x08:56/--
            x09 += x22 * L4_3;                          // x09:57/53
            x10 += x22 * L4_4;                          // x10:57/55
            x11 += x22 * L4_5;                          // x11:58/--
            x12 += x22 * L4_6;                          // x12:58/56
            x13 += x22 * L4_7;                          // x13:59/--

            x18 += (x17 >> 28); x17 &= M28UL;           // x18:59/31, x17:28/--
            x19 += (x18 >> 28); x18 &= M28UL;           // x19:58/54, x18:28/--
            x20 += (x19 >> 28); x19 &= M28UL;           // x20:30/29, x19:28/--
            x21 += (x20 >> 28); x20 &= M28UL;           // x21:28/03, x20:28/--

            x05 += x21 * L4_0;                          // x05:54/--
            x06 += x21 * L4_1;                          // x06:55/--
            x07 += x21 * L4_2;                          // x07:56/31
            x08 += x21 * L4_3;                          // x08:57/31
            x09 += x21 * L4_4;                          // x09:57/56
            x10 += x21 * L4_5;                          // x10:58/--
            x11 += x21 * L4_6;                          // x11:58/56
            x12 += x21 * L4_7;                          // x12:59/--

            x04 += x20 * L4_0;                          // x04:54/--
            x05 += x20 * L4_1;                          // x05:54/53
            x06 += x20 * L4_2;                          // x06:56/53
            x07 += x20 * L4_3;                          // x07:57/31
            x08 += x20 * L4_4;                          // x08:57/55
            x09 += x20 * L4_5;                          // x09:58/--
            x10 += x20 * L4_6;                          // x10:58/56
            x11 += x20 * L4_7;                          // x11:59/--

            x03 += x19 * L4_0;                          // x03:54/--
            x04 += x19 * L4_1;                          // x04:54/53
            x05 += x19 * L4_2;                          // x05:56/--
            x06 += x19 * L4_3;                          // x06:57/53
            x07 += x19 * L4_4;                          // x07:57/55
            x08 += x19 * L4_5;                          // x08:58/--
            x09 += x19 * L4_6;                          // x09:58/56
            x10 += x19 * L4_7;                          // x10:59/--

            x15 += (x14 >> 28); x14 &= M28UL;           // x15:59/31, x14:28/--
            x16 += (x15 >> 28); x15 &= M28UL;           // x16:59/32, x15:28/--
            x17 += (x16 >> 28); x16 &= M28UL;           // x17:31/29, x16:28/--
            x18 += (x17 >> 28); x17 &= M28UL;           // x18:28/04, x17:28/--

            x02 += x18 * L4_0;                          // x02:54/--
            x03 += x18 * L4_1;                          // x03:55/--
            x04 += x18 * L4_2;                          // x04:56/32
            x05 += x18 * L4_3;                          // x05:57/32
            x06 += x18 * L4_4;                          // x06:57/56
            x07 += x18 * L4_5;                          // x07:58/--
            x08 += x18 * L4_6;                          // x08:58/56
            x09 += x18 * L4_7;                          // x09:59/--

            x01 += x17 * L4_0;                          // x01:54/--
            x02 += x17 * L4_1;                          // x02:54/53
            x03 += x17 * L4_2;                          // x03:56/53
            x04 += x17 * L4_3;                          // x04:57/32
            x05 += x17 * L4_4;                          // x05:57/55
            x06 += x17 * L4_5;                          // x06:58/--
            x07 += x17 * L4_6;                          // x07:58/56
            x08 += x17 * L4_7;                          // x08:59/--

            x16 *= 4;
            x16 += (x15 >> 26); x15 &= M26UL;
            x16 += 1;                                   // x16:30/01

            x00 += x16 * L_0;
            x01 += x16 * L_1;
            x02 += x16 * L_2;
            x03 += x16 * L_3;
            x04 += x16 * L_4;
            x05 += x16 * L_5;
            x06 += x16 * L_6;
            x07 += x16 * L_7;

            x01 += (x00 >> 28); x00 &= M28UL;
            x02 += (x01 >> 28); x01 &= M28UL;
            x03 += (x02 >> 28); x02 &= M28UL;
            x04 += (x03 >> 28); x03 &= M28UL;
            x05 += (x04 >> 28); x04 &= M28UL;
            x06 += (x05 >> 28); x05 &= M28UL;
            x07 += (x06 >> 28); x06 &= M28UL;
            x08 += (x07 >> 28); x07 &= M28UL;
            x09 += (x08 >> 28); x08 &= M28UL;
            x10 += (x09 >> 28); x09 &= M28UL;
            x11 += (x10 >> 28); x10 &= M28UL;
            x12 += (x11 >> 28); x11 &= M28UL;
            x13 += (x12 >> 28); x12 &= M28UL;
            x14 += (x13 >> 28); x13 &= M28UL;
            x15 += (x14 >> 28); x14 &= M28UL;
            x16  = (x15 >> 26); x15 &= M26UL;

            x16 -= 1;

            Debug.Assert(x16 == 0UL || x16 == ulong.MaxValue);

            x00 -= x16 & L_0;
            x01 -= x16 & L_1;
            x02 -= x16 & L_2;
            x03 -= x16 & L_3;
            x04 -= x16 & L_4;
            x05 -= x16 & L_5;
            x06 -= x16 & L_6;
            x07 -= x16 & L_7;

            x01 += (ulong)((long)x00 >> 28); x00 &= M28UL;
            x02 += (ulong)((long)x01 >> 28); x01 &= M28UL;
            x03 += (ulong)((long)x02 >> 28); x02 &= M28UL;
            x04 += (ulong)((long)x03 >> 28); x03 &= M28UL;
            x05 += (ulong)((long)x04 >> 28); x04 &= M28UL;
            x06 += (ulong)((long)x05 >> 28); x05 &= M28UL;
            x07 += (ulong)((long)x06 >> 28); x06 &= M28UL;
            x08 += (ulong)((long)x07 >> 28); x07 &= M28UL;
            x09 += (ulong)((long)x08 >> 28); x08 &= M28UL;
            x10 += (ulong)((long)x09 >> 28); x09 &= M28UL;
            x11 += (ulong)((long)x10 >> 28); x10 &= M28UL;
            x12 += (ulong)((long)x11 >> 28); x11 &= M28UL;
            x13 += (ulong)((long)x12 >> 28); x12 &= M28UL;
            x14 += (ulong)((long)x13 >> 28); x13 &= M28UL;
            x15 += (ulong)((long)x14 >> 28); x14 &= M28UL;

            Debug.Assert(x15 >> 26 == 0UL);

            Codec.Encode56(x00 | (x01 << 28), r,  0);
            Codec.Encode56(x02 | (x03 << 28), r,  7);
            Codec.Encode56(x04 | (x05 << 28), r, 14);
            Codec.Encode56(x06 | (x07 << 28), r, 21);
            Codec.Encode56(x08 | (x09 << 28), r, 28);
            Codec.Encode56(x10 | (x11 << 28), r, 35);
            Codec.Encode56(x12 | (x13 << 28), r, 42);
            Codec.Encode56(x14 | (x15 << 28), r, 49);
            //r[ScalarBytes - 1] = 0;
#endif

            return r;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Reduce704(ReadOnlySpan<byte> n, Span<byte> r)
        {
            ulong x00 =  Codec.Decode32(n[  0..]);              // x00:32/--
            ulong x01 = (Codec.Decode24(n[  4..]) << 4);        // x01:28/--
            ulong x02 =  Codec.Decode32(n[  7..]);              // x02:32/--
            ulong x03 = (Codec.Decode24(n[ 11..]) << 4);        // x03:28/--
            ulong x04 =  Codec.Decode32(n[ 14..]);              // x04:32/--
            ulong x05 = (Codec.Decode24(n[ 18..]) << 4);        // x05:28/--
            ulong x06 =  Codec.Decode32(n[ 21..]);              // x06:32/--
            ulong x07 = (Codec.Decode24(n[ 25..]) << 4);        // x07:28/--
            ulong x08 =  Codec.Decode32(n[ 28..]);              // x08:32/--
            ulong x09 = (Codec.Decode24(n[ 32..]) << 4);        // x09:28/--
            ulong x10 =  Codec.Decode32(n[ 35..]);              // x10:32/--
            ulong x11 = (Codec.Decode24(n[ 39..]) << 4);        // x11:28/--
            ulong x12 =  Codec.Decode32(n[ 42..]);              // x12:32/--
            ulong x13 = (Codec.Decode24(n[ 46..]) << 4);        // x13:28/--
            ulong x14 =  Codec.Decode32(n[ 49..]);              // x14:32/--
            ulong x15 = (Codec.Decode24(n[ 53..]) << 4);        // x15:28/--
            ulong x16 =  Codec.Decode32(n[ 56..]);              // x16:32/--
            ulong x17 = (Codec.Decode24(n[ 60..]) << 4);        // x17:28/--
            ulong x18 =  Codec.Decode32(n[ 63..]);              // x18:32/--
            ulong x19 = (Codec.Decode24(n[ 67..]) << 4);        // x19:28/--
            ulong x20 =  Codec.Decode32(n[ 70..]);              // x20:32/--
            ulong x21 = (Codec.Decode24(n[ 74..]) << 4);        // x21:28/--
            ulong x22 =  Codec.Decode32(n[ 77..]);              // x22:32/--
            ulong x23 = (Codec.Decode24(n[ 81..]) << 4);        // x23:28/--
            ulong x24 =  Codec.Decode32(n[ 84..]);              // x24:32/--
            ulong x25 = 0UL;

            // TODO Fix bounds calculations which were copied from Reduce912

            x25 += (x24 >> 28); x24 &= M28UL;           // x25:28/--, x24:28/--
            x09 += x25 * L4_0;                          // x09:54/--
            x10 += x25 * L4_1;                          // x10:54/53
            x11 += x25 * L4_2;                          // x11:56/--
            x12 += x25 * L4_3;                          // x12:57/--
            x13 += x25 * L4_4;                          // x13:57/55
            x14 += x25 * L4_5;                          // x14:58/--
            x15 += x25 * L4_6;                          // x15:58/56
            x16 += x25 * L4_7;                          // x16:59/--

            x21 += (x20 >> 28); x20 &= M28UL;           // x21:58/--, x20:28/--
            x22 += (x21 >> 28); x21 &= M28UL;           // x22:57/54, x21:28/--
            x23 += (x22 >> 28); x22 &= M28UL;           // x23:45/42, x22:28/--
            x24 += (x23 >> 28); x23 &= M28UL;           // x24:28/18, x23:28/--

            x08 += x24 * L4_0;                          // x08:54/--
            x09 += x24 * L4_1;                          // x09:55/--
            x10 += x24 * L4_2;                          // x10:56/46
            x11 += x24 * L4_3;                          // x11:57/46
            x12 += x24 * L4_4;                          // x12:57/55
            x13 += x24 * L4_5;                          // x13:58/--
            x14 += x24 * L4_6;                          // x14:58/56
            x15 += x24 * L4_7;                          // x15:59/--

            x07 += x23 * L4_0;                          // x07:54/--
            x08 += x23 * L4_1;                          // x08:54/53
            x09 += x23 * L4_2;                          // x09:56/53
            x10 += x23 * L4_3;                          // x10:57/46
            x11 += x23 * L4_4;                          // x11:57/55
            x12 += x23 * L4_5;                          // x12:58/--
            x13 += x23 * L4_6;                          // x13:58/56
            x14 += x23 * L4_7;                          // x14:59/--

            x06 += x22 * L4_0;                          // x06:54/--
            x07 += x22 * L4_1;                          // x07:54/53
            x08 += x22 * L4_2;                          // x08:56/--
            x09 += x22 * L4_3;                          // x09:57/53
            x10 += x22 * L4_4;                          // x10:57/55
            x11 += x22 * L4_5;                          // x11:58/--
            x12 += x22 * L4_6;                          // x12:58/56
            x13 += x22 * L4_7;                          // x13:59/--

            x18 += (x17 >> 28); x17 &= M28UL;           // x18:59/31, x17:28/--
            x19 += (x18 >> 28); x18 &= M28UL;           // x19:58/54, x18:28/--
            x20 += (x19 >> 28); x19 &= M28UL;           // x20:30/29, x19:28/--
            x21 += (x20 >> 28); x20 &= M28UL;           // x21:28/03, x20:28/--

            x05 += x21 * L4_0;                          // x05:54/--
            x06 += x21 * L4_1;                          // x06:55/--
            x07 += x21 * L4_2;                          // x07:56/31
            x08 += x21 * L4_3;                          // x08:57/31
            x09 += x21 * L4_4;                          // x09:57/56
            x10 += x21 * L4_5;                          // x10:58/--
            x11 += x21 * L4_6;                          // x11:58/56
            x12 += x21 * L4_7;                          // x12:59/--

            x04 += x20 * L4_0;                          // x04:54/--
            x05 += x20 * L4_1;                          // x05:54/53
            x06 += x20 * L4_2;                          // x06:56/53
            x07 += x20 * L4_3;                          // x07:57/31
            x08 += x20 * L4_4;                          // x08:57/55
            x09 += x20 * L4_5;                          // x09:58/--
            x10 += x20 * L4_6;                          // x10:58/56
            x11 += x20 * L4_7;                          // x11:59/--

            x03 += x19 * L4_0;                          // x03:54/--
            x04 += x19 * L4_1;                          // x04:54/53
            x05 += x19 * L4_2;                          // x05:56/--
            x06 += x19 * L4_3;                          // x06:57/53
            x07 += x19 * L4_4;                          // x07:57/55
            x08 += x19 * L4_5;                          // x08:58/--
            x09 += x19 * L4_6;                          // x09:58/56
            x10 += x19 * L4_7;                          // x10:59/--

            x15 += (x14 >> 28); x14 &= M28UL;           // x15:59/31, x14:28/--
            x16 += (x15 >> 28); x15 &= M28UL;           // x16:59/32, x15:28/--
            x17 += (x16 >> 28); x16 &= M28UL;           // x17:31/29, x16:28/--
            x18 += (x17 >> 28); x17 &= M28UL;           // x18:28/04, x17:28/--

            x02 += x18 * L4_0;                          // x02:54/--
            x03 += x18 * L4_1;                          // x03:55/--
            x04 += x18 * L4_2;                          // x04:56/32
            x05 += x18 * L4_3;                          // x05:57/32
            x06 += x18 * L4_4;                          // x06:57/56
            x07 += x18 * L4_5;                          // x07:58/--
            x08 += x18 * L4_6;                          // x08:58/56
            x09 += x18 * L4_7;                          // x09:59/--

            x01 += x17 * L4_0;                          // x01:54/--
            x02 += x17 * L4_1;                          // x02:54/53
            x03 += x17 * L4_2;                          // x03:56/53
            x04 += x17 * L4_3;                          // x04:57/32
            x05 += x17 * L4_4;                          // x05:57/55
            x06 += x17 * L4_5;                          // x06:58/--
            x07 += x17 * L4_6;                          // x07:58/56
            x08 += x17 * L4_7;                          // x08:59/--

            x16 *= 4;
            x16 += (x15 >> 26); x15 &= M26UL;
            x16 += 1;                                   // x16:30/01

            x00 += x16 * L_0;
            x01 += x16 * L_1;
            x02 += x16 * L_2;
            x03 += x16 * L_3;
            x04 += x16 * L_4;
            x05 += x16 * L_5;
            x06 += x16 * L_6;
            x07 += x16 * L_7;

            x01 += (x00 >> 28); x00 &= M28UL;
            x02 += (x01 >> 28); x01 &= M28UL;
            x03 += (x02 >> 28); x02 &= M28UL;
            x04 += (x03 >> 28); x03 &= M28UL;
            x05 += (x04 >> 28); x04 &= M28UL;
            x06 += (x05 >> 28); x05 &= M28UL;
            x07 += (x06 >> 28); x06 &= M28UL;
            x08 += (x07 >> 28); x07 &= M28UL;
            x09 += (x08 >> 28); x08 &= M28UL;
            x10 += (x09 >> 28); x09 &= M28UL;
            x11 += (x10 >> 28); x10 &= M28UL;
            x12 += (x11 >> 28); x11 &= M28UL;
            x13 += (x12 >> 28); x12 &= M28UL;
            x14 += (x13 >> 28); x13 &= M28UL;
            x15 += (x14 >> 28); x14 &= M28UL;
            x16  = (x15 >> 26); x15 &= M26UL;

            x16 -= 1;

            Debug.Assert(x16 == 0UL || x16 == ulong.MaxValue);

            x00 -= x16 & L_0;
            x01 -= x16 & L_1;
            x02 -= x16 & L_2;
            x03 -= x16 & L_3;
            x04 -= x16 & L_4;
            x05 -= x16 & L_5;
            x06 -= x16 & L_6;
            x07 -= x16 & L_7;

            x01 += (ulong)((long)x00 >> 28); x00 &= M28UL;
            x02 += (ulong)((long)x01 >> 28); x01 &= M28UL;
            x03 += (ulong)((long)x02 >> 28); x02 &= M28UL;
            x04 += (ulong)((long)x03 >> 28); x03 &= M28UL;
            x05 += (ulong)((long)x04 >> 28); x04 &= M28UL;
            x06 += (ulong)((long)x05 >> 28); x05 &= M28UL;
            x07 += (ulong)((long)x06 >> 28); x06 &= M28UL;
            x08 += (ulong)((long)x07 >> 28); x07 &= M28UL;
            x09 += (ulong)((long)x08 >> 28); x08 &= M28UL;
            x10 += (ulong)((long)x09 >> 28); x09 &= M28UL;
            x11 += (ulong)((long)x10 >> 28); x10 &= M28UL;
            x12 += (ulong)((long)x11 >> 28); x11 &= M28UL;
            x13 += (ulong)((long)x12 >> 28); x12 &= M28UL;
            x14 += (ulong)((long)x13 >> 28); x13 &= M28UL;
            x15 += (ulong)((long)x14 >> 28); x14 &= M28UL;

            Debug.Assert(x15 >> 26 == 0UL);

            Codec.Encode56(x00 | (x01 << 28), r);
            Codec.Encode56(x02 | (x03 << 28), r[7..]);
            Codec.Encode56(x04 | (x05 << 28), r[14..]);
            Codec.Encode56(x06 | (x07 << 28), r[21..]);
            Codec.Encode56(x08 | (x09 << 28), r[28..]);
            Codec.Encode56(x10 | (x11 << 28), r[35..]);
            Codec.Encode56(x12 | (x13 << 28), r[42..]);
            Codec.Encode56(x14 | (x15 << 28), r[49..]);
            r[ScalarBytes - 1] = 0;
        }
#endif

        internal static byte[] Reduce912(byte[] n)
        {
            byte[] r = new byte[ScalarBytes];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Reduce912(n, r);
#else
            ulong x00 =  Codec.Decode32(n,   0);                // x00:32/--
            ulong x01 = (Codec.Decode24(n,   4) << 4);          // x01:28/--
            ulong x02 =  Codec.Decode32(n,   7);                // x02:32/--
            ulong x03 = (Codec.Decode24(n,  11) << 4);          // x03:28/--
            ulong x04 =  Codec.Decode32(n,  14);                // x04:32/--
            ulong x05 = (Codec.Decode24(n,  18) << 4);          // x05:28/--
            ulong x06 =  Codec.Decode32(n,  21);                // x06:32/--
            ulong x07 = (Codec.Decode24(n,  25) << 4);          // x07:28/--
            ulong x08 =  Codec.Decode32(n,  28);                // x08:32/--
            ulong x09 = (Codec.Decode24(n,  32) << 4);          // x09:28/--
            ulong x10 =  Codec.Decode32(n,  35);                // x10:32/--
            ulong x11 = (Codec.Decode24(n,  39) << 4);          // x11:28/--
            ulong x12 =  Codec.Decode32(n,  42);                // x12:32/--
            ulong x13 = (Codec.Decode24(n,  46) << 4);          // x13:28/--
            ulong x14 =  Codec.Decode32(n,  49);                // x14:32/--
            ulong x15 = (Codec.Decode24(n,  53) << 4);          // x15:28/--
            ulong x16 =  Codec.Decode32(n,  56);                // x16:32/--
            ulong x17 = (Codec.Decode24(n,  60) << 4);          // x17:28/--
            ulong x18 =  Codec.Decode32(n,  63);                // x18:32/--
            ulong x19 = (Codec.Decode24(n,  67) << 4);          // x19:28/--
            ulong x20 =  Codec.Decode32(n,  70);                // x20:32/--
            ulong x21 = (Codec.Decode24(n,  74) << 4);          // x21:28/--
            ulong x22 =  Codec.Decode32(n,  77);                // x22:32/--
            ulong x23 = (Codec.Decode24(n,  81) << 4);          // x23:28/--
            ulong x24 =  Codec.Decode32(n,  84);                // x24:32/--
            ulong x25 = (Codec.Decode24(n,  88) << 4);          // x25:28/--
            ulong x26 =  Codec.Decode32(n,  91);                // x26:32/--
            ulong x27 = (Codec.Decode24(n,  95) << 4);          // x27:28/--
            ulong x28 =  Codec.Decode32(n,  98);                // x28:32/--
            ulong x29 = (Codec.Decode24(n, 102) << 4);          // x29:28/--
            ulong x30 =  Codec.Decode32(n, 105);                // x30:32/--
            ulong x31 = (Codec.Decode24(n, 109) << 4);          // x31:28/--
            ulong x32 =  Codec.Decode16(n, 112);                // x32:16/--

            //x32 += (x31 >> 28); x31 &= M28UL;
            x16 += x32 * L4_0;                          // x16:42/--
            x17 += x32 * L4_1;                          // x17:41/28
            x18 += x32 * L4_2;                          // x18:43/42
            x19 += x32 * L4_3;                          // x19:44/28
            x20 += x32 * L4_4;                          // x20:43/--
            x21 += x32 * L4_5;                          // x21:44/28
            x22 += x32 * L4_6;                          // x22:43/41
            x23 += x32 * L4_7;                          // x23:45/41

            x31 += (x30 >> 28); x30 &= M28UL;           // x31:28/--, x30:28/--
            x15 += x31 * L4_0;                          // x15:54/--
            x16 += x31 * L4_1;                          // x16:53/42
            x17 += x31 * L4_2;                          // x17:55/54
            x18 += x31 * L4_3;                          // x18:56/44
            x19 += x31 * L4_4;                          // x19:55/--
            x20 += x31 * L4_5;                          // x20:56/43
            x21 += x31 * L4_6;                          // x21:55/53
            x22 += x31 * L4_7;                          // x22:57/53

            //x30 += (x29 >> 28); x29 &= M28UL;
            x14 += x30 * L4_0;                          // x14:54/--
            x15 += x30 * L4_1;                          // x15:54/53
            x16 += x30 * L4_2;                          // x16:56/--
            x17 += x30 * L4_3;                          // x17:57/--
            x18 += x30 * L4_4;                          // x18:56/55
            x19 += x30 * L4_5;                          // x19:56/55
            x20 += x30 * L4_6;                          // x20:57/--
            x21 += x30 * L4_7;                          // x21:57/56

            x29 += (x28 >> 28); x28 &= M28UL;           // x29:28/--, x28:28/--
            x13 += x29 * L4_0;                          // x13:54/--
            x14 += x29 * L4_1;                          // x14:54/53
            x15 += x29 * L4_2;                          // x15:56/--
            x16 += x29 * L4_3;                          // x16:57/--
            x17 += x29 * L4_4;                          // x17:57/55
            x18 += x29 * L4_5;                          // x18:57/55
            x19 += x29 * L4_6;                          // x19:57/52
            x20 += x29 * L4_7;                          // x20:58/52

            //x28 += (x27 >> 28); x27 &= M28UL;
            x12 += x28 * L4_0;                          // x12:54/--
            x13 += x28 * L4_1;                          // x13:54/53
            x14 += x28 * L4_2;                          // x14:56/--
            x15 += x28 * L4_3;                          // x15:57/--
            x16 += x28 * L4_4;                          // x16:57/55
            x17 += x28 * L4_5;                          // x17:58/--
            x18 += x28 * L4_6;                          // x18:58/--
            x19 += x28 * L4_7;                          // x19:58/53

            x27 += (x26 >> 28); x26 &= M28UL;           // x27:28/--, x26:28/--
            x11 += x27 * L4_0;                          // x11:54/--
            x12 += x27 * L4_1;                          // x12:54/53
            x13 += x27 * L4_2;                          // x13:56/--
            x14 += x27 * L4_3;                          // x14:57/--
            x15 += x27 * L4_4;                          // x15:57/55
            x16 += x27 * L4_5;                          // x16:58/--
            x17 += x27 * L4_6;                          // x17:58/56
            x18 += x27 * L4_7;                          // x18:59/--

            //x26 += (x25 >> 28); x25 &= M28UL;
            x10 += x26 * L4_0;                          // x10:54/--
            x11 += x26 * L4_1;                          // x11:54/53
            x12 += x26 * L4_2;                          // x12:56/--
            x13 += x26 * L4_3;                          // x13:57/--
            x14 += x26 * L4_4;                          // x14:57/55
            x15 += x26 * L4_5;                          // x15:58/--
            x16 += x26 * L4_6;                          // x16:58/56
            x17 += x26 * L4_7;                          // x17:59/--

            x25 += (x24 >> 28); x24 &= M28UL;           // x25:28/--, x24:28/--
            x09 += x25 * L4_0;                          // x09:54/--
            x10 += x25 * L4_1;                          // x10:54/53
            x11 += x25 * L4_2;                          // x11:56/--
            x12 += x25 * L4_3;                          // x12:57/--
            x13 += x25 * L4_4;                          // x13:57/55
            x14 += x25 * L4_5;                          // x14:58/--
            x15 += x25 * L4_6;                          // x15:58/56
            x16 += x25 * L4_7;                          // x16:59/--

            x21 += (x20 >> 28); x20 &= M28UL;           // x21:58/--, x20:28/--
            x22 += (x21 >> 28); x21 &= M28UL;           // x22:57/54, x21:28/--
            x23 += (x22 >> 28); x22 &= M28UL;           // x23:45/42, x22:28/--
            x24 += (x23 >> 28); x23 &= M28UL;           // x24:28/18, x23:28/--

            x08 += x24 * L4_0;                          // x08:54/--
            x09 += x24 * L4_1;                          // x09:55/--
            x10 += x24 * L4_2;                          // x10:56/46
            x11 += x24 * L4_3;                          // x11:57/46
            x12 += x24 * L4_4;                          // x12:57/55
            x13 += x24 * L4_5;                          // x13:58/--
            x14 += x24 * L4_6;                          // x14:58/56
            x15 += x24 * L4_7;                          // x15:59/--

            x07 += x23 * L4_0;                          // x07:54/--
            x08 += x23 * L4_1;                          // x08:54/53
            x09 += x23 * L4_2;                          // x09:56/53
            x10 += x23 * L4_3;                          // x10:57/46
            x11 += x23 * L4_4;                          // x11:57/55
            x12 += x23 * L4_5;                          // x12:58/--
            x13 += x23 * L4_6;                          // x13:58/56
            x14 += x23 * L4_7;                          // x14:59/--

            x06 += x22 * L4_0;                          // x06:54/--
            x07 += x22 * L4_1;                          // x07:54/53
            x08 += x22 * L4_2;                          // x08:56/--
            x09 += x22 * L4_3;                          // x09:57/53
            x10 += x22 * L4_4;                          // x10:57/55
            x11 += x22 * L4_5;                          // x11:58/--
            x12 += x22 * L4_6;                          // x12:58/56
            x13 += x22 * L4_7;                          // x13:59/--

            x18 += (x17 >> 28); x17 &= M28UL;           // x18:59/31, x17:28/--
            x19 += (x18 >> 28); x18 &= M28UL;           // x19:58/54, x18:28/--
            x20 += (x19 >> 28); x19 &= M28UL;           // x20:30/29, x19:28/--
            x21 += (x20 >> 28); x20 &= M28UL;           // x21:28/03, x20:28/--

            x05 += x21 * L4_0;                          // x05:54/--
            x06 += x21 * L4_1;                          // x06:55/--
            x07 += x21 * L4_2;                          // x07:56/31
            x08 += x21 * L4_3;                          // x08:57/31
            x09 += x21 * L4_4;                          // x09:57/56
            x10 += x21 * L4_5;                          // x10:58/--
            x11 += x21 * L4_6;                          // x11:58/56
            x12 += x21 * L4_7;                          // x12:59/--

            x04 += x20 * L4_0;                          // x04:54/--
            x05 += x20 * L4_1;                          // x05:54/53
            x06 += x20 * L4_2;                          // x06:56/53
            x07 += x20 * L4_3;                          // x07:57/31
            x08 += x20 * L4_4;                          // x08:57/55
            x09 += x20 * L4_5;                          // x09:58/--
            x10 += x20 * L4_6;                          // x10:58/56
            x11 += x20 * L4_7;                          // x11:59/--

            x03 += x19 * L4_0;                          // x03:54/--
            x04 += x19 * L4_1;                          // x04:54/53
            x05 += x19 * L4_2;                          // x05:56/--
            x06 += x19 * L4_3;                          // x06:57/53
            x07 += x19 * L4_4;                          // x07:57/55
            x08 += x19 * L4_5;                          // x08:58/--
            x09 += x19 * L4_6;                          // x09:58/56
            x10 += x19 * L4_7;                          // x10:59/--

            x15 += (x14 >> 28); x14 &= M28UL;           // x15:59/31, x14:28/--
            x16 += (x15 >> 28); x15 &= M28UL;           // x16:59/32, x15:28/--
            x17 += (x16 >> 28); x16 &= M28UL;           // x17:31/29, x16:28/--
            x18 += (x17 >> 28); x17 &= M28UL;           // x18:28/04, x17:28/--

            x02 += x18 * L4_0;                          // x02:54/--
            x03 += x18 * L4_1;                          // x03:55/--
            x04 += x18 * L4_2;                          // x04:56/32
            x05 += x18 * L4_3;                          // x05:57/32
            x06 += x18 * L4_4;                          // x06:57/56
            x07 += x18 * L4_5;                          // x07:58/--
            x08 += x18 * L4_6;                          // x08:58/56
            x09 += x18 * L4_7;                          // x09:59/--

            x01 += x17 * L4_0;                          // x01:54/--
            x02 += x17 * L4_1;                          // x02:54/53
            x03 += x17 * L4_2;                          // x03:56/53
            x04 += x17 * L4_3;                          // x04:57/32
            x05 += x17 * L4_4;                          // x05:57/55
            x06 += x17 * L4_5;                          // x06:58/--
            x07 += x17 * L4_6;                          // x07:58/56
            x08 += x17 * L4_7;                          // x08:59/--

            x16 *= 4;
            x16 += (x15 >> 26); x15 &= M26UL;
            x16 += 1;                                   // x16:30/01

            x00 += x16 * L_0;
            x01 += x16 * L_1;
            x02 += x16 * L_2;
            x03 += x16 * L_3;
            x04 += x16 * L_4;
            x05 += x16 * L_5;
            x06 += x16 * L_6;
            x07 += x16 * L_7;

            x01 += (x00 >> 28); x00 &= M28UL;
            x02 += (x01 >> 28); x01 &= M28UL;
            x03 += (x02 >> 28); x02 &= M28UL;
            x04 += (x03 >> 28); x03 &= M28UL;
            x05 += (x04 >> 28); x04 &= M28UL;
            x06 += (x05 >> 28); x05 &= M28UL;
            x07 += (x06 >> 28); x06 &= M28UL;
            x08 += (x07 >> 28); x07 &= M28UL;
            x09 += (x08 >> 28); x08 &= M28UL;
            x10 += (x09 >> 28); x09 &= M28UL;
            x11 += (x10 >> 28); x10 &= M28UL;
            x12 += (x11 >> 28); x11 &= M28UL;
            x13 += (x12 >> 28); x12 &= M28UL;
            x14 += (x13 >> 28); x13 &= M28UL;
            x15 += (x14 >> 28); x14 &= M28UL;
            x16  = (x15 >> 26); x15 &= M26UL;

            x16 -= 1;

            Debug.Assert(x16 == 0UL || x16 == ulong.MaxValue);

            x00 -= x16 & L_0;
            x01 -= x16 & L_1;
            x02 -= x16 & L_2;
            x03 -= x16 & L_3;
            x04 -= x16 & L_4;
            x05 -= x16 & L_5;
            x06 -= x16 & L_6;
            x07 -= x16 & L_7;

            x01 += (ulong)((long)x00 >> 28); x00 &= M28UL;
            x02 += (ulong)((long)x01 >> 28); x01 &= M28UL;
            x03 += (ulong)((long)x02 >> 28); x02 &= M28UL;
            x04 += (ulong)((long)x03 >> 28); x03 &= M28UL;
            x05 += (ulong)((long)x04 >> 28); x04 &= M28UL;
            x06 += (ulong)((long)x05 >> 28); x05 &= M28UL;
            x07 += (ulong)((long)x06 >> 28); x06 &= M28UL;
            x08 += (ulong)((long)x07 >> 28); x07 &= M28UL;
            x09 += (ulong)((long)x08 >> 28); x08 &= M28UL;
            x10 += (ulong)((long)x09 >> 28); x09 &= M28UL;
            x11 += (ulong)((long)x10 >> 28); x10 &= M28UL;
            x12 += (ulong)((long)x11 >> 28); x11 &= M28UL;
            x13 += (ulong)((long)x12 >> 28); x12 &= M28UL;
            x14 += (ulong)((long)x13 >> 28); x13 &= M28UL;
            x15 += (ulong)((long)x14 >> 28); x14 &= M28UL;

            Debug.Assert(x15 >> 26 == 0UL);

            Codec.Encode56(x00 | (x01 << 28), r,  0);
            Codec.Encode56(x02 | (x03 << 28), r,  7);
            Codec.Encode56(x04 | (x05 << 28), r, 14);
            Codec.Encode56(x06 | (x07 << 28), r, 21);
            Codec.Encode56(x08 | (x09 << 28), r, 28);
            Codec.Encode56(x10 | (x11 << 28), r, 35);
            Codec.Encode56(x12 | (x13 << 28), r, 42);
            Codec.Encode56(x14 | (x15 << 28), r, 49);
            //r[ScalarBytes - 1] = 0;
#endif

            return r;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Reduce912(ReadOnlySpan<byte> n, Span<byte> r)
        {
            ulong x00 =  Codec.Decode32(n[  0..]);              // x00:32/--
            ulong x01 = (Codec.Decode24(n[  4..]) << 4);        // x01:28/--
            ulong x02 =  Codec.Decode32(n[  7..]);              // x02:32/--
            ulong x03 = (Codec.Decode24(n[ 11..]) << 4);        // x03:28/--
            ulong x04 =  Codec.Decode32(n[ 14..]);              // x04:32/--
            ulong x05 = (Codec.Decode24(n[ 18..]) << 4);        // x05:28/--
            ulong x06 =  Codec.Decode32(n[ 21..]);              // x06:32/--
            ulong x07 = (Codec.Decode24(n[ 25..]) << 4);        // x07:28/--
            ulong x08 =  Codec.Decode32(n[ 28..]);              // x08:32/--
            ulong x09 = (Codec.Decode24(n[ 32..]) << 4);        // x09:28/--
            ulong x10 =  Codec.Decode32(n[ 35..]);              // x10:32/--
            ulong x11 = (Codec.Decode24(n[ 39..]) << 4);        // x11:28/--
            ulong x12 =  Codec.Decode32(n[ 42..]);              // x12:32/--
            ulong x13 = (Codec.Decode24(n[ 46..]) << 4);        // x13:28/--
            ulong x14 =  Codec.Decode32(n[ 49..]);              // x14:32/--
            ulong x15 = (Codec.Decode24(n[ 53..]) << 4);        // x15:28/--
            ulong x16 =  Codec.Decode32(n[ 56..]);              // x16:32/--
            ulong x17 = (Codec.Decode24(n[ 60..]) << 4);        // x17:28/--
            ulong x18 =  Codec.Decode32(n[ 63..]);              // x18:32/--
            ulong x19 = (Codec.Decode24(n[ 67..]) << 4);        // x19:28/--
            ulong x20 =  Codec.Decode32(n[ 70..]);              // x20:32/--
            ulong x21 = (Codec.Decode24(n[ 74..]) << 4);        // x21:28/--
            ulong x22 =  Codec.Decode32(n[ 77..]);              // x22:32/--
            ulong x23 = (Codec.Decode24(n[ 81..]) << 4);        // x23:28/--
            ulong x24 =  Codec.Decode32(n[ 84..]);              // x24:32/--
            ulong x25 = (Codec.Decode24(n[ 88..]) << 4);        // x25:28/--
            ulong x26 =  Codec.Decode32(n[ 91..]);              // x26:32/--
            ulong x27 = (Codec.Decode24(n[ 95..]) << 4);        // x27:28/--
            ulong x28 =  Codec.Decode32(n[ 98..]);              // x28:32/--
            ulong x29 = (Codec.Decode24(n[102..]) << 4);        // x29:28/--
            ulong x30 =  Codec.Decode32(n[105..]);              // x30:32/--
            ulong x31 = (Codec.Decode24(n[109..]) << 4);        // x31:28/--
            ulong x32 =  Codec.Decode16(n[112..]);              // x32:16/--

            //x32 += (x31 >> 28); x31 &= M28UL;
            x16 += x32 * L4_0;                          // x16:42/--
            x17 += x32 * L4_1;                          // x17:41/28
            x18 += x32 * L4_2;                          // x18:43/42
            x19 += x32 * L4_3;                          // x19:44/28
            x20 += x32 * L4_4;                          // x20:43/--
            x21 += x32 * L4_5;                          // x21:44/28
            x22 += x32 * L4_6;                          // x22:43/41
            x23 += x32 * L4_7;                          // x23:45/41

            x31 += (x30 >> 28); x30 &= M28UL;           // x31:28/--, x30:28/--
            x15 += x31 * L4_0;                          // x15:54/--
            x16 += x31 * L4_1;                          // x16:53/42
            x17 += x31 * L4_2;                          // x17:55/54
            x18 += x31 * L4_3;                          // x18:56/44
            x19 += x31 * L4_4;                          // x19:55/--
            x20 += x31 * L4_5;                          // x20:56/43
            x21 += x31 * L4_6;                          // x21:55/53
            x22 += x31 * L4_7;                          // x22:57/53

            //x30 += (x29 >> 28); x29 &= M28UL;
            x14 += x30 * L4_0;                          // x14:54/--
            x15 += x30 * L4_1;                          // x15:54/53
            x16 += x30 * L4_2;                          // x16:56/--
            x17 += x30 * L4_3;                          // x17:57/--
            x18 += x30 * L4_4;                          // x18:56/55
            x19 += x30 * L4_5;                          // x19:56/55
            x20 += x30 * L4_6;                          // x20:57/--
            x21 += x30 * L4_7;                          // x21:57/56

            x29 += (x28 >> 28); x28 &= M28UL;           // x29:28/--, x28:28/--
            x13 += x29 * L4_0;                          // x13:54/--
            x14 += x29 * L4_1;                          // x14:54/53
            x15 += x29 * L4_2;                          // x15:56/--
            x16 += x29 * L4_3;                          // x16:57/--
            x17 += x29 * L4_4;                          // x17:57/55
            x18 += x29 * L4_5;                          // x18:57/55
            x19 += x29 * L4_6;                          // x19:57/52
            x20 += x29 * L4_7;                          // x20:58/52

            //x28 += (x27 >> 28); x27 &= M28UL;
            x12 += x28 * L4_0;                          // x12:54/--
            x13 += x28 * L4_1;                          // x13:54/53
            x14 += x28 * L4_2;                          // x14:56/--
            x15 += x28 * L4_3;                          // x15:57/--
            x16 += x28 * L4_4;                          // x16:57/55
            x17 += x28 * L4_5;                          // x17:58/--
            x18 += x28 * L4_6;                          // x18:58/--
            x19 += x28 * L4_7;                          // x19:58/53

            x27 += (x26 >> 28); x26 &= M28UL;           // x27:28/--, x26:28/--
            x11 += x27 * L4_0;                          // x11:54/--
            x12 += x27 * L4_1;                          // x12:54/53
            x13 += x27 * L4_2;                          // x13:56/--
            x14 += x27 * L4_3;                          // x14:57/--
            x15 += x27 * L4_4;                          // x15:57/55
            x16 += x27 * L4_5;                          // x16:58/--
            x17 += x27 * L4_6;                          // x17:58/56
            x18 += x27 * L4_7;                          // x18:59/--

            //x26 += (x25 >> 28); x25 &= M28UL;
            x10 += x26 * L4_0;                          // x10:54/--
            x11 += x26 * L4_1;                          // x11:54/53
            x12 += x26 * L4_2;                          // x12:56/--
            x13 += x26 * L4_3;                          // x13:57/--
            x14 += x26 * L4_4;                          // x14:57/55
            x15 += x26 * L4_5;                          // x15:58/--
            x16 += x26 * L4_6;                          // x16:58/56
            x17 += x26 * L4_7;                          // x17:59/--

            x25 += (x24 >> 28); x24 &= M28UL;           // x25:28/--, x24:28/--
            x09 += x25 * L4_0;                          // x09:54/--
            x10 += x25 * L4_1;                          // x10:54/53
            x11 += x25 * L4_2;                          // x11:56/--
            x12 += x25 * L4_3;                          // x12:57/--
            x13 += x25 * L4_4;                          // x13:57/55
            x14 += x25 * L4_5;                          // x14:58/--
            x15 += x25 * L4_6;                          // x15:58/56
            x16 += x25 * L4_7;                          // x16:59/--

            x21 += (x20 >> 28); x20 &= M28UL;           // x21:58/--, x20:28/--
            x22 += (x21 >> 28); x21 &= M28UL;           // x22:57/54, x21:28/--
            x23 += (x22 >> 28); x22 &= M28UL;           // x23:45/42, x22:28/--
            x24 += (x23 >> 28); x23 &= M28UL;           // x24:28/18, x23:28/--

            x08 += x24 * L4_0;                          // x08:54/--
            x09 += x24 * L4_1;                          // x09:55/--
            x10 += x24 * L4_2;                          // x10:56/46
            x11 += x24 * L4_3;                          // x11:57/46
            x12 += x24 * L4_4;                          // x12:57/55
            x13 += x24 * L4_5;                          // x13:58/--
            x14 += x24 * L4_6;                          // x14:58/56
            x15 += x24 * L4_7;                          // x15:59/--

            x07 += x23 * L4_0;                          // x07:54/--
            x08 += x23 * L4_1;                          // x08:54/53
            x09 += x23 * L4_2;                          // x09:56/53
            x10 += x23 * L4_3;                          // x10:57/46
            x11 += x23 * L4_4;                          // x11:57/55
            x12 += x23 * L4_5;                          // x12:58/--
            x13 += x23 * L4_6;                          // x13:58/56
            x14 += x23 * L4_7;                          // x14:59/--

            x06 += x22 * L4_0;                          // x06:54/--
            x07 += x22 * L4_1;                          // x07:54/53
            x08 += x22 * L4_2;                          // x08:56/--
            x09 += x22 * L4_3;                          // x09:57/53
            x10 += x22 * L4_4;                          // x10:57/55
            x11 += x22 * L4_5;                          // x11:58/--
            x12 += x22 * L4_6;                          // x12:58/56
            x13 += x22 * L4_7;                          // x13:59/--

            x18 += (x17 >> 28); x17 &= M28UL;           // x18:59/31, x17:28/--
            x19 += (x18 >> 28); x18 &= M28UL;           // x19:58/54, x18:28/--
            x20 += (x19 >> 28); x19 &= M28UL;           // x20:30/29, x19:28/--
            x21 += (x20 >> 28); x20 &= M28UL;           // x21:28/03, x20:28/--

            x05 += x21 * L4_0;                          // x05:54/--
            x06 += x21 * L4_1;                          // x06:55/--
            x07 += x21 * L4_2;                          // x07:56/31
            x08 += x21 * L4_3;                          // x08:57/31
            x09 += x21 * L4_4;                          // x09:57/56
            x10 += x21 * L4_5;                          // x10:58/--
            x11 += x21 * L4_6;                          // x11:58/56
            x12 += x21 * L4_7;                          // x12:59/--

            x04 += x20 * L4_0;                          // x04:54/--
            x05 += x20 * L4_1;                          // x05:54/53
            x06 += x20 * L4_2;                          // x06:56/53
            x07 += x20 * L4_3;                          // x07:57/31
            x08 += x20 * L4_4;                          // x08:57/55
            x09 += x20 * L4_5;                          // x09:58/--
            x10 += x20 * L4_6;                          // x10:58/56
            x11 += x20 * L4_7;                          // x11:59/--

            x03 += x19 * L4_0;                          // x03:54/--
            x04 += x19 * L4_1;                          // x04:54/53
            x05 += x19 * L4_2;                          // x05:56/--
            x06 += x19 * L4_3;                          // x06:57/53
            x07 += x19 * L4_4;                          // x07:57/55
            x08 += x19 * L4_5;                          // x08:58/--
            x09 += x19 * L4_6;                          // x09:58/56
            x10 += x19 * L4_7;                          // x10:59/--

            x15 += (x14 >> 28); x14 &= M28UL;           // x15:59/31, x14:28/--
            x16 += (x15 >> 28); x15 &= M28UL;           // x16:59/32, x15:28/--
            x17 += (x16 >> 28); x16 &= M28UL;           // x17:31/29, x16:28/--
            x18 += (x17 >> 28); x17 &= M28UL;           // x18:28/04, x17:28/--

            x02 += x18 * L4_0;                          // x02:54/--
            x03 += x18 * L4_1;                          // x03:55/--
            x04 += x18 * L4_2;                          // x04:56/32
            x05 += x18 * L4_3;                          // x05:57/32
            x06 += x18 * L4_4;                          // x06:57/56
            x07 += x18 * L4_5;                          // x07:58/--
            x08 += x18 * L4_6;                          // x08:58/56
            x09 += x18 * L4_7;                          // x09:59/--

            x01 += x17 * L4_0;                          // x01:54/--
            x02 += x17 * L4_1;                          // x02:54/53
            x03 += x17 * L4_2;                          // x03:56/53
            x04 += x17 * L4_3;                          // x04:57/32
            x05 += x17 * L4_4;                          // x05:57/55
            x06 += x17 * L4_5;                          // x06:58/--
            x07 += x17 * L4_6;                          // x07:58/56
            x08 += x17 * L4_7;                          // x08:59/--

            x16 *= 4;
            x16 += (x15 >> 26); x15 &= M26UL;
            x16 += 1;                                   // x16:30/01

            x00 += x16 * L_0;
            x01 += x16 * L_1;
            x02 += x16 * L_2;
            x03 += x16 * L_3;
            x04 += x16 * L_4;
            x05 += x16 * L_5;
            x06 += x16 * L_6;
            x07 += x16 * L_7;

            x01 += (x00 >> 28); x00 &= M28UL;
            x02 += (x01 >> 28); x01 &= M28UL;
            x03 += (x02 >> 28); x02 &= M28UL;
            x04 += (x03 >> 28); x03 &= M28UL;
            x05 += (x04 >> 28); x04 &= M28UL;
            x06 += (x05 >> 28); x05 &= M28UL;
            x07 += (x06 >> 28); x06 &= M28UL;
            x08 += (x07 >> 28); x07 &= M28UL;
            x09 += (x08 >> 28); x08 &= M28UL;
            x10 += (x09 >> 28); x09 &= M28UL;
            x11 += (x10 >> 28); x10 &= M28UL;
            x12 += (x11 >> 28); x11 &= M28UL;
            x13 += (x12 >> 28); x12 &= M28UL;
            x14 += (x13 >> 28); x13 &= M28UL;
            x15 += (x14 >> 28); x14 &= M28UL;
            x16  = (x15 >> 26); x15 &= M26UL;

            x16 -= 1;

            Debug.Assert(x16 == 0UL || x16 == ulong.MaxValue);

            x00 -= x16 & L_0;
            x01 -= x16 & L_1;
            x02 -= x16 & L_2;
            x03 -= x16 & L_3;
            x04 -= x16 & L_4;
            x05 -= x16 & L_5;
            x06 -= x16 & L_6;
            x07 -= x16 & L_7;

            x01 += (ulong)((long)x00 >> 28); x00 &= M28UL;
            x02 += (ulong)((long)x01 >> 28); x01 &= M28UL;
            x03 += (ulong)((long)x02 >> 28); x02 &= M28UL;
            x04 += (ulong)((long)x03 >> 28); x03 &= M28UL;
            x05 += (ulong)((long)x04 >> 28); x04 &= M28UL;
            x06 += (ulong)((long)x05 >> 28); x05 &= M28UL;
            x07 += (ulong)((long)x06 >> 28); x06 &= M28UL;
            x08 += (ulong)((long)x07 >> 28); x07 &= M28UL;
            x09 += (ulong)((long)x08 >> 28); x08 &= M28UL;
            x10 += (ulong)((long)x09 >> 28); x09 &= M28UL;
            x11 += (ulong)((long)x10 >> 28); x10 &= M28UL;
            x12 += (ulong)((long)x11 >> 28); x11 &= M28UL;
            x13 += (ulong)((long)x12 >> 28); x12 &= M28UL;
            x14 += (ulong)((long)x13 >> 28); x13 &= M28UL;
            x15 += (ulong)((long)x14 >> 28); x14 &= M28UL;

            Debug.Assert(x15 >> 26 == 0UL);

            Codec.Encode56(x00 | (x01 << 28), r);
            Codec.Encode56(x02 | (x03 << 28), r[7..]);
            Codec.Encode56(x04 | (x05 << 28), r[14..]);
            Codec.Encode56(x06 | (x07 << 28), r[21..]);
            Codec.Encode56(x08 | (x09 << 28), r[28..]);
            Codec.Encode56(x10 | (x11 << 28), r[35..]);
            Codec.Encode56(x12 | (x13 << 28), r[42..]);
            Codec.Encode56(x14 | (x15 << 28), r[49..]);
            r[ScalarBytes - 1] = 0;
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

            Span<uint> Nu = stackalloc uint[28];    LSq.CopyTo(Nu);
            Span<uint> Nv = stackalloc uint[28];    Nat448.Square(k, Nv); ++Nv[0];
            Span<uint> p  = stackalloc uint[28];    Nat448.Mul(L, k, p);
            Span<uint> t  = stackalloc uint[28];
            Span<uint> u0 = stackalloc uint[8];     u0.CopyFrom(L);
            Span<uint> u1 = stackalloc uint[8];
            Span<uint> v0 = stackalloc uint[8];     v0.CopyFrom(k);
            Span<uint> v1 = stackalloc uint[8];     v1[0] = 1U;

            int last = 27;
            int len_Nv = ScalarUtilities.GetBitLengthPositive(last, Nv);

            while (len_Nv > TargetLength)
            {
                int len_p = ScalarUtilities.GetBitLength(last, p);
                int s = len_p - len_Nv;
                s &= ~(s >> 31);

                if ((int)p[last] < 0)
                {
                    ScalarUtilities.AddShifted_NP(last, s, Nu, Nv, p, t);
                    ScalarUtilities.AddShifted_UV(last: 7, s, u0, u1, v0, v1);
                }
                else
                {
                    ScalarUtilities.SubShifted_NP(last, s, Nu, Nv, p, t);
                    ScalarUtilities.SubShifted_UV(last: 7, s, u0, u1, v0, v1);
                }

                if (ScalarUtilities.LessThan(last, Nu, Nv))
                {
                    ScalarUtilities.Swap(ref u0, ref v0);
                    ScalarUtilities.Swap(ref u1, ref v1);
                    ScalarUtilities.Swap(ref Nu, ref Nv);

                    last = len_Nv >> 5;
                    len_Nv = ScalarUtilities.GetBitLengthPositive(last, Nv);
                }
            }

            Debug.Assert((int)v0[7] >> 31 == (int)v0[7]);
            Debug.Assert((int)v1[7] >> 31 == (int)v1[7]);

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

            uint[] Nu = new uint[28];       Array.Copy(LSq, Nu, 28);
            uint[] Nv = new uint[28];       Nat448.Square(k, Nv); ++Nv[0];
            uint[] p  = new uint[28];       Nat448.Mul(L, k, p);
            uint[] t  = new uint[28];
            uint[] u0 = new uint[8];        Array.Copy(L, u0, 8);
            uint[] u1 = new uint[8];
            uint[] v0 = new uint[8];        Array.Copy(k, v0, 8);
            uint[] v1 = new uint[8];        v1[0] = 1U;

            int last = 27;
            int len_Nv = ScalarUtilities.GetBitLengthPositive(last, Nv);

            while (len_Nv > TargetLength)
            {
                int len_p = ScalarUtilities.GetBitLength(last, p);
                int s = len_p - len_Nv;
                s &= ~(s >> 31);

                if ((int)p[last] < 0)
                {
                    ScalarUtilities.AddShifted_NP(last, s, Nu, Nv, p, t);
                    ScalarUtilities.AddShifted_UV(last: 7, s, u0, u1, v0, v1);
                }
                else
                {
                    ScalarUtilities.SubShifted_NP(last, s, Nu, Nv, p, t);
                    ScalarUtilities.SubShifted_UV(last: 7, s, u0, u1, v0, v1);
                }

                if (ScalarUtilities.LessThan(last, Nu, Nv))
                {
                    ScalarUtilities.Swap(ref u0, ref v0);
                    ScalarUtilities.Swap(ref u1, ref v1);
                    ScalarUtilities.Swap(ref Nu, ref Nv);

                    last = len_Nv >> 5;
                    len_Nv = ScalarUtilities.GetBitLengthPositive(last, Nv);
                }
            }

            Debug.Assert((int)v0[7] >> 31 == (int)v0[7]);
            Debug.Assert((int)v1[7] >> 31 == (int)v1[7]);

            // v1 * k == v0 mod L
            Array.Copy(v0, z0, 8);
            Array.Copy(v1, z1, 8);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void ToSignedDigits(int bits, ReadOnlySpan<uint> x, Span<uint> z)
#else
        internal static void ToSignedDigits(int bits, uint[] x, uint[] z)
#endif
        {
            Debug.Assert(448 < bits && bits < 480);
            Debug.Assert(z.Length > Size);

            z[Size] = (1U << (bits - 448))
                    + Nat.CAdd(Size, ~(int)x[0] & 1, x, L, z);
            uint c = Nat.ShiftDownBit(Size + 1, z, 0);
            Debug.Assert(c == (1U << 31));
        }
    }
}
