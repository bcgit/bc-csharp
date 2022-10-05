using System;
using System.Diagnostics;

using Org.BouncyCastle.Math.Raw;

#if NET5_0_OR_GREATER
using static System.Math;
#endif

namespace Org.BouncyCastle.Math.EC.Rfc7748
{
    public static class X25519Field
    {
        public const int Size = 10;

        private const int M24 = 0x00FFFFFF;
        private const int M25 = 0x01FFFFFF;
        private const int M26 = 0x03FFFFFF;

        private static readonly uint[] P32 = new uint[]{ 0xFFFFFFEDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
            0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU };
        private static readonly int[] RootNegOne = { 0x020EA0B0, 0x0386C9D2, 0x00478C4E, 0x0035697F, 0x005E8630,
            0x01FBD7A7, 0x0340264F, 0x01F0B2B4, 0x00027E0E, 0x00570649 };

        public static void Add(int[] x, int[] y, int[] z)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[i] = x[i] + y[i];
            }
        }

        public static void AddOne(int[] z)
        {
            z[0] += 1;
        }

        public static void AddOne(int[] z, int zOff)
        {
            z[zOff] += 1;
        }

        public static void Apm(int[] x, int[] y, int[] zp, int[] zm)
        {
            for (int i = 0; i < Size; ++i)
            {
                int xi = x[i], yi = y[i];
                zp[i] = xi + yi;
                zm[i] = xi - yi;
            }
        }

        public static int AreEqual(int[] x, int[] y)
        {
            int d = 0;
            for (int i = 0; i < Size; ++i)
            {
                d |= x[i] ^ y[i];
            }
            d |= d >> 16;
            d &= 0xFFFF;
            return (d - 1) >> 31;
        }

        public static bool AreEqualVar(int[] x, int[] y)
        {
            return 0 != AreEqual(x, y);
        }

        public static void Carry(int[] z)
        {
            int z0 = z[0], z1 = z[1], z2 = z[2], z3 = z[3], z4 = z[4];
            int z5 = z[5], z6 = z[6], z7 = z[7], z8 = z[8], z9 = z[9];

            z2 += (z1 >> 26); z1 &= M26;
            z4 += (z3 >> 26); z3 &= M26;
            z7 += (z6 >> 26); z6 &= M26;
            z9 += (z8 >> 26); z8 &= M26;

            z3 += (z2 >> 25); z2 &= M25;
            z5 += (z4 >> 25); z4 &= M25;
            z8 += (z7 >> 25); z7 &= M25;
            //z0 += (z9 >> 24) * 19; z9 &= M24;
            z0 += (z9 >> 25) * 38; z9 &= M25;

            z1 += (z0 >> 26); z0 &= M26;
            z6 += (z5 >> 26); z5 &= M26;

            z2 += (z1 >> 26); z1 &= M26;
            z4 += (z3 >> 26); z3 &= M26;
            z7 += (z6 >> 26); z6 &= M26;
            z9 += (z8 >> 26); z8 &= M26;

            z[0] = z0; z[1] = z1; z[2] = z2; z[3] = z3; z[4] = z4;
            z[5] = z5; z[6] = z6; z[7] = z7; z[8] = z8; z[9] = z9;
        }

        public static void CMov(int cond, int[] x, int xOff, int[] z, int zOff)
        {
            Debug.Assert(0 == cond || -1 == cond);

            for (int i = 0; i < Size; ++i)
            {
                int z_i = z[zOff + i], diff = z_i ^ x[xOff + i];
                z_i ^= (diff & cond);
                z[zOff + i] = z_i;
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void CMov(int cond, ReadOnlySpan<int> x, Span<int> z)
        {
            Debug.Assert(0 == cond || -1 == cond);

            for (int i = 0; i < Size; ++i)
            {
                int z_i = z[i], diff = z_i ^ x[i];
                z_i ^= (diff & cond);
                z[i] = z_i;
            }
        }
#endif

        public static void CNegate(int negate, int[] z)
        {
            Debug.Assert(negate >> 1 == 0);

            int mask = 0 - negate;
            for (int i = 0; i < Size; ++i)
            {
                z[i] = (z[i] ^ mask) - mask;
            }
        }

        public static void Copy(int[] x, int xOff, int[] z, int zOff)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[zOff + i] = x[xOff + i];
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Copy(ReadOnlySpan<int> x, Span<int> z)
        {
            x[..Size].CopyTo(z);
        }
#endif

        public static int[] Create()
        {
            return new int[Size];
        }

        public static int[] CreateTable(int n)
        {
            return new int[Size * n];
        }

        public static void CSwap(int swap, int[] a, int[] b)
        {
            Debug.Assert(swap >> 1 == 0);
            Debug.Assert(a != b);

            int mask = 0 - swap;
            for (int i = 0; i < Size; ++i)
            {
                int ai = a[i], bi = b[i];
                int dummy = mask & (ai ^ bi);
                a[i] = ai ^ dummy; 
                b[i] = bi ^ dummy; 
            }
        }

        [CLSCompliant(false)]
        public static void Decode(uint[] x, int xOff, int[] z)
        {
            Decode128(x, xOff, z, 0);
            Decode128(x, xOff + 4, z, 5);
            z[9] &= M24;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [CLSCompliant(false)]
        public static void Decode(ReadOnlySpan<uint> x, Span<int> z)
        {
            Decode128(x, z);
            Decode128(x[4..], z[5..]);
            z[9] &= M24;
        }
#endif

        public static void Decode(byte[] x, int xOff, int[] z)
        {
            Decode128(x, xOff, z, 0);
            Decode128(x, xOff + 16, z, 5);
            z[9] &= M24;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Decode(ReadOnlySpan<byte> x, Span<int> z)
        {
            Decode128(x, z);
            Decode128(x[16..], z[5..]);
            z[9] &= M24;
        }
#endif

        private static void Decode128(uint[] x, int xOff, int[] z, int zOff)
        {
            uint t0 = x[xOff + 0], t1 = x[xOff + 1], t2 = x[xOff + 2], t3 = x[xOff + 3];

            z[zOff + 0] = (int)t0 & M26;
            z[zOff + 1] = (int)((t1 <<  6) | (t0 >> 26)) & M26;
            z[zOff + 2] = (int)((t2 << 12) | (t1 >> 20)) & M25;
            z[zOff + 3] = (int)((t3 << 19) | (t2 >> 13)) & M26;
            z[zOff + 4] = (int)(t3 >> 7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void Decode128(ReadOnlySpan<uint> x, Span<int> z)
        {
            uint t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3];

            z[0] = (int)t0 & M26;
            z[1] = (int)((t1 <<  6) | (t0 >> 26)) & M26;
            z[2] = (int)((t2 << 12) | (t1 >> 20)) & M25;
            z[3] = (int)((t3 << 19) | (t2 >> 13)) & M26;
            z[4] = (int)(t3 >> 7);
        }
#endif

        private static void Decode128(byte[] bs, int off, int[] z, int zOff)
        {
            uint t0 = Decode32(bs, off + 0);
            uint t1 = Decode32(bs, off + 4);
            uint t2 = Decode32(bs, off + 8);
            uint t3 = Decode32(bs, off + 12);

            z[zOff + 0] = (int)t0 & M26;
            z[zOff + 1] = (int)((t1 <<  6) | (t0 >> 26)) & M26;
            z[zOff + 2] = (int)((t2 << 12) | (t1 >> 20)) & M25;
            z[zOff + 3] = (int)((t3 << 19) | (t2 >> 13)) & M26;
            z[zOff + 4] = (int)(t3 >> 7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void Decode128(ReadOnlySpan<byte> bs, Span<int> z)
        {
            uint t0 = Decode32(bs);
            uint t1 = Decode32(bs[4..]);
            uint t2 = Decode32(bs[8..]);
            uint t3 = Decode32(bs[12..]);

            z[0] = (int)t0 & M26;
            z[1] = (int)((t1 <<  6) | (t0 >> 26)) & M26;
            z[2] = (int)((t2 << 12) | (t1 >> 20)) & M25;
            z[3] = (int)((t3 << 19) | (t2 >> 13)) & M26;
            z[4] = (int)(t3 >> 7);
        }
#endif

        private static uint Decode32(byte[] bs, int off)
        {
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 24;
            return n;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static uint Decode32(ReadOnlySpan<byte> bs)
        {
            uint n = bs[0];
            n |= (uint)bs[1] << 8;
            n |= (uint)bs[2] << 16;
            n |= (uint)bs[3] << 24;
            return n;
        }
#endif

        [CLSCompliant(false)]
        public static void Encode(int[] x, uint[] z, int zOff)
        {
            Encode128(x, 0, z, zOff);
            Encode128(x, 5, z, zOff + 4);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [CLSCompliant(false)]
        public static void Encode(ReadOnlySpan<int> x, Span<uint> z)
        {
            Encode128(x, z);
            Encode128(x[5..], z[4..]);
        }
#endif

        public static void Encode(int[] x, byte[] z, int zOff)
        {
            Encode128(x, 0, z, zOff);
            Encode128(x, 5, z, zOff + 16);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Encode(ReadOnlySpan<int> x, Span<byte> z)
        {
            Encode128(x, z);
            Encode128(x[5..], z[16..]);
        }
#endif

        private static void Encode128(int[] x, int xOff, uint[] z, int zOff)
        {
            uint x0 = (uint)x[xOff + 0], x1 = (uint)x[xOff + 1], x2 = (uint)x[xOff + 2], x3 = (uint)x[xOff + 3],
                x4 = (uint)x[xOff + 4];

            z[zOff + 0] =  x0        | (x1 << 26);
            z[zOff + 1] = (x1 >>  6) | (x2 << 20);
            z[zOff + 2] = (x2 >> 12) | (x3 << 13);
            z[zOff + 3] = (x3 >> 19) | (x4 <<  7);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void Encode128(ReadOnlySpan<int> x, Span<uint> z)
        {
            uint x0 = (uint)x[0], x1 = (uint)x[1], x2 = (uint)x[2], x3 = (uint)x[3], x4 = (uint)x[4];

            z[0] =  x0        | (x1 << 26);
            z[1] = (x1 >>  6) | (x2 << 20);
            z[2] = (x2 >> 12) | (x3 << 13);
            z[3] = (x3 >> 19) | (x4 <<  7);
        }
#endif

        private static void Encode128(int[] x, int xOff, byte[] bs, int off)
        {
            uint x0 = (uint)x[xOff + 0], x1 = (uint)x[xOff + 1], x2 = (uint)x[xOff + 2];
            uint x3 = (uint)x[xOff + 3], x4 = (uint)x[xOff + 4];

            uint t0 =  x0        | (x1 << 26);  Encode32(t0, bs, off + 0);
            uint t1 = (x1 >>  6) | (x2 << 20);  Encode32(t1, bs, off + 4);
            uint t2 = (x2 >> 12) | (x3 << 13);  Encode32(t2, bs, off + 8);
            uint t3 = (x3 >> 19) | (x4 <<  7);  Encode32(t3, bs, off + 12);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void Encode128(ReadOnlySpan<int> x, Span<byte> bs)
        {
            uint x0 = (uint)x[0], x1 = (uint)x[1], x2 = (uint)x[2];
            uint x3 = (uint)x[3], x4 = (uint)x[4];

            uint t0 =  x0        | (x1 << 26);  Encode32(t0, bs);
            uint t1 = (x1 >>  6) | (x2 << 20);  Encode32(t1, bs[4..]);
            uint t2 = (x2 >> 12) | (x3 << 13);  Encode32(t2, bs[8..]);
            uint t3 = (x3 >> 19) | (x4 <<  7);  Encode32(t3, bs[12..]);
        }
#endif

        private static void Encode32(uint n, byte[] bs, int off)
        {
            bs[  off] = (byte)(n      );
            bs[++off] = (byte)(n >>  8);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 24);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void Encode32(uint n, Span<byte> bs)
        {
            bs[0] = (byte)(n      );
            bs[1] = (byte)(n >>  8);
            bs[2] = (byte)(n >> 16);
            bs[3] = (byte)(n >> 24);
        }
#endif

        public static void Inv(int[] x, int[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Inv(x.AsSpan(), z.AsSpan());
#else
            //int[] x2 = Create();
            //int[] t = Create();
            //PowPm5d8(x, x2, t);
            //Sqr(t, 3, t);
            //Mul(t, x2, z);

            int[] t = Create();
            uint[] u = new uint[8];

            Copy(x, 0, t, 0);
            Normalize(t);
            Encode(t, u, 0);

            Mod.ModOddInverse(P32, u, u);

            Decode(u, 0, z);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Inv(ReadOnlySpan<int> x, Span<int> z)
        {
            Span<int> t = stackalloc int[Size];
            Span<uint> u = stackalloc uint[8];

            Copy(x, t);
            Normalize(t);
            Encode(t, u);

            Mod.ModOddInverse(P32, u, u);

            Decode(u, z);
        }
#endif

        public static void InvVar(int[] x, int[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            InvVar(x.AsSpan(), z.AsSpan());
#else
            int[] t = Create();
            uint[] u = new uint[8];

            Copy(x, 0, t, 0);
            Normalize(t);
            Encode(t, u, 0);

            Mod.ModOddInverseVar(P32, u, u);

            Decode(u, 0, z);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void InvVar(ReadOnlySpan<int> x, Span<int> z)
        {
            Span<int> t = stackalloc int[Size];
            Span<uint> u = stackalloc uint[8];

            Copy(x, t);
            Normalize(t);
            Encode(t, u);

            Mod.ModOddInverseVar(P32, u, u);

            Decode(u, z);
        }
#endif

        public static int IsOne(int[] x)
        {
            int d = x[0] ^ 1;
            for (int i = 1; i < Size; ++i)
            {
                d |= x[i];
            }
            d |= d >> 16;
            d &= 0xFFFF;
            return (d - 1) >> 31;
        }

        public static bool IsOneVar(int[] x)
        {
            return 0 != IsOne(x);
        }

        public static int IsZero(int[] x)
        {
            int d = 0;
            for (int i = 0; i < Size; ++i)
            {
                d |= x[i];
            }
            d |= d >> 16;
            d &= 0xFFFF;
            return (d - 1) >> 31;
        }

        public static bool IsZeroVar(int[] x)
        {
            return 0 != IsZero(x);
        }

        public static void Mul(int[] x, int y, int[] z)
        {
            int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4];
            int x5 = x[5], x6 = x[6], x7 = x[7], x8 = x[8], x9 = x[9];
            long c0, c1, c2, c3;

            c0  = (long)x2 * y; x2 = (int)c0 & M25; c0 >>= 25;
            c1  = (long)x4 * y; x4 = (int)c1 & M25; c1 >>= 25;
            c2  = (long)x7 * y; x7 = (int)c2 & M25; c2 >>= 25;
            //c3 = (long)x9 * y; x9 = (int)c3 & M24; c3 >>= 24;
            //c3 *= 19;
            c3  = (long)x9 * y; x9 = (int)c3 & M25; c3 >>= 25;
            c3 *= 38;

            c3 += (long)x0 * y; z[0] = (int)c3 & M26; c3 >>= 26;
            c1 += (long)x5 * y; z[5] = (int)c1 & M26; c1 >>= 26;

            c3 += (long)x1 * y; z[1] = (int)c3 & M26; c3 >>= 26;
            c0 += (long)x3 * y; z[3] = (int)c0 & M26; c0 >>= 26;
            c1 += (long)x6 * y; z[6] = (int)c1 & M26; c1 >>= 26;
            c2 += (long)x8 * y; z[8] = (int)c2 & M26; c2 >>= 26;

            z[2] = x2 + (int)c3;
            z[4] = x4 + (int)c0;
            z[7] = x7 + (int)c1;
            z[9] = x9 + (int)c2;
        }

        public static void Mul(int[] x, int[] y, int[] z)
        {
            int x0 = x[0], y0 = y[0];
            int x1 = x[1], y1 = y[1];
            int x2 = x[2], y2 = y[2];
            int x3 = x[3], y3 = y[3];
            int x4 = x[4], y4 = y[4];

            int u0 = x[5], v0 = y[5];
            int u1 = x[6], v1 = y[6];
            int u2 = x[7], v2 = y[7];
            int u3 = x[8], v3 = y[8];
            int u4 = x[9], v4 = y[9];

            long a0  = (long)x0 * y0;
            long a1  = (long)x0 * y1
                     + (long)x1 * y0;
            long a2  = (long)x0 * y2
                     + (long)x1 * y1
                     + (long)x2 * y0;
            long a3  = (long)x1 * y2
                     + (long)x2 * y1;
            a3     <<= 1;
            a3      += (long)x0 * y3
                     + (long)x3 * y0;
            long a4  = (long)x2 * y2;
            a4     <<= 1;
            a4      += (long)x0 * y4
                     + (long)x1 * y3
                     + (long)x3 * y1
                     + (long)x4 * y0;
            long a5  = (long)x1 * y4
                     + (long)x2 * y3
                     + (long)x3 * y2
                     + (long)x4 * y1;
            a5     <<= 1;
            long a6  = (long)x2 * y4
                     + (long)x4 * y2;
            a6     <<= 1;
            a6      += (long)x3 * y3;
            long a7  = (long)x3 * y4
                     + (long)x4 * y3;
            long a8  = (long)x4 * y4;
            a8     <<= 1;

            long b0  = (long)u0 * v0;
            long b1  = (long)u0 * v1
                     + (long)u1 * v0;
            long b2  = (long)u0 * v2
                     + (long)u1 * v1
                     + (long)u2 * v0;
            long b3  = (long)u1 * v2
                     + (long)u2 * v1;
            b3     <<= 1;
            b3      += (long)u0 * v3
                     + (long)u3 * v0;
            long b4  = (long)u2 * v2;
            b4     <<= 1;
            b4      += (long)u0 * v4
                     + (long)u1 * v3
                     + (long)u3 * v1
                     + (long)u4 * v0;
            long b5  = (long)u1 * v4
                     + (long)u2 * v3
                     + (long)u3 * v2
                     + (long)u4 * v1;
            //b5     <<= 1;
            long b6  = (long)u2 * v4
                     + (long)u4 * v2;
            b6     <<= 1;
            b6      += (long)u3 * v3;
            long b7  = (long)u3 * v4
                     + (long)u4 * v3;
            long b8  = (long)u4 * v4;
            //b8     <<= 1;

            a0 -= b5 * 76;
            a1 -= b6 * 38;
            a2 -= b7 * 38;
            a3 -= b8 * 76;

            a5 -= b0;
            a6 -= b1;
            a7 -= b2;
            a8 -= b3;
            //long a9 = -b4;

            x0 += u0; y0 += v0;
            x1 += u1; y1 += v1;
            x2 += u2; y2 += v2;
            x3 += u3; y3 += v3;
            x4 += u4; y4 += v4;

            long c0  = (long)x0 * y0;
            long c1  = (long)x0 * y1
                     + (long)x1 * y0;
            long c2  = (long)x0 * y2
                     + (long)x1 * y1
                     + (long)x2 * y0;
            long c3  = (long)x1 * y2
                     + (long)x2 * y1;
            c3     <<= 1;
            c3      += (long)x0 * y3
                     + (long)x3 * y0;
            long c4  = (long)x2 * y2;
            c4     <<= 1;
            c4      += (long)x0 * y4
                     + (long)x1 * y3
                     + (long)x3 * y1
                     + (long)x4 * y0;
            long c5  = (long)x1 * y4
                     + (long)x2 * y3
                     + (long)x3 * y2
                     + (long)x4 * y1;
            c5     <<= 1;
            long c6  = (long)x2 * y4
                     + (long)x4 * y2;
            c6     <<= 1;
            c6      += (long)x3 * y3;
            long c7  = (long)x3 * y4
                     + (long)x4 * y3;
            long c8  = (long)x4 * y4;
            c8     <<= 1;

            int z8, z9;
            long t;

            t        = a8 + (c3 - a3);
            z8       = (int)t & M26; t >>= 26;
            //t       += a9 + (c4 - a4);
            t       +=      (c4 - a4) - b4;
            //z9       = (int)t & M24; t >>= 24;
            //t        = a0 + (t + ((c5 - a5) << 1)) * 19;
            z9       = (int)t & M25; t >>= 25;
            t        = a0 + (t + c5 - a5) * 38;
            z[0]     = (int)t & M26; t >>= 26;
            t       += a1 + (c6 - a6) * 38;
            z[1]     = (int)t & M26; t >>= 26;
            t       += a2 + (c7 - a7) * 38;
            z[2]     = (int)t & M25; t >>= 25;
            t       += a3 + (c8 - a8) * 38;
            z[3]     = (int)t & M26; t >>= 26;
            //t       += a4 - a9 * 38;
            t       += a4 + b4 * 38;
            z[4]     = (int)t & M25; t >>= 25;
            t       += a5 + (c0 - a0);
            z[5]     = (int)t & M26; t >>= 26;
            t       += a6 + (c1 - a1);
            z[6]     = (int)t & M26; t >>= 26;
            t       += a7 + (c2 - a2);
            z[7]     = (int)t & M25; t >>= 25;
            t       += z8;
            z[8]     = (int)t & M26; t >>= 26;
            z[9]     = z9 + (int)t;
        }

        public static void Negate(int[] x, int[] z)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[i] = -x[i];
            }
        }

        public static void Normalize(int[] z)
        {
            int x = (z[9] >> 23) & 1;
            Reduce(z, x);
            Reduce(z, -x);
            Debug.Assert(z[9] >> 24 == 0);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Normalize(Span<int> z)
        {
            int x = (z[9] >> 23) & 1;
            Reduce(z, x);
            Reduce(z, -x);
            Debug.Assert(z[9] >> 24 == 0);
        }
#endif

        public static void One(int[] z)
        {
            z[0] = 1;
            for (int i = 1; i < Size; ++i)
            {
                z[i] = 0;
            }
        }

        private static void PowPm5d8(int[] x, int[] rx2, int[] rz)
        {
            // z = x^((p-5)/8) = x^FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
            // (250 1s) (1 0s) (1 1s)
            // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]

            int[] x2 = rx2;         Sqr(x, x2);             Mul(x, x2, x2);
            int[] x3 = Create();    Sqr(x2, x3);            Mul(x, x3, x3);
            int[] x5 = x3;          Sqr(x3, 2, x5);         Mul(x2, x5, x5);
            int[] x10 = Create();   Sqr(x5, 5, x10);        Mul(x5, x10, x10);
            int[] x15 = Create();   Sqr(x10, 5, x15);       Mul(x5, x15, x15);
            int[] x25 = x5;         Sqr(x15, 10, x25);      Mul(x10, x25, x25);
            int[] x50 = x10;        Sqr(x25, 25, x50);      Mul(x25, x50, x50);
            int[] x75 = x15;        Sqr(x50, 25, x75);      Mul(x25, x75, x75);
            int[] x125 = x25;       Sqr(x75, 50, x125);     Mul(x50, x125, x125);
            int[] x250 = x50;       Sqr(x125, 125, x250);   Mul(x125, x250, x250);

            int[] t = x125;
            Sqr(x250, 2, t);
            Mul(t, x, rz);
        }

        private static void Reduce(int[] z, int x)
        {
            int t = z[9], z9 = t & M24;
            t = (t >> 24) + x;

            long cc = t * 19;
            cc += z[0]; z[0] = (int)cc & M26; cc >>= 26;
            cc += z[1]; z[1] = (int)cc & M26; cc >>= 26;
            cc += z[2]; z[2] = (int)cc & M25; cc >>= 25;
            cc += z[3]; z[3] = (int)cc & M26; cc >>= 26;
            cc += z[4]; z[4] = (int)cc & M25; cc >>= 25;
            cc += z[5]; z[5] = (int)cc & M26; cc >>= 26;
            cc += z[6]; z[6] = (int)cc & M26; cc >>= 26;
            cc += z[7]; z[7] = (int)cc & M25; cc >>= 25;
            cc += z[8]; z[8] = (int)cc & M26; cc >>= 26;
            z[9] = z9 + (int)cc;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void Reduce(Span<int> z, int x)
        {
            int t = z[9], z9 = t & M24;
            t = (t >> 24) + x;

            long cc = t * 19;
            cc += z[0]; z[0] = (int)cc & M26; cc >>= 26;
            cc += z[1]; z[1] = (int)cc & M26; cc >>= 26;
            cc += z[2]; z[2] = (int)cc & M25; cc >>= 25;
            cc += z[3]; z[3] = (int)cc & M26; cc >>= 26;
            cc += z[4]; z[4] = (int)cc & M25; cc >>= 25;
            cc += z[5]; z[5] = (int)cc & M26; cc >>= 26;
            cc += z[6]; z[6] = (int)cc & M26; cc >>= 26;
            cc += z[7]; z[7] = (int)cc & M25; cc >>= 25;
            cc += z[8]; z[8] = (int)cc & M26; cc >>= 26;
            z[9] = z9 + (int)cc;
        }
#endif

        public static void Sqr(int[] x, int[] z)
        {
            int x0 = x[0];
            int x1 = x[1];
            int x2 = x[2];
            int x3 = x[3];
            int x4 = x[4];

            int u0 = x[5];
            int u1 = x[6];
            int u2 = x[7];
            int u3 = x[8];
            int u4 = x[9];

            int x1_2 = x1 * 2;
            int x2_2 = x2 * 2;
            int x3_2 = x3 * 2;
            int x4_2 = x4 * 2;

            long a0  = (long)x0 * x0;
            long a1  = (long)x0 * x1_2;
            long a2  = (long)x0 * x2_2
                     + (long)x1 * x1;
            long a3  = (long)x1_2 * x2_2
                     + (long)x0 * x3_2;
            long a4  = (long)x2 * x2_2
                     + (long)x0 * x4_2
                     + (long)x1 * x3_2;
            long a5  = (long)x1_2 * x4_2
                     + (long)x2_2 * x3_2;
            long a6  = (long)x2_2 * x4_2
                     + (long)x3 * x3;
            long a7  = (long)x3 * x4_2;
            long a8  = (long)x4 * x4_2;

            int u1_2 = u1 * 2;
            int u2_2 = u2 * 2;
            int u3_2 = u3 * 2;
            int u4_2 = u4 * 2;
        
            long b0  = (long)u0 * u0;
            long b1  = (long)u0 * u1_2;
            long b2  = (long)u0 * u2_2
                     + (long)u1 * u1;
            long b3  = (long)u1_2 * u2_2
                     + (long)u0 * u3_2;
            long b4  = (long)u2 * u2_2
                     + (long)u0 * u4_2
                     + (long)u1 * u3_2;
            long b5  = (long)u1_2 * u4_2
                     + (long)u2_2 * u3_2;
            long b6  = (long)u2_2 * u4_2
                     + (long)u3 * u3;
            long b7  = (long)u3 * u4_2;
            long b8  = (long)u4 * u4_2;

            a0 -= b5 * 38;
            a1 -= b6 * 38;
            a2 -= b7 * 38;
            a3 -= b8 * 38;

            a5 -= b0;
            a6 -= b1;
            a7 -= b2;
            a8 -= b3;
            //long a9 = -b4;

            x0 += u0;
            x1 += u1;
            x2 += u2;
            x3 += u3;
            x4 += u4;

            x1_2 = x1 * 2;
            x2_2 = x2 * 2;
            x3_2 = x3 * 2;
            x4_2 = x4 * 2;

            long c0  = (long)x0 * x0;
            long c1  = (long)x0 * x1_2;
            long c2  = (long)x0 * x2_2
                     + (long)x1 * x1;
            long c3  = (long)x1_2 * x2_2
                     + (long)x0 * x3_2;
            long c4  = (long)x2 * x2_2
                     + (long)x0 * x4_2
                     + (long)x1 * x3_2;
            long c5  = (long)x1_2 * x4_2
                     + (long)x2_2 * x3_2;
            long c6  = (long)x2_2 * x4_2
                     + (long)x3 * x3;
            long c7  = (long)x3 * x4_2;
            long c8  = (long)x4 * x4_2;

            int z8, z9;
            long t;

            t        = a8 + (c3 - a3);
            z8       = (int)t & M26; t >>= 26;
            //t       += a9 + (c4 - a4);
            t       +=      (c4 - a4) - b4;
            //z9       = (int)t & M24; t >>= 24;
            //t        = a0 + (t + ((c5 - a5) << 1)) * 19;
            z9       = (int)t & M25; t >>= 25;
            t        = a0 + (t + c5 - a5) * 38;
            z[0]     = (int)t & M26; t >>= 26;
            t       += a1 + (c6 - a6) * 38;
            z[1]     = (int)t & M26; t >>= 26;
            t       += a2 + (c7 - a7) * 38;
            z[2]     = (int)t & M25; t >>= 25;
            t       += a3 + (c8 - a8) * 38;
            z[3]     = (int)t & M26; t >>= 26;
            //t       += a4 - a9 * 38;
            t       += a4 + b4 * 38;
            z[4]     = (int)t & M25; t >>= 25;
            t       += a5 + (c0 - a0);
            z[5]     = (int)t & M26; t >>= 26;
            t       += a6 + (c1 - a1);
            z[6]     = (int)t & M26; t >>= 26;
            t       += a7 + (c2 - a2);
            z[7]     = (int)t & M25; t >>= 25;
            t       += z8;
            z[8]     = (int)t & M26; t >>= 26;
            z[9]     = z9 + (int)t;
        }

        public static void Sqr(int[] x, int n, int[] z)
        {
            Debug.Assert(n > 0);

            Sqr(x, z);

            while (--n > 0)
            {
                Sqr(z, z);
            }
        }

        public static bool SqrtRatioVar(int[] u, int[] v, int[] z)
        {
            int[] uv3 = Create();
            int[] uv7 = Create();

            Mul(u, v, uv3);
            Sqr(v, uv7);
            Mul(uv3, uv7, uv3);
            Sqr(uv7, uv7);
            Mul(uv7, uv3, uv7);

            int[] t = Create();
            int[] x = Create();
            PowPm5d8(uv7, t, x);
            Mul(x, uv3, x);

            int[] vx2 = Create();
            Sqr(x, vx2);
            Mul(vx2, v, vx2);

            Sub(vx2, u, t);
            Normalize(t);
            if (IsZeroVar(t))
            {
                Copy(x, 0, z, 0);
                return true;
            }

            Add(vx2, u, t);
            Normalize(t);
            if (IsZeroVar(t))
            {
                Mul(x, RootNegOne, z);
                return true;
            }

            return false;
        }

        public static void Sub(int[] x, int[] y, int[] z)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[i] = x[i] - y[i];
            }
        }

        public static void SubOne(int[] z)
        {
            z[0] -= 1;
        }

        public static void Zero(int[] z)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[i] = 0;
            }
        }

#if NET5_0_OR_GREATER

        public const int Size64 = 5;

        private const long M51 = 0x0007FFFFFFFFFFFFL;

        private static readonly long[] RootNegOne64 = { 0x00061B274A0EA0B0L, 0x0000D5A5FC8F189DL, 0x0007EF5E9CBD0C60L,
            0x00078595A6804C9EL, 0x0002B8324804FC1DL };

        public static void Add(ReadOnlySpan<long> x, ReadOnlySpan<long> y, Span<long> z)
        {
            for (int i = 0; i < Size64; ++i)
            {
                z[i] = x[i] + y[i];
            }
        }

        public static void AddOne(Span<long> z)
        {
            z[0] += 1L;
        }

        public static void Apm(ReadOnlySpan<long> x, ReadOnlySpan<long> y, Span<long> zp, Span<long> zm)
        {
            for (int i = 0; i < Size64; ++i)
            {
                long xi = x[i], yi = y[i];
                zp[i] = xi + yi;
                zm[i] = xi - yi;
            }
        }

        public static long AreEqual(ReadOnlySpan<long> x, ReadOnlySpan<long> y)
        {
            long d = 0;
            for (int i = 0; i < Size64; ++i)
            {
                d |= x[i] ^ y[i];
            }
            return (~d & (d - 1)) >> 63;
        }

        public static bool AreEqualVar(ReadOnlySpan<long> x, ReadOnlySpan<long> y)
        {
            return 0 != AreEqual(x, y);
        }

        public static void CMov(long cond, ReadOnlySpan<long> x, Span<long> z)
        {
            Debug.Assert(0L == cond || -1L == cond);

            for (int i = 0; i < Size64; ++i)
            {
                long z_i = z[i], diff = z_i ^ x[i];
                z_i ^= diff & cond;
                z[i] = z_i;
            }
        }

        public static void CNegate(long negate, Span<long> z)
        {
            Debug.Assert(negate >> 1 == 0L);

            long mask = 0L - negate;
            for (int i = 0; i < Size64; ++i)
            {
                z[i] = (z[i] ^ mask) - mask;
            }
        }

        public static void Copy(ReadOnlySpan<long> x, Span<long> z)
        {
            for (int i = 0; i < Size64; ++i)
            {
                z[i] = x[i];
            }
        }

        public static void CSwap(long swap, Span<long> a, Span<long> b)
        {
            Debug.Assert(swap >> 1 == 0);
            Debug.Assert(a != b);

            long mask = 0 - swap;
            for (int i = 0; i < Size64; ++i)
            {
                long ai = a[i], bi = b[i];
                long dummy = mask & (ai ^ bi);
                a[i] = ai ^ dummy;
                b[i] = bi ^ dummy;
            }
        }

        public static long IsOne(ReadOnlySpan<long> x)
        {
            long d = x[0] ^ 1L;
            for (int i = 1; i < Size64; ++i)
            {
                d |= x[i];
            }
            return (~d & (d - 1)) >> 63;
        }

        public static bool IsOneVar(ReadOnlySpan<long> x)
        {
            return 0 != IsOne(x);
        }

        public static long IsZero(ReadOnlySpan<long> x)
        {
            long d = x[0];
            for (int i = 1; i < Size64; ++i)
            {
                d |= x[i];
            }
            return (~d & (d - 1)) >> 63;
        }

        public static bool IsZeroVar(ReadOnlySpan<long> x)
        {
            return 0 != IsZero(x);
        }

        public static void Mul(ReadOnlySpan<long> x, ReadOnlySpan<long> y, Span<long> z)
        {
            long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4];
            long y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3], y4 = y[4];
            long z0, z1, z2, z3, z4, t5, t6, t7, t8, t9;

            long hi00 = BigMul(x0, y0, out long lo00);

            z0  = lo00 & M51;
            z1  = (hi00 << 13)
                + (lo00 >> 51);

            long hi01 = BigMul(x0, y1, out long lo01);
            long hi10 = BigMul(x1, y0, out long lo10);

            z1 += (lo01 & M51) + (lo10 & M51);
            z2  = ((hi01 + hi10) << 13)
                + (lo01 >> 51) + (lo10 >> 51);

            long hi02 = BigMul(x0, y2, out long lo02);
            long hi11 = BigMul(x1, y1, out long lo11);
            long hi20 = BigMul(x2, y0, out long lo20);

            z2 += (lo02 & M51) + (lo11 & M51) + (lo20 & M51);
            z3  = ((hi02 + hi11 + hi20) << 13)
                + (lo02 >> 51) + (lo11 >> 51) + (lo20 >> 51);

            long hi03 = BigMul(x0, y3, out long lo03);
            long hi12 = BigMul(x1, y2, out long lo12);
            long hi21 = BigMul(x2, y1, out long lo21);
            long hi30 = BigMul(x3, y0, out long lo30);

            z3 += (lo03 & M51) + (lo12 & M51) + (lo21 & M51) + (lo30 & M51);
            z4  = ((hi03 + hi12 + hi21 + hi30) << 13)
                + (lo03 >> 51) + (lo12 >> 51) + (lo21 >> 51) + (lo30 >> 51);

            long hi04 = BigMul(x0, y4, out long lo04);
            long hi13 = BigMul(x1, y3, out long lo13);
            long hi22 = BigMul(x2, y2, out long lo22);
            long hi31 = BigMul(x3, y1, out long lo31);
            long hi40 = BigMul(x4, y0, out long lo40);

            z4 += (lo04 & M51) + (lo13 & M51) + (lo22 & M51) + (lo31 & M51) + (lo40 & M51);
            t5  = ((hi04 + hi13 + hi22 + hi31 + hi40) << 13)
                + (lo04 >> 51) + (lo13 >> 51) + (lo22 >> 51) + (lo31 >> 51) + (lo40 >> 51);

            long hi14 = BigMul(x1, y4, out long lo14);
            long hi23 = BigMul(x2, y3, out long lo23);
            long hi32 = BigMul(x3, y2, out long lo32);
            long hi41 = BigMul(x4, y1, out long lo41);

            t5 += (lo14 & M51) + (lo23 & M51) + (lo32 & M51) + (lo41 & M51);
            t6  = ((hi14 + hi23 + hi32 + hi41) << 13)
                + (lo14 >> 51) + (lo23 >> 51) + (lo32 >> 51) + (lo41 >> 51);

            long hi24 = BigMul(x2, y4, out long lo24);
            long hi33 = BigMul(x3, y3, out long lo33);
            long hi42 = BigMul(x4, y2, out long lo42);

            t6 += (lo24 & M51) + (lo33 & M51) + (lo42 & M51);
            t7  = ((hi24 + hi33 + hi42) << 13)
                + (lo24 >> 51) + (lo33 >> 51) + (lo42 >> 51);

            long hi34 = BigMul(x3, y4, out long lo34);
            long hi43 = BigMul(x4, y3, out long lo43);

            t7 += (lo34 & M51) + (lo43 & M51);
            t8  = ((hi34 + hi43) << 13)
                + (lo34 >> 51) + (lo43 >> 51);

            long hi44 = BigMul(x4, y4, out long lo44);

            t8 += lo44 & M51;
            t9  = (hi44 << 13)
                + (lo44 >> 51);

            z3 += t8 * 19;
            z4 += t9 * 19;

            z4 += z3 >> 51; z3 &= M51;
            t5 += z4 >> 51; z4 &= M51;

            z0 += t5 * 19;
            z1 += t6 * 19;
            z2 += t7 * 19;

            z1 += z0 >> 51; z0 &= M51;
            z2 += z1 >> 51; z1 &= M51;
            z3 += z2 >> 51; z2 &= M51;
            z4 += z3 >> 51; z3 &= M51;

            z[0] = z0; z[1] = z1; z[2] = z2; z[3] = z3; z[4] = z4;
        }

        public static void Negate(ReadOnlySpan<long> x, Span<long> z)
        {
            for (int i = 0; i < Size64; ++i)
            {
                z[i] = -x[i];
            }
        }

        public static void Normalize(Span<long> z)
        {
            long x = (z[4] >> 50) & 1L;
            Reduce(z, x);
            Reduce(z, -x);
            Debug.Assert(z[4] >> 51 == 0);
        }

        public static void One(Span<long> z)
        {
            z[0] = 1L;
            for (int i = 1; i < Size64; ++i)
            {
                z[i] = 0L;
            }
        }

        private static void PowPm5d8(ReadOnlySpan<long> x, Span<long> rx2, Span<long> rz)
        {
            // z = x^((p-5)/8) = x^FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
            // (250 1s) (1 0s) (1 1s)
            // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]

            Span<long> x2 = rx2;                        Sqr(x, x2);             Mul(x, x2, x2);
            Span<long> x3 = stackalloc long[Size64];    Sqr(x2, x3);            Mul(x, x3, x3);
            Span<long> x5 = x3;                         Sqr(x3, 2, x5);         Mul(x2, x5, x5);
            Span<long> x10 = stackalloc long[Size64];   Sqr(x5, 5, x10);        Mul(x5, x10, x10);
            Span<long> x15 = stackalloc long[Size64];   Sqr(x10, 5, x15);       Mul(x5, x15, x15);
            Span<long> x25 = x5;                        Sqr(x15, 10, x25);      Mul(x10, x25, x25);
            Span<long> x50 = x10;                       Sqr(x25, 25, x50);      Mul(x25, x50, x50);
            Span<long> x75 = x15;                       Sqr(x50, 25, x75);      Mul(x25, x75, x75);
            Span<long> x125 = x25;                      Sqr(x75, 50, x125);     Mul(x50, x125, x125);
            Span<long> x250 = x50;                      Sqr(x125, 125, x250);   Mul(x125, x250, x250);

            Span<long> t = x125;
            Sqr(x250, 2, t);
            Mul(t, x, rz);
        }

        private static void Reduce(Span<long> z, long x)
        {
            long t = z[4], z4 = t & M51;
            t = (t >> 51) + x;

            long cc = t * 19;
            cc += z[0]; z[0] = cc & M51; cc >>= 51;
            cc += z[1]; z[1] = cc & M51; cc >>= 51;
            cc += z[2]; z[2] = cc & M51; cc >>= 51;
            cc += z[3]; z[3] = cc & M51; cc >>= 51;
            cc += z4  ; z[4] = cc;
        }

        public static void Sqr(ReadOnlySpan<long> x, Span<long> z)
        {
            Mul(x, x, z);
        }

        public static void Sqr(ReadOnlySpan<long> x, int n, Span<long> z)
        {
            Debug.Assert(n > 0);

            Sqr(x, z);

            while (--n > 0)
            {
                Sqr(z, z);
            }
        }

        public static bool SqrtRatioVar(ReadOnlySpan<long> u, ReadOnlySpan<long> v, Span<long> z)
        {
            Span<long> uv3 = stackalloc long[Size64];
            Span<long> uv7 = stackalloc long[Size64];

            Mul(u, v, uv3);
            Sqr(v, uv7);
            Mul(uv3, uv7, uv3);
            Sqr(uv7, uv7);
            Mul(uv7, uv3, uv7);

            Span<long> t = stackalloc long[Size64];
            Span<long> x = stackalloc long[Size64];
            PowPm5d8(uv7, t, x);
            Mul(x, uv3, x);

            Span<long> vx2 = stackalloc long[Size64];
            Sqr(x, vx2);
            Mul(vx2, v, vx2);

            Sub(vx2, u, t);
            Normalize(t);
            if (IsZeroVar(t))
            {
                Copy(x, z);
                return true;
            }

            Add(vx2, u, t);
            Normalize(t);
            if (IsZeroVar(t))
            {
                Mul(x, RootNegOne64, z);
                return true;
            }

            return false;
        }

        public static void Sub(ReadOnlySpan<long> x, ReadOnlySpan<long> y, Span<long> z)
        {
            for (int i = 0; i < Size64; ++i)
            {
                z[i] = x[i] - y[i];
            }
        }

        public static void SubOne(Span<long> z)
        {
            z[0] -= 1L;
        }

        public static void Zero(Span<long> z)
        {
            for (int i = 0; i < Size64; ++i)
            {
                z[i] = 0L;
            }
        }

#endif
    }
}
