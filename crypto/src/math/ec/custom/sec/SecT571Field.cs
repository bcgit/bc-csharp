using System;
using System.Diagnostics;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal static class SecT571Field
    {
        private const ulong M59 = ulong.MaxValue >> 5;

        private static readonly ulong[] ROOT_Z = new ulong[]{ 0x2BE1195F08CAFB99UL, 0x95F08CAF84657C23UL,
            0xCAF84657C232BE11UL, 0x657C232BE1195F08UL, 0xF84657C2308CAF84UL, 0x7C232BE1195F08CAUL,
            0xBE1195F08CAF8465UL, 0x5F08CAF84657C232UL, 0x784657C232BE119UL };

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Add(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void Add(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
            Nat.Xor64(9, x, y, z);
        }

        private static void Add(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            Nat.Xor64(9, x, xOff, y, yOff, z, zOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddBothTo(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void AddBothTo(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
            for (int i = 0; i < 9; ++i)
            {
                z[i] ^= x[i] ^ y[i];
            }
        }

        private static void AddBothTo(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            for (int i = 0; i < 9; ++i)
            {
                z[zOff + i] ^= x[xOff + i] ^ y[yOff + i];
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddExt(ReadOnlySpan<ulong> xx, ReadOnlySpan<ulong> yy, Span<ulong> zz)
#else
        public static void AddExt(ulong[] xx, ulong[] yy, ulong[] zz)
#endif
        {
            Nat.Xor64(18, xx, yy, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddOne(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void AddOne(ulong[] x, ulong[] z)
#endif
        {
            z[0] = x[0] ^ 1UL;
            for (int i = 1; i < 9; ++i)
            {
                z[i] = x[i];
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddTo(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void AddTo(ulong[] x, ulong[] z)
#endif
        {
            Nat.XorTo64(9, x, z);
        }

        public static ulong[] FromBigInteger(BigInteger x)
        {
            return Nat.FromBigInteger64(571, x);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void HalfTrace(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void HalfTrace(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif

            Nat576.Copy64(x, z);
            for (int i = 1; i < 571; i += 2)
            {
                ImplSquare(z, tt);
                Reduce(tt, z);
                ImplSquare(z, tt);
                Reduce(tt, z);
                AddTo(x, z);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Invert(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Invert(ulong[] x, ulong[] z)
#endif
        {
            if (Nat576.IsZero64(x))
                throw new InvalidOperationException();

            // Itoh-Tsujii inversion with bases { 2, 3, 5 }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> t0 = stackalloc ulong[9];
            Span<ulong> t1 = stackalloc ulong[9];
            Span<ulong> t2 = stackalloc ulong[9];
#else
            ulong[] t0 = Nat576.Create64();
            ulong[] t1 = Nat576.Create64();
            ulong[] t2 = Nat576.Create64();
#endif

            Square(x, t2);

            // 5 | 570
            Square(t2, t0);
            Square(t0, t1);
            Multiply(t0, t1, t0);
            SquareN(t0, 2, t1);
            Multiply(t0, t1, t0);
            Multiply(t0, t2, t0);

            // 3 | 114
            SquareN(t0, 5, t1);
            Multiply(t0, t1, t0);
            SquareN(t1, 5, t1);
            Multiply(t0, t1, t0);

            // 2 | 38
            SquareN(t0, 15, t1);
            Multiply(t0, t1, t2);

            // ! {2,3,5} | 19
            SquareN(t2, 30, t0);
            SquareN(t0, 30, t1);
            Multiply(t0, t1, t0);

            // 3 | 9
            SquareN(t0, 60, t1);
            Multiply(t0, t1, t0);
            SquareN(t1, 60, t1);
            Multiply(t0, t1, t0);

            // 3 | 3
            SquareN(t0, 180, t1);
            Multiply(t0, t1, t0);
            SquareN(t1, 180, t1);
            Multiply(t0, t1, t0);

            Multiply(t0, t2, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Multiply(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void Multiply(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplMultiply(x, y, tt);
            Reduce(tt, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void MultiplyAddToExt(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
#else
        public static void MultiplyAddToExt(ulong[] x, ulong[] y, ulong[] zz)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplMultiply(x, y, tt);
            AddExt(zz, tt, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void MultiplyExt(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
#else
        public static void MultiplyExt(ulong[] x, ulong[] y, ulong[] zz)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            zz[..18].Fill(0UL);
#else
            Array.Clear(zz, 0, 18);
#endif
            ImplMultiply(x, y, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void MultiplyPrecomp(ReadOnlySpan<ulong> x, ulong[] precomp, Span<ulong> z)
#else
        public static void MultiplyPrecomp(ulong[] x, ulong[] precomp, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplMultiplyPrecomp(x, precomp, tt);
            Reduce(tt, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void MultiplyPrecompAddToExt(ReadOnlySpan<ulong> x, ulong[] precomp, Span<ulong> zz)
#else
        public static void MultiplyPrecompAddToExt(ulong[] x, ulong[] precomp, ulong[] zz)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplMultiplyPrecomp(x, precomp, tt);
            AddExt(zz, tt, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ulong[] PrecompMultiplicand(ReadOnlySpan<ulong> x)
#else
        public static ulong[] PrecompMultiplicand(ulong[] x)
#endif
        {
#if NETCOREAPP3_0_OR_GREATER
            ulong[] z = Nat576.Create64();
            Nat576.Copy64(x, z);
            return z;
#else
            /*
             * Precompute table of all 4-bit products of x (first section)
             */
            int len = 9 << 4;
            ulong[] t = new ulong[len << 1];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            x[..9].CopyTo(t.AsSpan(9));
#else
            Array.Copy(x, 0, t, 9, 9);
#endif
            //Reduce5(t, 9);
            int tOff = 0;
            for (int i = 7; i > 0; --i)
            {
                tOff += 18;
                Nat.ShiftUpBit64(9, t, tOff >> 1, 0UL, t, tOff);
                Reduce5(t, tOff);
                Add(t, 9, t, tOff, t, tOff + 9);
            }

            /*
             * Second section with all 4-bit products of x shifted 4 bits
             */
            Nat.ShiftUpBits64(len, t, 0, 4, 0UL, t, len);

            return t;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Reduce(ReadOnlySpan<ulong> xx, Span<ulong> z)
#else
        public static void Reduce(ulong[] xx, ulong[] z)
#endif
        {
            ulong xx09 = xx[9];
            ulong u = xx[17], v = xx09;

            xx09  = v ^ (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
            v = xx[8] ^ (u <<  5) ^ (u <<  7) ^ (u << 10) ^ (u << 15);

            for (int i = 16; i >= 10; --i)
            {
                u = xx[i];
                z[i - 8]  = v ^ (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
                v = xx[i - 9] ^ (u <<  5) ^ (u <<  7) ^ (u << 10) ^ (u << 15);
            }

            u = xx09;
            z[1]  = v ^ (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
            v = xx[0] ^ (u <<  5) ^ (u <<  7) ^ (u << 10) ^ (u << 15);

            ulong x08 = z[8];
            ulong t   = x08 >> 59;
            z[0]      = v ^ t ^ (t << 2) ^ (t << 5) ^ (t << 10);
            z[8]      = x08 & M59;
        }

        public static void Reduce5(ulong[] z, int zOff)
        {
            ulong z8     = z[zOff + 8], t = z8 >> 59;
            z[zOff    ] ^= t ^ (t << 2) ^ (t << 5) ^ (t << 10);
            z[zOff + 8]  = z8 & M59;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Sqrt(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Sqrt(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> evn = stackalloc ulong[9], odd = stackalloc ulong[9];
#else
            ulong[] evn = Nat576.Create64(), odd = Nat576.Create64();
#endif

            odd[0] = Interleave.Unshuffle(x[0], x[1], out evn[0]);
            odd[1] = Interleave.Unshuffle(x[2], x[3], out evn[1]);
            odd[2] = Interleave.Unshuffle(x[4], x[5], out evn[2]);
            odd[3] = Interleave.Unshuffle(x[6], x[7], out evn[3]);
            odd[4] = Interleave.Unshuffle(x[8]      , out evn[4]);

            Multiply(odd, ROOT_Z, z);
            Add(z, evn, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Square(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Square(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplSquare(x, tt);
            Reduce(tt, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void SquareAddToExt(ReadOnlySpan<ulong> x, Span<ulong> zz)
#else
        public static void SquareAddToExt(ulong[] x, ulong[] zz)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplSquare(x, tt);
            AddExt(zz, tt, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void SquareExt(ReadOnlySpan<ulong> x, Span<ulong> zz)
#else
        public static void SquareExt(ulong[] x, ulong[] zz)
#endif
        {
            ImplSquare(x, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void SquareN(ReadOnlySpan<ulong> x, int n, Span<ulong> z)
#else
        public static void SquareN(ulong[] x, int n, ulong[] z)
#endif
        {
            Debug.Assert(n > 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[18];
#else
            ulong[] tt = Nat576.CreateExt64();
#endif
            ImplSquare(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                ImplSquare(z, tt);
                Reduce(tt, z);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Trace(ReadOnlySpan<ulong> x)
#else
        public static uint Trace(ulong[] x)
#endif
        {
            // Non-zero-trace bits: 0, 561, 569
            return (uint)(x[0] ^ (x[8] >> 49) ^ (x[8] >> 57)) & 1U;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMultiply(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            //ulong[] precomp = PrecompMultiplicand(y);

            //ImplMultiplyPrecomp(x, precomp, zz);

            ulong[] u = new ulong[16];
            for (int i = 0; i < 9; ++i)
            {
                ImplMulwAcc(u, x[i], y[i], zz[(i << 1)..]);
            }

            ulong v0 = zz[0], v1 = zz[1];
            v0 ^= zz[ 2]; zz[1] = v0 ^ v1; v1 ^= zz[ 3];
            v0 ^= zz[ 4]; zz[2] = v0 ^ v1; v1 ^= zz[ 5];
            v0 ^= zz[ 6]; zz[3] = v0 ^ v1; v1 ^= zz[ 7];
            v0 ^= zz[ 8]; zz[4] = v0 ^ v1; v1 ^= zz[ 9];
            v0 ^= zz[10]; zz[5] = v0 ^ v1; v1 ^= zz[11];
            v0 ^= zz[12]; zz[6] = v0 ^ v1; v1 ^= zz[13];
            v0 ^= zz[14]; zz[7] = v0 ^ v1; v1 ^= zz[15];
            v0 ^= zz[16]; zz[8] = v0 ^ v1; v1 ^= zz[17];

            ulong w = v0 ^ v1;
            zz[ 9] = zz[0] ^ w;
            zz[10] = zz[1] ^ w;
            zz[11] = zz[2] ^ w;
            zz[12] = zz[3] ^ w;
            zz[13] = zz[4] ^ w;
            zz[14] = zz[5] ^ w;
            zz[15] = zz[6] ^ w;
            zz[16] = zz[7] ^ w;
            zz[17] = zz[8] ^ w;

            ImplMulwAcc(u, x[0] ^ x[1], y[0] ^ y[1], zz[ 1..]);

            ImplMulwAcc(u, x[0] ^ x[2], y[0] ^ y[2], zz[ 2..]);

            ImplMulwAcc(u, x[0] ^ x[3], y[0] ^ y[3], zz[ 3..]);
            ImplMulwAcc(u, x[1] ^ x[2], y[1] ^ y[2], zz[ 3..]);

            ImplMulwAcc(u, x[0] ^ x[4], y[0] ^ y[4], zz[ 4..]);
            ImplMulwAcc(u, x[1] ^ x[3], y[1] ^ y[3], zz[ 4..]);

            ImplMulwAcc(u, x[0] ^ x[5], y[0] ^ y[5], zz[ 5..]);
            ImplMulwAcc(u, x[1] ^ x[4], y[1] ^ y[4], zz[ 5..]);
            ImplMulwAcc(u, x[2] ^ x[3], y[2] ^ y[3], zz[ 5..]);

            ImplMulwAcc(u, x[0] ^ x[6], y[0] ^ y[6], zz[ 6..]);
            ImplMulwAcc(u, x[1] ^ x[5], y[1] ^ y[5], zz[ 6..]);
            ImplMulwAcc(u, x[2] ^ x[4], y[2] ^ y[4], zz[ 6..]);

            ImplMulwAcc(u, x[0] ^ x[7], y[0] ^ y[7], zz[ 7..]);
            ImplMulwAcc(u, x[1] ^ x[6], y[1] ^ y[6], zz[ 7..]);
            ImplMulwAcc(u, x[2] ^ x[5], y[2] ^ y[5], zz[ 7..]);
            ImplMulwAcc(u, x[3] ^ x[4], y[3] ^ y[4], zz[ 7..]);

            ImplMulwAcc(u, x[0] ^ x[8], y[0] ^ y[8], zz[ 8..]);
            ImplMulwAcc(u, x[1] ^ x[7], y[1] ^ y[7], zz[ 8..]);
            ImplMulwAcc(u, x[2] ^ x[6], y[2] ^ y[6], zz[ 8..]);
            ImplMulwAcc(u, x[3] ^ x[5], y[3] ^ y[5], zz[ 8..]);

            ImplMulwAcc(u, x[1] ^ x[8], y[1] ^ y[8], zz[ 9..]);
            ImplMulwAcc(u, x[2] ^ x[7], y[2] ^ y[7], zz[ 9..]);
            ImplMulwAcc(u, x[3] ^ x[6], y[3] ^ y[6], zz[ 9..]);
            ImplMulwAcc(u, x[4] ^ x[5], y[4] ^ y[5], zz[ 9..]);

            ImplMulwAcc(u, x[2] ^ x[8], y[2] ^ y[8], zz[10..]);
            ImplMulwAcc(u, x[3] ^ x[7], y[3] ^ y[7], zz[10..]);
            ImplMulwAcc(u, x[4] ^ x[6], y[4] ^ y[6], zz[10..]);

            ImplMulwAcc(u, x[3] ^ x[8], y[3] ^ y[8], zz[11..]);
            ImplMulwAcc(u, x[4] ^ x[7], y[4] ^ y[7], zz[11..]);
            ImplMulwAcc(u, x[5] ^ x[6], y[5] ^ y[6], zz[11..]);

            ImplMulwAcc(u, x[4] ^ x[8], y[4] ^ y[8], zz[12..]);
            ImplMulwAcc(u, x[5] ^ x[7], y[5] ^ y[7], zz[12..]);

            ImplMulwAcc(u, x[5] ^ x[8], y[5] ^ y[8], zz[13..]);
            ImplMulwAcc(u, x[6] ^ x[7], y[6] ^ y[7], zz[13..]);

            ImplMulwAcc(u, x[6] ^ x[8], y[6] ^ y[8], zz[14..]);

            ImplMulwAcc(u, x[7] ^ x[8], y[7] ^ y[8], zz[15..]);
        }
#else
        private static void ImplMultiply(ulong[] x, ulong[] y, ulong[] zz)
        {
            //ulong[] precomp = PrecompMultiplicand(y);

            //ImplMultiplyPrecomp(x, precomp, zz);

            ulong[] u = new ulong[16];
            for (int i = 0; i < 9; ++i)
            {
                ImplMulwAcc(u, x[i], y[i], zz, i << 1);
            }

            ulong v0 = zz[0], v1 = zz[1];
            v0 ^= zz[ 2]; zz[1] = v0 ^ v1; v1 ^= zz[ 3];
            v0 ^= zz[ 4]; zz[2] = v0 ^ v1; v1 ^= zz[ 5];
            v0 ^= zz[ 6]; zz[3] = v0 ^ v1; v1 ^= zz[ 7];
            v0 ^= zz[ 8]; zz[4] = v0 ^ v1; v1 ^= zz[ 9];
            v0 ^= zz[10]; zz[5] = v0 ^ v1; v1 ^= zz[11];
            v0 ^= zz[12]; zz[6] = v0 ^ v1; v1 ^= zz[13];
            v0 ^= zz[14]; zz[7] = v0 ^ v1; v1 ^= zz[15];
            v0 ^= zz[16]; zz[8] = v0 ^ v1; v1 ^= zz[17];

            ulong w = v0 ^ v1;
            zz[ 9] = zz[0] ^ w;
            zz[10] = zz[1] ^ w;
            zz[11] = zz[2] ^ w;
            zz[12] = zz[3] ^ w;
            zz[13] = zz[4] ^ w;
            zz[14] = zz[5] ^ w;
            zz[15] = zz[6] ^ w;
            zz[16] = zz[7] ^ w;
            zz[17] = zz[8] ^ w;

            ImplMulwAcc(u, x[0] ^ x[1], y[0] ^ y[1], zz, 1);

            ImplMulwAcc(u, x[0] ^ x[2], y[0] ^ y[2], zz, 2);

            ImplMulwAcc(u, x[0] ^ x[3], y[0] ^ y[3], zz, 3);
            ImplMulwAcc(u, x[1] ^ x[2], y[1] ^ y[2], zz, 3);

            ImplMulwAcc(u, x[0] ^ x[4], y[0] ^ y[4], zz, 4);
            ImplMulwAcc(u, x[1] ^ x[3], y[1] ^ y[3], zz, 4);

            ImplMulwAcc(u, x[0] ^ x[5], y[0] ^ y[5], zz, 5);
            ImplMulwAcc(u, x[1] ^ x[4], y[1] ^ y[4], zz, 5);
            ImplMulwAcc(u, x[2] ^ x[3], y[2] ^ y[3], zz, 5);

            ImplMulwAcc(u, x[0] ^ x[6], y[0] ^ y[6], zz, 6);
            ImplMulwAcc(u, x[1] ^ x[5], y[1] ^ y[5], zz, 6);
            ImplMulwAcc(u, x[2] ^ x[4], y[2] ^ y[4], zz, 6);

            ImplMulwAcc(u, x[0] ^ x[7], y[0] ^ y[7], zz, 7);
            ImplMulwAcc(u, x[1] ^ x[6], y[1] ^ y[6], zz, 7);
            ImplMulwAcc(u, x[2] ^ x[5], y[2] ^ y[5], zz, 7);
            ImplMulwAcc(u, x[3] ^ x[4], y[3] ^ y[4], zz, 7);

            ImplMulwAcc(u, x[0] ^ x[8], y[0] ^ y[8], zz, 8);
            ImplMulwAcc(u, x[1] ^ x[7], y[1] ^ y[7], zz, 8);
            ImplMulwAcc(u, x[2] ^ x[6], y[2] ^ y[6], zz, 8);
            ImplMulwAcc(u, x[3] ^ x[5], y[3] ^ y[5], zz, 8);

            ImplMulwAcc(u, x[1] ^ x[8], y[1] ^ y[8], zz, 9);
            ImplMulwAcc(u, x[2] ^ x[7], y[2] ^ y[7], zz, 9);
            ImplMulwAcc(u, x[3] ^ x[6], y[3] ^ y[6], zz, 9);
            ImplMulwAcc(u, x[4] ^ x[5], y[4] ^ y[5], zz, 9);

            ImplMulwAcc(u, x[2] ^ x[8], y[2] ^ y[8], zz, 10);
            ImplMulwAcc(u, x[3] ^ x[7], y[3] ^ y[7], zz, 10);
            ImplMulwAcc(u, x[4] ^ x[6], y[4] ^ y[6], zz, 10);

            ImplMulwAcc(u, x[3] ^ x[8], y[3] ^ y[8], zz, 11);
            ImplMulwAcc(u, x[4] ^ x[7], y[4] ^ y[7], zz, 11);
            ImplMulwAcc(u, x[5] ^ x[6], y[5] ^ y[6], zz, 11);

            ImplMulwAcc(u, x[4] ^ x[8], y[4] ^ y[8], zz, 12);
            ImplMulwAcc(u, x[5] ^ x[7], y[5] ^ y[7], zz, 12);

            ImplMulwAcc(u, x[5] ^ x[8], y[5] ^ y[8], zz, 13);
            ImplMulwAcc(u, x[6] ^ x[7], y[6] ^ y[7], zz, 13);

            ImplMulwAcc(u, x[6] ^ x[8], y[6] ^ y[8], zz, 14);

            ImplMulwAcc(u, x[7] ^ x[8], y[7] ^ y[8], zz, 15);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMultiplyPrecomp(ReadOnlySpan<ulong> x, ulong[] precomp, Span<ulong> zz)
#else
        private static void ImplMultiplyPrecomp(ulong[] x, ulong[] precomp, ulong[] zz)
#endif
        {
#if NETCOREAPP3_0_OR_GREATER
            ImplMultiply(x, precomp, zz);
#else
            uint MASK = 0xF;

            /*
             * Lopez-Dahab algorithm
             */

            for (int k = 56; k >= 0; k -= 8)
            {
                for (int j = 1; j < 9; j += 2)
                {
                    uint aVal = (uint)(x[j] >> k);
                    uint u = aVal & MASK;
                    uint v = (aVal >> 4) & MASK;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    AddBothTo(precomp.AsSpan((int)(9 * u)), precomp.AsSpan((int)(9 * (v + 16))), zz[(j - 1)..]);
#else
                    AddBothTo(precomp, (int)(9 * u), precomp, (int)(9 * (v + 16)), zz, j - 1);
#endif
                }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Nat.ShiftUpBits64(16, zz, 8, 0UL);
#else
                Nat.ShiftUpBits64(16, zz, 0, 8, 0UL);
#endif
            }

            for (int k = 56; k >= 0; k -= 8)
            {
                for (int j = 0; j < 9; j += 2)
                {
                    uint aVal = (uint)(x[j] >> k);
                    uint u = aVal & MASK;
                    uint v = (aVal >> 4) & MASK;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    AddBothTo(precomp.AsSpan((int)(9 * u)), precomp.AsSpan((int)(9 * (v + 16))), zz[j..]);
#else
                    AddBothTo(precomp, (int)(9 * u), precomp, (int)(9 * (v + 16)), zz, j);
#endif
                }
                if (k > 0)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Nat.ShiftUpBits64(18, zz, 8, 0UL);
#else
                    Nat.ShiftUpBits64(18, zz, 0, 8, 0UL);
#endif
                }
            }
#endif
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMulwAcc(Span<ulong> u, ulong x, ulong y, Span<ulong> z)
#else
        private static void ImplMulwAcc(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
#endif
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Pclmulqdq.IsSupported)
            {
                var X = Vector128.CreateScalar(x);
                var Y = Vector128.CreateScalar(y);
                var Z = Pclmulqdq.CarrylessMultiply(X, Y, 0x00);
                z[0] ^= Z.GetElement(0);
                z[1] ^= Z.GetElement(1);
                return;
            }
#endif

            //u[0] = 0;
            u[1] = y;
            for (int i = 2; i < 16; i += 2)
            {
                u[i    ] = u[i >> 1] << 1;
                u[i + 1] = u[i     ] ^  y;
            }

            uint j = (uint)x;
            ulong g, h = 0, l = u[(int)j & 15]
                              ^ u[(int)(j >> 4) & 15] << 4;
            int k = 56;
            do
            {
                j  = (uint)(x >> k);
                g  = u[(int)j & 15]
                   ^ u[(int)(j >> 4) & 15] << 4;
                l ^= (g << k);
                h ^= (g >> -k);
            }
            while ((k -= 8) > 0);

            for (int p = 0; p < 7; ++p)
            {
                x = (x & 0xFEFEFEFEFEFEFEFEUL) >> 1;
                h ^= x & (ulong)((long)(y << p) >> 63);
            }

            Debug.Assert(h >> 63 == 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            z[0] ^= l;
            z[1] ^= h;
#else
            z[zOff    ] ^= l;
            z[zOff + 1] ^= h;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplSquare(ReadOnlySpan<ulong> x, Span<ulong> zz)
#else
        private static void ImplSquare(ulong[] x, ulong[] zz)
#endif
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                zz[17] = Bmi2.X64.ParallelBitDeposit(x[8] >> 32, 0x5555555555555555UL);
                zz[16] = Bmi2.X64.ParallelBitDeposit(x[8]      , 0x5555555555555555UL);
                zz[15] = Bmi2.X64.ParallelBitDeposit(x[7] >> 32, 0x5555555555555555UL);
                zz[14] = Bmi2.X64.ParallelBitDeposit(x[7]      , 0x5555555555555555UL);
                zz[13] = Bmi2.X64.ParallelBitDeposit(x[6] >> 32, 0x5555555555555555UL);
                zz[12] = Bmi2.X64.ParallelBitDeposit(x[6]      , 0x5555555555555555UL);
                zz[11] = Bmi2.X64.ParallelBitDeposit(x[5] >> 32, 0x5555555555555555UL);
                zz[10] = Bmi2.X64.ParallelBitDeposit(x[5]      , 0x5555555555555555UL);
                zz[ 9] = Bmi2.X64.ParallelBitDeposit(x[4] >> 32, 0x5555555555555555UL);
                zz[ 8] = Bmi2.X64.ParallelBitDeposit(x[4]      , 0x5555555555555555UL);
                zz[ 7] = Bmi2.X64.ParallelBitDeposit(x[3] >> 32, 0x5555555555555555UL);
                zz[ 6] = Bmi2.X64.ParallelBitDeposit(x[3]      , 0x5555555555555555UL);
                zz[ 5] = Bmi2.X64.ParallelBitDeposit(x[2] >> 32, 0x5555555555555555UL);
                zz[ 4] = Bmi2.X64.ParallelBitDeposit(x[2]      , 0x5555555555555555UL);
                zz[ 3] = Bmi2.X64.ParallelBitDeposit(x[1] >> 32, 0x5555555555555555UL);
                zz[ 2] = Bmi2.X64.ParallelBitDeposit(x[1]      , 0x5555555555555555UL);
                zz[ 1] = Bmi2.X64.ParallelBitDeposit(x[0] >> 32, 0x5555555555555555UL);
                zz[ 0] = Bmi2.X64.ParallelBitDeposit(x[0]      , 0x5555555555555555UL);
                return;
            }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Interleave.Expand64To128(x[..9], zz[..18]);
#else
            Interleave.Expand64To128(x, 0, 9, zz, 0);
#endif
        }
    }
}
