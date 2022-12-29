using System;
using System.Diagnostics;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal static class SecT193Field
    {
        private const ulong M01 = 1UL;
        private const ulong M49 = ulong.MaxValue >> 15;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Add(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void Add(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
            z[0] = x[0] ^ y[0];
            z[1] = x[1] ^ y[1];
            z[2] = x[2] ^ y[2];
            z[3] = x[3] ^ y[3];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddBothTo(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void AddBothTo(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
            z[0] ^= x[0] ^ y[0];
            z[1] ^= x[1] ^ y[1];
            z[2] ^= x[2] ^ y[2];
            z[3] ^= x[3] ^ y[3];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddExt(ReadOnlySpan<ulong> xx, ReadOnlySpan<ulong> yy, Span<ulong> zz)
#else
        public static void AddExt(ulong[] xx, ulong[] yy, ulong[] zz)
#endif
        {
            zz[0] = xx[0] ^ yy[0];
            zz[1] = xx[1] ^ yy[1];
            zz[2] = xx[2] ^ yy[2];
            zz[3] = xx[3] ^ yy[3];
            zz[4] = xx[4] ^ yy[4];
            zz[5] = xx[5] ^ yy[5];
            zz[6] = xx[6] ^ yy[6];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddOne(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void AddOne(ulong[] x, ulong[] z)
#endif
        {
            z[0] = x[0] ^ 1UL;
            z[1] = x[1];
            z[2] = x[2];
            z[3] = x[3];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddTo(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void AddTo(ulong[] x, ulong[] z)
#endif
        {
            z[0] ^= x[0];
            z[1] ^= x[1];
            z[2] ^= x[2];
            z[3] ^= x[3];
        }

        public static ulong[] FromBigInteger(BigInteger x)
        {
            return Nat.FromBigInteger64(193, x);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void HalfTrace(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void HalfTrace(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[8];
#else
            ulong[] tt = Nat256.CreateExt64();
#endif

            Nat256.Copy64(x, z);
            for (int i = 1; i < 193; i += 2)
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
            if (Nat256.IsZero64(x))
                throw new InvalidOperationException();

            // Itoh-Tsujii inversion with bases { 2, 3 }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> t0 = stackalloc ulong[4];
            Span<ulong> t1 = stackalloc ulong[4];
#else
            ulong[] t0 = Nat256.Create64();
            ulong[] t1 = Nat256.Create64();
#endif

            Square(x, t0);

            // 3 | 192
            SquareN(t0, 1, t1);
            Multiply(t0, t1, t0);
            SquareN(t1, 1, t1);
            Multiply(t0, t1, t0);

            // 2 | 64
            SquareN(t0, 3, t1);
            Multiply(t0, t1, t0);

            // 2 | 32
            SquareN(t0, 6, t1);
            Multiply(t0, t1, t0);

            // 2 | 16
            SquareN(t0, 12, t1);
            Multiply(t0, t1, t0);

            // 2 | 8
            SquareN(t0, 24, t1);
            Multiply(t0, t1, t0);

            // 2 | 4
            SquareN(t0, 48, t1);
            Multiply(t0, t1, t0);

            // 2 | 2
            SquareN(t0, 96, t1);
            Multiply(t0, t1, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Multiply(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void Multiply(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[8];
#else
            ulong[] tt = Nat256.CreateExt64();
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
            Span<ulong> tt = stackalloc ulong[8];
#else
            ulong[] tt = Nat256.CreateExt64();
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
            zz[..8].Fill(0UL);
#else
            Array.Clear(zz, 0, 8);
#endif
            ImplMultiply(x, y, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Reduce(ReadOnlySpan<ulong> xx, Span<ulong> z)
#else
        public static void Reduce(ulong[] xx, ulong[] z)
#endif
        {
            ulong x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3], x4 = xx[4], x5 = xx[5], x6 = xx[6];

            x2 ^= (x6 << 63);
            x3 ^= (x6 >>  1) ^ (x6 << 14);
            x4 ^= (x6 >> 50);

            x1 ^= (x5 << 63);
            x2 ^= (x5 >>  1) ^ (x5 << 14);
            x3 ^= (x5 >> 50);

            x0 ^= (x4 << 63);
            x1 ^= (x4 >>  1) ^ (x4 << 14);
            x2 ^= (x4 >> 50);

            ulong t = x3 >> 1;
            z[0]    = x0 ^ t ^ (t << 15);
            z[1]    = x1     ^ (t >> 49);
            z[2]    = x2;
            z[3]    = x3 & M01;
        }

        public static void Reduce63(ulong[] z, int zOff)
        {
            ulong z3     = z[zOff + 3], t = z3 >> 1;
            z[zOff    ] ^= t ^ (t << 15);
            z[zOff + 1] ^=     (t >> 49);
            z[zOff + 3]  = z3 & M01;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Sqrt(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Sqrt(ulong[] x, ulong[] z)
#endif
        {
            ulong c0 = Interleave.Unshuffle(x[0], x[1], out ulong e0);
            ulong c1 = Interleave.Unshuffle(x[2]      , out ulong e1);
            e1 ^= x[3] << 32;

            z[0] = e0 ^ (c0 << 8);
            z[1] = e1 ^ (c1 << 8) ^ (c0 >> 56) ^ (c0 << 33);
            z[2] =                  (c1 >> 56) ^ (c1 << 33) ^ (c0 >> 31);
            z[3] =                                            (c1 >> 31);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Square(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Square(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[8];
#else
            ulong[] tt = Nat256.CreateExt64();
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
            Span<ulong> tt = stackalloc ulong[8];
#else
            ulong[] tt = Nat256.CreateExt64();
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
            Span<ulong> tt = stackalloc ulong[8];
#else
            ulong[] tt = Nat256.CreateExt64();
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
            // Non-zero-trace bits: 0
            return (uint)(x[0]) & 1U;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplCompactExt(Span<ulong> zz)
#else
        private static void ImplCompactExt(ulong[] zz)
#endif
        {
            ulong z0 = zz[0], z1 = zz[1], z2 = zz[2], z3 = zz[3], z4 = zz[4], z5 = zz[5], z6 = zz[6], z7 = zz[7];
            zz[0] =  z0        ^ (z1 << 49);
            zz[1] = (z1 >> 15) ^ (z2 << 34);
            zz[2] = (z2 >> 30) ^ (z3 << 19);
            zz[3] = (z3 >> 45) ^ (z4 <<  4)
                               ^ (z5 << 53);
            zz[4] = (z4 >> 60) ^ (z6 << 38)
                  ^ (z5 >> 11);
            zz[5] = (z6 >> 26) ^ (z7 << 23);
            zz[6] = (z7 >> 41);
            zz[7] = 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplExpand(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        private static void ImplExpand(ulong[] x, ulong[] z)
#endif
        {
            ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
            z[0] = x0 & M49;
            z[1] = ((x0 >> 49) ^ (x1 << 15)) & M49;
            z[2] = ((x1 >> 34) ^ (x2 << 30)) & M49;
            z[3] = ((x2 >> 19) ^ (x3 << 45));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMultiply(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Pclmulqdq.IsSupported)
            {
                var X01 = Vector128.Create(x[0], x[1]);
                var X2_ = Vector128.CreateScalar(x[2]);
                var Y01 = Vector128.Create(y[0], y[1]);
                var Y2_ = Vector128.CreateScalar(y[2]);

                var Z01 =          Pclmulqdq.CarrylessMultiply(X01, Y01, 0x00);
                var Z12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y01, 0x01),
                                   Pclmulqdq.CarrylessMultiply(X01, Y01, 0x10));
                var Z23 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y2_, 0x00),
                          Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y01, 0x11),
                                   Pclmulqdq.CarrylessMultiply(X2_, Y01, 0x00)));
                var Z34 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y2_, 0x01),
                                   Pclmulqdq.CarrylessMultiply(X2_, Y01, 0x10));
                var Z45 =          Pclmulqdq.CarrylessMultiply(X2_, Y2_, 0x00);

                ulong X3M = 0UL - x[3];
                ulong Y3M = 0UL - y[3];

                zz[0] = Z01.GetElement(0);
                zz[1] = Z01.GetElement(1) ^ Z12.GetElement(0);
                zz[2] = Z23.GetElement(0) ^ Z12.GetElement(1);
                zz[3] = Z23.GetElement(1) ^ Z34.GetElement(0) ^ (X3M & y[0]) ^ (x[0] & Y3M);
                zz[4] = Z45.GetElement(0) ^ Z34.GetElement(1) ^ (X3M & y[1]) ^ (x[1] & Y3M);
                zz[5] = Z45.GetElement(1)                     ^ (X3M & y[2]) ^ (x[2] & Y3M);
                zz[6] =                                          X3M & y[3];
                return;
            }
#endif

            /*
             * "Two-level seven-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
             */

            ulong[] f = new ulong[4], g = new ulong[4];
            ImplExpand(x, f);
            ImplExpand(y, g);

            ulong[] u = new ulong[8];

            ImplMulwAcc(u, f[0], g[0], zz[0..]);
            ImplMulwAcc(u, f[1], g[1], zz[1..]);
            ImplMulwAcc(u, f[2], g[2], zz[2..]);
            ImplMulwAcc(u, f[3], g[3], zz[3..]);

            // U *= (1 - t^n)
            for (int i = 5; i > 0; --i)
            {
                zz[i] ^= zz[i - 1];
            }

            ImplMulwAcc(u, f[0] ^ f[1], g[0] ^ g[1], zz[1..]);
            ImplMulwAcc(u, f[2] ^ f[3], g[2] ^ g[3], zz[3..]);

            // V *= (1 - t^2n)
            for (int i = 7; i > 1; --i)
            {
                zz[i] ^= zz[i - 2];
            }

            // Double-length recursion
            {
                ulong c0 = f[0] ^ f[2], c1 = f[1] ^ f[3];
                ulong d0 = g[0] ^ g[2], d1 = g[1] ^ g[3];
                ImplMulwAcc(u, c0 ^ c1, d0 ^ d1, zz[3..]);
                Span<ulong> t = stackalloc ulong[3];
                ImplMulwAcc(u, c0, d0, t[0..]);
                ImplMulwAcc(u, c1, d1, t[1..]);
                ulong t0 = t[0], t1 = t[1], t2 = t[2];
                zz[2] ^= t0;
                zz[3] ^= t0 ^ t1;
                zz[4] ^= t2 ^ t1;
                zz[5] ^= t2;
            }

            ImplCompactExt(zz);
        }
#else
        private static void ImplMultiply(ulong[] x, ulong[] y, ulong[] zz)
        {
            /*
             * "Two-level seven-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
             */

            ulong[] f = new ulong[4], g = new ulong[4];
            ImplExpand(x, f);
            ImplExpand(y, g);

            ulong[] u = new ulong[8];

            ImplMulwAcc(u, f[0], g[0], zz, 0);
            ImplMulwAcc(u, f[1], g[1], zz, 1);
            ImplMulwAcc(u, f[2], g[2], zz, 2);
            ImplMulwAcc(u, f[3], g[3], zz, 3);

            // U *= (1 - t^n)
            for (int i = 5; i > 0; --i)
            {
                zz[i] ^= zz[i - 1];
            }

            ImplMulwAcc(u, f[0] ^ f[1], g[0] ^ g[1], zz, 1);
            ImplMulwAcc(u, f[2] ^ f[3], g[2] ^ g[3], zz, 3);

            // V *= (1 - t^2n)
            for (int i = 7; i > 1; --i)
            {
                zz[i] ^= zz[i - 2];
            }

            // Double-length recursion
            {
                ulong c0 = f[0] ^ f[2], c1 = f[1] ^ f[3];
                ulong d0 = g[0] ^ g[2], d1 = g[1] ^ g[3];
                ImplMulwAcc(u, c0 ^ c1, d0 ^ d1, zz, 3);
                ulong[] t = new ulong[3];
                ImplMulwAcc(u, c0, d0, t, 0);
                ImplMulwAcc(u, c1, d1, t, 1);
                ulong t0 = t[0], t1 = t[1], t2 = t[2];
                zz[2] ^= t0;
                zz[3] ^= t0 ^ t1;
                zz[4] ^= t2 ^ t1;
                zz[5] ^= t2;
            }

            ImplCompactExt(zz);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMulwAcc(Span<ulong> u, ulong x, ulong y, Span<ulong> z)
#else
        private static void ImplMulwAcc(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
#endif
        {
            Debug.Assert(x >> 49 == 0);
            Debug.Assert(y >> 49 == 0);

            //u[0] = 0;
            u[1] = y;
            u[2] = u[1] << 1;
            u[3] = u[2] ^  y;
            u[4] = u[2] << 1;
            u[5] = u[4] ^  y;
            u[6] = u[3] << 1;
            u[7] = u[6] ^ y;

            uint j = (uint)x;
            ulong g, h = 0, l = u[(int)j & 7]
                              ^ (u[(int)(j >> 3) & 7] << 3);
            int k = 36;
            do
            {
                j  = (uint)(x >> k);
                g  = u[(int)j & 7]
                   ^ u[(int)(j >> 3) & 7] << 3
                   ^ u[(int)(j >> 6) & 7] << 6
                   ^ u[(int)(j >> 9) & 7] << 9
                   ^ u[(int)(j >> 12) & 7] << 12;
                l ^= (g <<  k);
                h ^= (g >> -k);
            }
            while ((k -= 15) > 0);

            Debug.Assert(h >> 33 == 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            z[0] ^= l & M49;
            z[1] ^= (l >> 49) ^ (h << 15);
#else
            z[zOff    ] ^= l & M49;
            z[zOff + 1] ^= (l >> 49) ^ (h << 15);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplSquare(ReadOnlySpan<ulong> x, Span<ulong> zz)
#else
        private static void ImplSquare(ulong[] x, ulong[] zz)
#endif
        {
            zz[6] = x[3] & M01;

#if NETCOREAPP3_0_OR_GREATER
            if (Bmi2.X64.IsSupported)
            {
                zz[5] = Bmi2.X64.ParallelBitDeposit(x[2] >> 32, 0x5555555555555555UL);
                zz[4] = Bmi2.X64.ParallelBitDeposit(x[2]      , 0x5555555555555555UL);
                zz[3] = Bmi2.X64.ParallelBitDeposit(x[1] >> 32, 0x5555555555555555UL);
                zz[2] = Bmi2.X64.ParallelBitDeposit(x[1]      , 0x5555555555555555UL);
                zz[1] = Bmi2.X64.ParallelBitDeposit(x[0] >> 32, 0x5555555555555555UL);
                zz[0] = Bmi2.X64.ParallelBitDeposit(x[0]      , 0x5555555555555555UL);
                return;
            }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Interleave.Expand64To128(x[..3], zz[..6]);
#else
            Interleave.Expand64To128(x, 0, 3, zz, 0);
#endif
        }
    }
}
