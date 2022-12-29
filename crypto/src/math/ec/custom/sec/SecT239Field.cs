using System;
using System.Diagnostics;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal static class SecT239Field
    {
        private const ulong M47 = ulong.MaxValue >> 17;
        private const ulong M60 = ulong.MaxValue >> 4;

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
            zz[7] = xx[7] ^ yy[7];
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
            return Nat.FromBigInteger64(239, x);
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
            for (int i = 1; i < 239; i += 2)
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

            // Itoh-Tsujii inversion

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> t0 = stackalloc ulong[4];
            Span<ulong> t1 = stackalloc ulong[4];
#else
            ulong[] t0 = Nat256.Create64();
            ulong[] t1 = Nat256.Create64();
#endif

            Square(x, t0);
            Multiply(t0, x, t0);
            Square(t0, t0);
            Multiply(t0, x, t0);
            SquareN(t0, 3, t1);
            Multiply(t1, t0, t1);
            Square(t1, t1);
            Multiply(t1, x, t1);
            SquareN(t1, 7, t0);
            Multiply(t0, t1, t0);
            SquareN(t0, 14, t1);
            Multiply(t1, t0, t1);
            Square(t1, t1);
            Multiply(t1, x, t1);
            SquareN(t1, 29, t0);
            Multiply(t0, t1, t0);
            Square(t0, t0);
            Multiply(t0, x, t0);
            SquareN(t0, 59, t1);
            Multiply(t1, t0, t1);
            Square(t1, t1);
            Multiply(t1, x, t1);
            SquareN(t1, 119, t0);
            Multiply(t0, t1, t0);
            Square(t0, z);
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
            ulong x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3];
            ulong x4 = xx[4], x5 = xx[5], x6 = xx[6], x7 = xx[7];

            x3 ^= (x7 << 17);
            x4 ^= (x7 >> 47);
            x5 ^= (x7 << 47);
            x6 ^= (x7 >> 17);

            x2 ^= (x6 << 17);
            x3 ^= (x6 >> 47);
            x4 ^= (x6 << 47);
            x5 ^= (x6 >> 17);

            x1 ^= (x5 << 17);
            x2 ^= (x5 >> 47);
            x3 ^= (x5 << 47);
            x4 ^= (x5 >> 17);

            x0 ^= (x4 << 17);
            x1 ^= (x4 >> 47);
            x2 ^= (x4 << 47);
            x3 ^= (x4 >> 17);

            ulong t = x3 >> 47;
            z[0]    = x0 ^ t;
            z[1]    = x1;
            z[2]    = x2 ^ (t << 30);
            z[3]    = x3 & M47;
        }

        public static void Reduce17(ulong[] z, int zOff)
        {
            ulong z3     = z[zOff + 3], t = z3 >> 47;
            z[zOff    ] ^= t;
            z[zOff + 2] ^= (t << 30);
            z[zOff + 3]  = z3 & M47;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Sqrt(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Sqrt(ulong[] x, ulong[] z)
#endif
        {
            ulong c0 = Interleave.Unshuffle(x[0], x[1], out ulong e0);
            ulong c1 = Interleave.Unshuffle(x[2], x[3], out ulong e1);

            ulong c2, c3;
            c3  = (c1 >> 49);
            c2  = (c0 >> 49) | (c1 << 15);
            c1 ^=              (c0 << 15);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[8];
            Span<int> shifts = stackalloc int[] { 39, 120 };
#else
            ulong[] tt = Nat256.CreateExt64();
            int[] shifts = { 39, 120 };
#endif

            for (int i = 0; i < shifts.Length; ++i)
            {
                int w = shifts[i] >> 6, s = shifts[i] & 63;
                Debug.Assert(s != 0);
                tt[w    ] ^= (c0 << s);
                tt[w + 1] ^= (c1 << s) | (c0 >> -s);
                tt[w + 2] ^= (c2 << s) | (c1 >> -s);
                tt[w + 3] ^= (c3 << s) | (c2 >> -s);
                tt[w + 4] ^=             (c3 >> -s);
            }

            Reduce(tt, z);

            z[0] ^= e0;
            z[1] ^= e1;
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
            // Non-zero-trace bits: 0, 81, 162
            return (uint)(x[0] ^ (x[1] >> 17) ^ (x[2] >> 34)) & 1U;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplCompactExt(Span<ulong> zz)
#else
        private static void ImplCompactExt(ulong[] zz)
#endif
        {
            ulong z0 = zz[0], z1 = zz[1], z2 = zz[2], z3 = zz[3], z4 = zz[4], z5 = zz[5], z6 = zz[6], z7 = zz[7];
            zz[0] =  z0        ^ (z1 << 60);
            zz[1] = (z1 >>  4) ^ (z2 << 56);
            zz[2] = (z2 >>  8) ^ (z3 << 52);
            zz[3] = (z3 >> 12) ^ (z4 << 48);
            zz[4] = (z4 >> 16) ^ (z5 << 44);
            zz[5] = (z5 >> 20) ^ (z6 << 40);
            zz[6] = (z6 >> 24) ^ (z7 << 36);
            zz[7] = (z7 >> 28);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplExpand(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        private static void ImplExpand(ulong[] x, ulong[] z)
#endif
        {
            ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
            z[0] = x0 & M60;
            z[1] = ((x0 >> 60) ^ (x1 <<  4)) & M60;
            z[2] = ((x1 >> 56) ^ (x2 <<  8)) & M60;
            z[3] = ((x2 >> 52) ^ (x3 << 12));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMultiply(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Pclmulqdq.IsSupported && BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<ulong>>() == 16)
            {
                var X01 = Vector128.Create(x[0], x[1]);
                var X23 = Vector128.Create(x[2], x[3]);
                var Y01 = Vector128.Create(y[0], y[1]);
                var Y23 = Vector128.Create(y[2], y[3]);
                var X03 = Sse2.Xor(X01, X23);
                var Y03 = Sse2.Xor(Y01, Y23);

                var Z01 =          Pclmulqdq.CarrylessMultiply(X01, Y01, 0x00);
                var Z12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y01, 0x01),
                                   Pclmulqdq.CarrylessMultiply(X01, Y01, 0x10));
                var Z23 =          Pclmulqdq.CarrylessMultiply(X01, Y01, 0x11);

                Z01 = Sse2.Xor(Z01, Sse2.ShiftLeftLogical128BitLane (Z12, 8));
                Z23 = Sse2.Xor(Z23, Sse2.ShiftRightLogical128BitLane(Z12, 8));

                var Z45 =          Pclmulqdq.CarrylessMultiply(X23, Y23, 0x00);
                var Z56 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X23, Y23, 0x01),
                                   Pclmulqdq.CarrylessMultiply(X23, Y23, 0x10));
                var Z67 =          Pclmulqdq.CarrylessMultiply(X23, Y23, 0x11);

                Z45 = Sse2.Xor(Z45, Sse2.ShiftLeftLogical128BitLane (Z56, 8));
                Z67 = Sse2.Xor(Z67, Sse2.ShiftRightLogical128BitLane(Z56, 8));

                var K01 =          Pclmulqdq.CarrylessMultiply(X03, Y03, 0x00);
                var K12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X03, Y03, 0x01),
                                   Pclmulqdq.CarrylessMultiply(X03, Y03, 0x10));
                var K23 =          Pclmulqdq.CarrylessMultiply(X03, Y03, 0x11);

                var T = Sse2.Xor(Z23, Z45);

                Z23 = Sse2.Xor(T, Z01);
                Z45 = Sse2.Xor(T, Z67);

                Z23 = Sse2.Xor(Z23, K01);
                Z23 = Sse2.Xor(Z23, Sse2.ShiftLeftLogical128BitLane (K12, 8));
                Z45 = Sse2.Xor(Z45, Sse2.ShiftRightLogical128BitLane(K12, 8));
                Z45 = Sse2.Xor(Z45, K23);

                Span<byte> zzBytes = MemoryMarshal.AsBytes(zz);
                MemoryMarshal.Write(zzBytes[0x00..0x10], ref Z01);
                MemoryMarshal.Write(zzBytes[0x10..0x20], ref Z23);
                MemoryMarshal.Write(zzBytes[0x20..0x30], ref Z45);
                MemoryMarshal.Write(zzBytes[0x30..0x40], ref Z67);
                return;
            }
#endif

            /*
             * "Two-level seven-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
             */

            Span<ulong> f = stackalloc ulong[4], g = stackalloc ulong[4];
            ImplExpand(x, f);
            ImplExpand(y, g);

            Span<ulong> u = stackalloc ulong[8];

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
            Debug.Assert(x >> 60 == 0);
            Debug.Assert(y >> 60 == 0);

            //u[0] = 0;
            u[1] = y;
            u[2] = u[1] << 1;
            u[3] = u[2] ^  y;
            u[4] = u[2] << 1;
            u[5] = u[4] ^  y;
            u[6] = u[3] << 1;
            u[7] = u[6] ^  y;

            uint j = (uint)x;
            ulong g, h = 0, l = u[(int)j & 7]
                              ^ (u[(int)(j >> 3) & 7] << 3);
            int k = 54;
            do
            {
                j  = (uint)(x >> k);
                g  = u[(int)j & 7]
                   ^ u[(int)(j >> 3) & 7] << 3;
                l ^= (g <<  k);
                h ^= (g >> -k);
            }
            while ((k -= 6) > 0);

            h ^= ((x & 0x0820820820820820L) & (ulong)(((long)y << 4) >> 63)) >> 5;

            Debug.Assert(h >> 55 == 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            z[0] ^= l & M60;
            z[1] ^= (l >> 60) ^ (h << 4);
#else
            z[zOff    ] ^= l & M60;
            z[zOff + 1] ^= (l >> 60) ^ (h << 4);
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
                ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
                zz[7] = Bmi2.X64.ParallelBitDeposit(x3 >> 32, 0x5555555555555555UL);
                zz[6] = Bmi2.X64.ParallelBitDeposit(x3      , 0x5555555555555555UL);
                zz[5] = Bmi2.X64.ParallelBitDeposit(x2 >> 32, 0x5555555555555555UL);
                zz[4] = Bmi2.X64.ParallelBitDeposit(x2      , 0x5555555555555555UL);
                zz[3] = Bmi2.X64.ParallelBitDeposit(x1 >> 32, 0x5555555555555555UL);
                zz[2] = Bmi2.X64.ParallelBitDeposit(x1      , 0x5555555555555555UL);
                zz[1] = Bmi2.X64.ParallelBitDeposit(x0 >> 32, 0x5555555555555555UL);
                zz[0] = Bmi2.X64.ParallelBitDeposit(x0      , 0x5555555555555555UL);
                return;
            }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Interleave.Expand64To128(x[..4], zz[..8]);
#else
            Interleave.Expand64To128(x, 0, 4, zz, 0);
#endif
        }
    }
}
