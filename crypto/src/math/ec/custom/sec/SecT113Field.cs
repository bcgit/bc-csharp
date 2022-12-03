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
    internal static class SecT113Field
    {
        private const ulong M49 = ulong.MaxValue >> 15;
        private const ulong M57 = ulong.MaxValue >> 7;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Add(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void Add(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
            z[0] = x[0] ^ y[0];
            z[1] = x[1] ^ y[1];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddBothTo(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
#else
        public static void AddBothTo(ulong[] x, ulong[] y, ulong[] z)
#endif
        {
            z[0] ^= x[0] ^ y[0];
            z[1] ^= x[1] ^ y[1];
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
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddOne(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void AddOne(ulong[] x, ulong[] z)
#endif
        {
            z[0] = x[0] ^ 1UL;
            z[1] = x[1];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void AddTo(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void AddTo(ulong[] x, ulong[] z)
#endif
        {
            z[0] ^= x[0];
            z[1] ^= x[1];
        }

        public static ulong[] FromBigInteger(BigInteger x)
        {
            return Nat.FromBigInteger64(113, x);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void HalfTrace(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void HalfTrace(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[4];
#else
            ulong[] tt = Nat128.CreateExt64();
#endif

            Nat128.Copy64(x, z);
            for (int i = 1; i < 113; i += 2)
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
            if (Nat128.IsZero64(x))
                throw new InvalidOperationException();

            // Itoh-Tsujii inversion

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> t0 = stackalloc ulong[2];
            Span<ulong> t1 = stackalloc ulong[2];
#else
            ulong[] t0 = Nat128.Create64();
            ulong[] t1 = Nat128.Create64();
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
            SquareN(t1, 28, t0);
            Multiply(t0, t1, t0);
            SquareN(t0, 56, t1);
            Multiply(t1, t0, t1);
            Square(t1, z);
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
            ulong[] tt = new ulong[8];
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
            ulong[] tt = new ulong[8];
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
            ImplMultiply(x, y, zz);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Reduce(ReadOnlySpan<ulong> xx, Span<ulong> z)
#else
        public static void Reduce(ulong[] xx, ulong[] z)
#endif
        {
            ulong x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3];

            x1 ^= (x3 << 15) ^ (x3 << 24);
            x2 ^= (x3 >> 49) ^ (x3 >> 40);

            x0 ^= (x2 << 15) ^ (x2 << 24);
            x1 ^= (x2 >> 49) ^ (x2 >> 40);

            ulong t = x1 >> 49;
            z[0]    = x0 ^ t ^ (t << 9);
            z[1]    = x1 & M49;
        }

        public static void Reduce15(ulong[] z, int zOff)
        {
            ulong z1     = z[zOff + 1], t = z1 >> 49;
            z[zOff    ] ^= t ^ (t << 9);
            z[zOff + 1]  = z1 & M49;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Sqrt(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Sqrt(ulong[] x, ulong[] z)
#endif
        {
            ulong c0 = Interleave.Unshuffle(x[0], x[1], out ulong e0);

            z[0] = e0 ^ (c0 << 57) ^ (c0 <<  5);
            z[1] =      (c0 >>  7) ^ (c0 >> 59); 
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Square(ReadOnlySpan<ulong> x, Span<ulong> z)
#else
        public static void Square(ulong[] x, ulong[] z)
#endif
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<ulong> tt = stackalloc ulong[4];
#else
            ulong[] tt = Nat128.CreateExt64();
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
            Span<ulong> tt = stackalloc ulong[4];
#else
            ulong[] tt = Nat128.CreateExt64();
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
            Span<ulong> tt = stackalloc ulong[4];
#else
            ulong[] tt = Nat128.CreateExt64();
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
        private static void ImplMultiply(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Pclmulqdq.IsSupported && BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<ulong>>() == 16)
            {
                var X01 = Vector128.Create(x[0], x[1]);
                var Y01 = Vector128.Create(y[0], y[1]);

                var Z01 =          Pclmulqdq.CarrylessMultiply(X01, Y01, 0x00);
                var Z12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y01, 0x01),
                                   Pclmulqdq.CarrylessMultiply(X01, Y01, 0x10));
                var Z23 =          Pclmulqdq.CarrylessMultiply(X01, Y01, 0x11);

                Z01 = Sse2.Xor(Z01, Sse2.ShiftLeftLogical128BitLane(Z12, 8));
                Z23 = Sse2.Xor(Z23, Sse2.ShiftRightLogical128BitLane(Z12, 8));

                Span<byte> zzBytes = MemoryMarshal.AsBytes(zz);
                MemoryMarshal.Write(zzBytes[0x00..0x10], ref Z01);
                MemoryMarshal.Write(zzBytes[0x10..0x20], ref Z23);
                return;
            }
#endif

            /*
             * "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
             */

            ulong f0 = x[0], f1 = x[1];
            f1  = ((f0 >> 57) ^ (f1 << 7)) & M57;
            f0 &= M57;

            ulong g0 = y[0], g1 = y[1];
            g1  = ((g0 >> 57) ^ (g1 << 7)) & M57;
            g0 &= M57;

            Span<ulong> u = zz;
            Span<ulong> H = stackalloc ulong[6];

            ImplMulw(u, f0, g0, H[0..]);                // H(0)       57/56 bits                                
            ImplMulw(u, f1, g1, H[2..]);                // H(INF)     57/54 bits                                
            ImplMulw(u, f0 ^ f1, g0 ^ g1, H[4..]);      // H(1)       57/56 bits

            ulong r  = H[1] ^ H[2];
            ulong z0 = H[0],
                  z3 = H[3],
                  z1 = H[4] ^ z0 ^ r,
                  z2 = H[5] ^ z3 ^ r;

            zz[0] =  z0        ^ (z1 << 57);
            zz[1] = (z1 >>  7) ^ (z2 << 50);
            zz[2] = (z2 >> 14) ^ (z3 << 43);
            zz[3] = (z3 >> 21);
        }
#else
        private static void ImplMultiply(ulong[] x, ulong[] y, ulong[] zz)
        {
            /*
             * "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
             */

            ulong f0 = x[0], f1 = x[1];
            f1  = ((f0 >> 57) ^ (f1 << 7)) & M57;
            f0 &= M57;

            ulong g0 = y[0], g1 = y[1];
            g1  = ((g0 >> 57) ^ (g1 << 7)) & M57;
            g0 &= M57;

            ulong[] u = zz;
            ulong[] H = new ulong[6];

            ImplMulw(u, f0, g0, H, 0);              // H(0)       57/56 bits                                
            ImplMulw(u, f1, g1, H, 2);              // H(INF)     57/54 bits                                
            ImplMulw(u, f0 ^ f1, g0 ^ g1, H, 4);    // H(1)       57/56 bits

            ulong r  = H[1] ^ H[2];
            ulong z0 = H[0],
                  z3 = H[3],
                  z1 = H[4] ^ z0 ^ r,
                  z2 = H[5] ^ z3 ^ r;

            zz[0] =  z0        ^ (z1 << 57);
            zz[1] = (z1 >>  7) ^ (z2 << 50);
            zz[2] = (z2 >> 14) ^ (z3 << 43);
            zz[3] = (z3 >> 21);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void ImplMulw(Span<ulong> u, ulong x, ulong y, Span<ulong> z)
#else
        private static void ImplMulw(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
#endif
        {
            Debug.Assert(x >> 57 == 0);
            Debug.Assert(y >> 57 == 0);

            //u[0] = 0;
            u[1] = y;
            u[2] = u[1] << 1;
            u[3] = u[2] ^ y;
            u[4] = u[2] << 1;
            u[5] = u[4] ^ y;
            u[6] = u[3] << 1;
            u[7] = u[6] ^ y;

            uint j = (uint)x;
            ulong g, h = 0, l = u[(int)j & 7];
            int k = 48;
            do
            {
                j  = (uint)(x >> k);
                g  = u[(int)j & 7]
                   ^ u[(int)(j >> 3) & 7] << 3
                   ^ u[(int)(j >> 6) & 7] << 6;
                l ^= (g << k);
                h ^= (g >> -k);
            }
            while ((k -= 9) > 0);

            h ^= ((x & 0x0100804020100800UL) & (ulong)(((long)y << 7) >> 63)) >> 8;

            Debug.Assert(h >> 49 == 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            z[0] ^= l & M57;
            z[1] ^= (l >> 57) ^ (h << 7);
#else
            z[zOff    ] = l & M57;
            z[zOff + 1] = (l >> 57) ^ (h << 7);
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
                zz[3] = Bmi2.X64.ParallelBitDeposit(x[1] >> 32, 0x5555555555555555UL);
                zz[2] = Bmi2.X64.ParallelBitDeposit(x[1]      , 0x5555555555555555UL);
                zz[1] = Bmi2.X64.ParallelBitDeposit(x[0] >> 32, 0x5555555555555555UL);
                zz[0] = Bmi2.X64.ParallelBitDeposit(x[0]      , 0x5555555555555555UL);
                return;
            }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Interleave.Expand64To128(x[..2], zz[..4]);
#else
            Interleave.Expand64To128(x, 0, 2, zz, 0);
#endif
        }
    }
}
