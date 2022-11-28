using System;
using System.Collections.Generic;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal sealed class BikeRing
    {
        private const int PermutationCutoff = 64;

        private readonly int m_bits;
        private readonly int m_size;
        private readonly int m_sizeExt;
        private readonly Dictionary<int, int> m_halfPowers = new Dictionary<int, int>();

        internal BikeRing(int r)
        {
            if ((r & 0xFFFF0001) != 1)
                throw new ArgumentException();

            m_bits = r;
            m_size = (r + 63) >> 6;
            m_sizeExt = m_size * 2;

            foreach (int n in EnumerateSquarePowersInv(r))
            {
                if (n >= PermutationCutoff && !m_halfPowers.ContainsKey(n))
                {
                    m_halfPowers[n] = GenerateHalfPower(r, n);
                }
            }
        }

        internal void Add(ulong[] x, ulong[] y, ulong[] z)
        {
            Nat.Xor64(Size, x, y, z);
        }

        internal void AddTo(ulong[] x, ulong[] z)
        {
            Nat.XorTo64(Size, x, z);
        }

        internal void Copy(ulong[] x, ulong[] z)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[i] = x[i];
            }
        }

        internal ulong[] Create()
        {
            return new ulong[Size];
        }

        internal ulong[] CreateExt()
        {
            return new ulong[SizeExt];
        }

        internal void DecodeBytes(byte[] bs, ulong[] z)
        {
            int partialBits = m_bits & 63;
            Pack.LE_To_UInt64(bs, 0, z, 0, Size - 1);
            byte[] last = new byte[8];
            Array.Copy(bs, (Size - 1) << 3, last, 0, (partialBits + 7) >> 3);
            z[Size - 1] = Pack.LE_To_UInt64(last);
            Debug.Assert((z[Size - 1] >> partialBits) == 0UL);
        }

        internal byte[] EncodeBits(ulong[] x)
        {
            byte[] bs = new byte[m_bits];
            for (int i = 0; i < m_bits; ++i)
            {
                bs[i] = (byte)((x[i >> 6] >> (i & 63)) & 1UL);
            }
            return bs;
        }

        internal void EncodeBytes(ulong[] x, byte[] bs)
        {
            int partialBits = m_bits & 63;
            Debug.Assert((x[Size - 1] >> partialBits) == 0UL);
            Pack.UInt64_To_LE(x, 0, Size - 1, bs, 0);
            byte[] last = new byte[8];
            Pack.UInt64_To_LE(x[Size - 1], last);
            Array.Copy(last, 0, bs, (Size - 1) << 3, (partialBits + 7) >> 3);
        }
        
        internal void Inv(ulong[] a, ulong[] z)
        {
            ulong[] f = Create();
            ulong[] g = Create();
            ulong[] t = Create();

            Copy(a, f);
            Copy(a, t);

            int rSub2 = m_bits - 2;
            int bits = 32 - Integers.NumberOfLeadingZeros(rSub2);

            for (int i = 1; i < bits; ++i)
            {
                SquareN(f, 1 << (i - 1), g);
                Multiply(f, g, f);

                if ((rSub2 & (1 << i)) != 0)
                {
                    int n = rSub2 & ((1 << i) - 1);
                    SquareN(f, n, g);
                    Multiply(t, g, t);
                }
            }

            Square(t, z);
        }

        internal void Multiply(ulong[] x, ulong[] y, ulong[] z)
        {
            ulong[] tt = CreateExt();
            ImplMultiplyAcc(x, y, tt);
            Reduce(tt, z);
        }

        internal void Reduce(ulong[] tt, ulong[] z)
        {
            int partialBits = m_bits & 63;
            int excessBits = 64 - partialBits;
            ulong partialMask = ulong.MaxValue >> excessBits;

            ulong c = Nat.ShiftUpBits64(Size, tt, Size, excessBits, tt[Size - 1], z, 0);
            Debug.Assert(c == 0UL);
            AddTo(tt, z);
            z[Size - 1] &= partialMask;
        }

        internal int Size => m_size;

        internal int SizeExt => m_sizeExt;

        internal void Square(ulong[] x, ulong[] z)
        {
            ulong[] tt = CreateExt();
            ImplSquare(x, tt);
            Reduce(tt, z);
        }

        internal void SquareN(ulong[] x, int n, ulong[] z)
        {
            Debug.Assert(n > 0);

            /*
             * In these polynomial rings, 'SquareN' for some 'n' is equivalent to a fixed permutation of the
             * coefficients. Calls to 'Inv' generate calls to 'SquareN' with a predictable sequence of 'n' values.
             * For such 'n' above some cutoff value, we precalculate a small constant and then apply the permutation in
             * place of explicit squaring for that 'n'.
             */
            if (n >= PermutationCutoff)
            {
                ImplPermute(x, n, z);
                return;
            }

            ulong[] tt = CreateExt();
            ImplSquare(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                ImplSquare(z, tt);
                Reduce(tt, z);
            }
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static int ImplModAdd(int m, int x, int y)
        {
            int t = x + y - m;
            return t + ((t >> 31) & m);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static int ImplModHalf(int m, int x)
        {
            int t = -(x & 1);
            return (x + (m & t)) >> 1;
        }

        private void ImplMultiplyAcc(ulong[] x, ulong[] y, ulong[] zz)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Pclmulqdq.IsSupported)
            {
                int i = 0, limit = Size - 2;
                while (i <= limit)
                {
                    var X01 = Vector128.Create(x[i], x[i + 1]);

                    int j = 0;
                    while (j <= limit)
                    {
                        var Y01 = Vector128.Create(y[j], y[j + 1]);

                        var Z01 = Pclmulqdq.CarrylessMultiply(X01, Y01, 0x00);
                        var Z12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y01, 0x01),
                                           Pclmulqdq.CarrylessMultiply(X01, Y01, 0x10));
                        var Z23 = Pclmulqdq.CarrylessMultiply(X01, Y01, 0x11);

                        zz[i + j + 0] ^= Z01.GetElement(0);
                        zz[i + j + 1] ^= Z01.GetElement(1) ^ Z12.GetElement(0);
                        zz[i + j + 2] ^= Z23.GetElement(0) ^ Z12.GetElement(1);
                        zz[i + j + 3] ^= Z23.GetElement(1);

                        j += 2;
                    }

                    i += 2;
                }
                if (i < Size)
                {
                    var Xi = Vector128.CreateScalar(x[i]);
                    var Yi = Vector128.CreateScalar(y[i]);

                    for (int j = 0; j < i; ++j)
                    {
                        var Xj = Vector128.CreateScalar(x[j]);
                        var Yj = Vector128.CreateScalar(y[j]);

                        var Z = Sse2.Xor(Pclmulqdq.CarrylessMultiply(Xi, Yj, 0x00),
                                         Pclmulqdq.CarrylessMultiply(Yi, Xj, 0x00));

                        zz[i + j + 0] ^= Z.GetElement(0);
                        zz[i + j + 1] ^= Z.GetElement(1);
                    }

                    {
                        var Z = Pclmulqdq.CarrylessMultiply(Xi, Yi, 0x00);

                        zz[i + i + 0] ^= Z.GetElement(0);
                        zz[i + i + 1] ^= Z.GetElement(1);

                    }
                }
                return;
            }
#endif

            ulong[] u = new ulong[16];

            // Schoolbook

            //for (int i = 0; i < Size; ++i)
            //{
            //    ulong x_i = x[i];

            //    for (int j = 0; j < Size; ++j)
            //    {
            //        ulong y_j = y[j];

            //        ImplMulwAcc(u, x_i, y_j, zz, i + j);
            //    }
            //}

            // Arbitrary-degree Karatsuba

            for (int i = 0; i < Size; ++i)
            {
                ImplMulwAcc(u, x[i], y[i], zz, i << 1);
            }

            ulong v0 = zz[0], v1 = zz[1];
            for (int i = 1; i < Size; ++i)
            {
                v0 ^= zz[i << 1]; zz[i] = v0 ^ v1; v1 ^= zz[(i << 1) + 1];
            }

            ulong w = v0 ^ v1;
            Nat.Xor64(Size, zz, 0, w, zz, Size);

            int last = Size - 1;
            for (int zPos = 1; zPos < (last * 2); ++zPos)
            {
                int hi = System.Math.Min(last, zPos);
                int lo = zPos - hi;

                while (lo < hi)
                {
                    ImplMulwAcc(u, x[lo] ^ x[hi], y[lo] ^ y[hi], zz, zPos);

                    ++lo;
                    --hi;
                }
            }
        }

        private void ImplPermute(ulong[] x, int n, ulong[] z)
        {
            int r = m_bits;

            var pow_1 = m_halfPowers[n];
            var pow_2 = ImplModAdd(r, pow_1, pow_1);
            var pow_4 = ImplModAdd(r, pow_2, pow_2);
            var pow_8 = ImplModAdd(r, pow_4, pow_4);

            int p0 = r - pow_8;
            int p1 = ImplModAdd(r, p0, pow_1);
            int p2 = ImplModAdd(r, p0, pow_2);
            int p3 = ImplModAdd(r, p1, pow_2);
            int p4 = ImplModAdd(r, p0, pow_4);
            int p5 = ImplModAdd(r, p1, pow_4);
            int p6 = ImplModAdd(r, p2, pow_4);
            int p7 = ImplModAdd(r, p3, pow_4);

            for (int i = 0; i < Size; ++i)
            {
                ulong z_i = 0UL;

                for (int j = 0; j < 64; j += 8)
                {
                    p0 = ImplModAdd(r, p0, pow_8);
                    p1 = ImplModAdd(r, p1, pow_8);
                    p2 = ImplModAdd(r, p2, pow_8);
                    p3 = ImplModAdd(r, p3, pow_8);
                    p4 = ImplModAdd(r, p4, pow_8);
                    p5 = ImplModAdd(r, p5, pow_8);
                    p6 = ImplModAdd(r, p6, pow_8);
                    p7 = ImplModAdd(r, p7, pow_8);

                    z_i |= ((x[p0 >> 6] >> p0) & 1UL) << (j + 0);
                    z_i |= ((x[p1 >> 6] >> p1) & 1UL) << (j + 1);
                    z_i |= ((x[p2 >> 6] >> p2) & 1UL) << (j + 2);
                    z_i |= ((x[p3 >> 6] >> p3) & 1UL) << (j + 3);
                    z_i |= ((x[p4 >> 6] >> p4) & 1UL) << (j + 4);
                    z_i |= ((x[p5 >> 6] >> p5) & 1UL) << (j + 5);
                    z_i |= ((x[p6 >> 6] >> p6) & 1UL) << (j + 6);
                    z_i |= ((x[p7 >> 6] >> p7) & 1UL) << (j + 7);
                }

                z[i] = z_i;
            }

            z[Size - 1] &= ulong.MaxValue >> -r;
        }

        private static IEnumerable<int> EnumerateSquarePowersInv(int r)
        {
            int rSub2 = r - 2;
            int bits = 32 - Integers.NumberOfLeadingZeros(rSub2);

            for (int i = 1; i < bits; ++i)
            {
                yield return 1 << (i - 1);

                if ((rSub2 & (1 << i)) != 0)
                {
                    int n = rSub2 & ((1 << i) - 1);
                    yield return n;
                }
            }
        }

        private static int GenerateHalfPower(int r, int n)
        {
            int p = 1;
            for (int k = 0; k < n; ++k)
            {
                p = ImplModHalf(r, p);
            }
            return p;
        }

        private static void ImplMulwAcc(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
        {
            //u[0] = 0;
            u[1] = y;
            for (int i = 2; i < 16; i += 2)
            {
                u[i    ] = u[i >> 1] << 1;
                u[i + 1] = u[i     ] ^  y;
            }

            uint j = (uint)x;
            ulong g, h = 0, l = u[j & 15]
                              ^ u[(j >> 4) & 15] << 4;
            int k = 56;
            do
            {
                j  = (uint)(x >> k);
                g  = u[j & 15]
                   ^ u[(j >> 4) & 15] << 4;
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

            z[zOff    ] ^= l;
            z[zOff + 1] ^= h;
        }

        private void ImplSquare(ulong[] x, ulong[] zz)
        {
            Interleave.Expand64To128(x, 0, Size, zz, 0);
        }
    }
}
