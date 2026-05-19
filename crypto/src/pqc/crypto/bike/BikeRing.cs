using System;
using System.Collections.Generic;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.BinPoly;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal sealed class BikeRing
    {
        private const int PermutationCutoff = 64;

        private readonly Dictionary<int, int> m_halfPowers = new Dictionary<int, int>();
        private readonly IBinPolyMul m_binPolyMul;
        private readonly int m_bits;
        private readonly int m_size;

        internal BikeRing(int r)
        {
            if ((r & 0xFFFF0001) != 1)
                throw new ArgumentException();

            m_binPolyMul = BinPolys.Mul.Binomial(r);
            m_bits = r;
            m_size = BinPolys.Size(r);

            uint r32 = Mod.Inverse32((uint)-r);
            foreach (int n in EnumerateSquarePowersInv(r))
            {
                if (n >= PermutationCutoff && !m_halfPowers.ContainsKey(n))
                {
                    m_halfPowers[n] = GenerateHalfPower((uint)r, r32, n);
                }
            }
        }

        internal void Add(ulong[] x, ulong[] y, ulong[] z) => BinPolys.Add(m_size, x, 0, y, 0, z, 0);

        internal void AddTo(ulong[] x, ulong[] z) => BinPolys.AddTo(m_size, x, 0, z, 0);

        internal void Copy(ulong[] x, ulong[] z) => BinPolys.Copy(m_size, x, 0, z, 0);

        internal ulong[] Create() => BinPolys.Create(m_size);

        internal void DecodeBytes(byte[] bs, ulong[] z)
        {
            int last = Size - 1;
            int partialBits = m_bits & 63;
            int partialBytes = (partialBits + 7) >> 3;
            Pack.LE_To_UInt64(bs, 0, z, 0, last);
            z[last] = Pack.LE_To_UInt64_Low(bs, last << 3, partialBytes);
            Debug.Assert((z[last] >> partialBits) == 0UL);
        }

        internal byte[] EncodeBitsTransposed(ulong[] x)
        {
            byte[] bs = new byte[m_bits];
            bs[0] = (byte)(x[0] & 1UL);
            for (int i = 1; i < m_bits; ++i)
            {
                bs[m_bits - i] = (byte)((x[i >> 6] >> (i & 63)) & 1UL);
            }
            return bs;
        }

        internal void EncodeBytes(ulong[] x, byte[] bs)
        {
            int last = Size - 1;
            int partialBits = m_bits & 63;
            int partialBytes = (partialBits + 7) >> 3;
            Debug.Assert((x[last] >> partialBits) == 0UL);
            Pack.UInt64_To_LE(x, 0, last, bs, 0);
            Pack.UInt64_To_LE_Low(x[last], bs, last << 3, partialBytes);
        }

        internal void Inv(ulong[] a, ulong[] z)
        {
            /*
             * Algorithm for inversion is based on https://ia.cr/2020/298 (Nir Drucker, Shay Gueron, Dusan Kostic,
             * "Fast polynomial inversion for post quantum QC-MDPC cryptography"), in particular replacing large
             * squarings with permutations. However we precompute only powers-of-half instead of full tables.
             */

            ulong[] f = Create();
            ulong[] g = Create();
            ulong[] t = Create();

            Copy(a, f);
            Copy(a, t);

            int rSub2 = m_bits - 2;
            int bits = Integers.BitLength(rSub2);

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

        internal void Multiply(ulong[] x, ulong[] y, ulong[] z) => Multiply(x, 0, y, 0, z);

        internal void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z) =>
            m_binPolyMul.Multiply(x, xOff, y, yOff, z, 0);

        internal int Size => m_size;

        internal void Square(ulong[] x, ulong[] z) => m_binPolyMul.Square(x, 0, z, 0);

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

            m_binPolyMul.SquareN(x, 0, n, z, 0);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static int ImplModAdd(int m, int x, int y)
        {
            int t = x + y - m;
            return t + ((t >> 31) & m);
        }

        private void ImplPermute(ulong[] x, int n, ulong[] z)
        {
            int r = m_bits;

            int pow_1 = m_halfPowers[n];
            int pow_2 = ImplModAdd(r, pow_1, pow_1);
            int pow_4 = ImplModAdd(r, pow_2, pow_2);
            int pow_8 = ImplModAdd(r, pow_4, pow_4);

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
            int bits = Integers.BitLength(rSub2);

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

        private static int GenerateHalfPower(uint r, uint r32, int n)
        {
            uint p = 1;
            int k = n;
            while (k >= 32)
            {
                uint y = r32 * p;
                ulong t = (ulong)y * r;
                ulong u = t + p;
                Debug.Assert((uint)u == 0U);
                p = (uint)(u >> 32);
                k -= 32;
            }
            if (k > 0)
            {
                uint mk = uint.MaxValue >> -k;
                uint y = (r32 * p) & mk;
                ulong t = (ulong)y * r;
                ulong u = t + p;
                Debug.Assert(((uint)u & mk) == 0U);
                p = (uint)(u >> k);
            }
            return (int)p;
        }
    }
}
