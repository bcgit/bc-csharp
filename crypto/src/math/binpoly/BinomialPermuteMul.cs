using System;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.BinPoly
{
    /// <summary>
    /// <see cref="IBinPolyMul"/> for <c>x^n + 1</c> with odd <c>n</c>: <see cref="SquareN"/> becomes a coefficient
    /// permutation at and above a crossover count, and every other operation forwards to the wrapped instance.
    /// </summary>
    /// <remarks>
    /// <para>Bit <c>b</c> of <c>x^(2^k)</c> is bit <c>(b * 2^-k) mod n</c> of <c>x</c> (2 is invertible mod odd
    /// <c>n</c>). Generating the indices on the fly costs a few cycles per bit independent of <c>k</c>, so beyond a
    /// crossover <c>k</c> it beats <c>k</c> explicit squarings. Only the constant <c>2^-k mod n</c> is needed, and at
    /// <c>O(log k)</c> modular multiplications it is cheap enough to compute per call. The permutation view follows
    /// https://ia.cr/2020/298 (Drucker, Gueron, Kostic), but the index map is never materialized.</para>
    /// <para>The indices depend only on <c>n</c> and <c>k</c>, so, like repeated squaring, the permutation's timing
    /// and memory access pattern are independent of <c>x</c>.</para>
    /// </remarks>
    internal sealed class BinomialPermuteMul
        : IBinPolyMul
    {
        // Measured k crossover vs. repeated squaring (BIKE sizes, i7-12700H): ~16-27 with BMI2 (PDEP expand),
        // ~13 on .NET 6 without it, ~8 on .NET Framework.
#if NETCOREAPP3_0_OR_GREATER
        private const int FallbackCutoff = 12;
#else
        private const int FallbackCutoff = 8;
#endif
        private static readonly int Cutoff =
            Org.BouncyCastle.Runtime.Intrinsics.X86.Bmi2.X64.IsEnabled ? 24 : FallbackCutoff;

        /// <summary>
        /// Wrap <paramref name="mul"/>, which must reduce by <c>x^n + 1</c>, if <c>n</c> is odd; for even <c>n</c>
        /// there is no such permutation and <paramref name="mul"/> is returned as is.
        /// </summary>
        internal static IBinPolyMul Wrap(IBinPolyMul mul) => (mul.N & 1) == 0 ? mul : new BinomialPermuteMul(mul);

        private readonly IBinPolyMul m_mul;
        private readonly int m_n;
        private readonly int m_size;

        private BinomialPermuteMul(IBinPolyMul mul)
        {
            Debug.Assert((mul.N & 1) != 0);

            m_mul = mul;
            m_n = mul.N;
            m_size = mul.Size;
        }

        public int N => m_n;

        public int Size => m_size;

        public void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff) =>
            m_mul.Multiply(x, xOff, y, yOff, z, zOff);

        public void Square(ulong[] x, int xOff, ulong[] z, int zOff) => m_mul.Square(x, xOff, z, zOff);

        public void SquareN(ulong[] x, int xOff, int n, ulong[] z, int zOff)
        {
            // Also routes n < 1 to the wrapped instance's argument check.
            if (n < Cutoff)
            {
                m_mul.SquareN(x, xOff, n, z, zOff);
                return;
            }

            // The gather indexes x from offset 0 (an offset add per bit costs measurably) and reads all of x while
            // z is written, so an offset or aliased source is copied first.
            if (xOff == 0 && x != z)
            {
                Permute(x, n, z, zOff);
                return;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ulong[] t = BinPolyMulBase.m_scratchPool.Rent(m_size);
            try
            {
                Array.Copy(x, xOff, t, 0, m_size);
                Permute(t, n, z, zOff);
            }
            finally
            {
                BinPolys.Clear(m_size, t, 0);
                BinPolyMulBase.m_scratchPool.Return(t);
            }
#else
            ulong[] t = new ulong[m_size];
            Array.Copy(x, xOff, t, 0, m_size);
            Permute(t, n, z, zOff);
            BinPolys.Clear(m_size, t, 0);
#endif
        }

        // 2^-k mod n, as h^k mod n where h = (n + 1) / 2 = 2^-1 mod n (n odd).
        private static int HalfPower(int n, int k)
        {
            ulong m = (uint)n, h = (m + 1) >> 1, p = 1;
            for (int i = Integers.BitLength(k) - 1; i >= 0; --i)
            {
                p = p * p % m;
                if ((k & (1 << i)) != 0)
                {
                    p = p * h % m;
                }
            }
            return (int)p;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static int ModAdd(int m, int x, int y)
        {
            int t = x + y - m;
            return t + ((t >> 31) & m);
        }

        private void Permute(ulong[] x, int k, ulong[] z, int zOff)
        {
            int n = m_n, size = m_size;

            int pow_1 = HalfPower(n, k);
            int pow_2 = ModAdd(n, pow_1, pow_1);
            int pow_4 = ModAdd(n, pow_2, pow_2);
            int pow_8 = ModAdd(n, pow_4, pow_4);

            // Eight interleaved index chains (ILP), each stepping by 8 * 2^-k; the first step brings p0 to 0.
            int p0 = n - pow_8;
            int p1 = ModAdd(n, p0, pow_1);
            int p2 = ModAdd(n, p0, pow_2);
            int p3 = ModAdd(n, p1, pow_2);
            int p4 = ModAdd(n, p0, pow_4);
            int p5 = ModAdd(n, p1, pow_4);
            int p6 = ModAdd(n, p2, pow_4);
            int p7 = ModAdd(n, p3, pow_4);

            for (int i = 0; i < size; ++i)
            {
                ulong z_i = 0UL;

                for (int j = 0; j < 64; j += 8)
                {
                    p0 = ModAdd(n, p0, pow_8);
                    p1 = ModAdd(n, p1, pow_8);
                    p2 = ModAdd(n, p2, pow_8);
                    p3 = ModAdd(n, p3, pow_8);
                    p4 = ModAdd(n, p4, pow_8);
                    p5 = ModAdd(n, p5, pow_8);
                    p6 = ModAdd(n, p6, pow_8);
                    p7 = ModAdd(n, p7, pow_8);

                    z_i |= ((x[p0 >> 6] >> p0) & 1UL) << (j + 0);
                    z_i |= ((x[p1 >> 6] >> p1) & 1UL) << (j + 1);
                    z_i |= ((x[p2 >> 6] >> p2) & 1UL) << (j + 2);
                    z_i |= ((x[p3 >> 6] >> p3) & 1UL) << (j + 3);
                    z_i |= ((x[p4 >> 6] >> p4) & 1UL) << (j + 4);
                    z_i |= ((x[p5 >> 6] >> p5) & 1UL) << (j + 5);
                    z_i |= ((x[p6 >> 6] >> p6) & 1UL) << (j + 6);
                    z_i |= ((x[p7 >> 6] >> p7) & 1UL) << (j + 7);
                }

                z[zOff + i] = z_i;
            }

            // Output bits at positions >= n gathered arbitrary (valid) input bits.
            z[zOff + size - 1] &= ulong.MaxValue >> -n;
        }
    }
}
