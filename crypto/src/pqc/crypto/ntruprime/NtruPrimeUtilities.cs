using System.Diagnostics;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    internal static class NtruPrimeUtilities
    {
        // GetBarrettFactor(3)
        internal const int Barrett3 = (int)(0x100000000L / 3);

        // floor(2^32 / n), the factor Freeze takes for modulus n. The modulus is public, so dividing by it here is
        // safe; callers compute the factor once, outside their loops. It is below 2^31 for n >= 3, and an int so that
        // Freeze's product is a 32x32 -> 64-bit multiplication even on 32-bit platforms.
        internal static int GetBarrettFactor(int n) =>
            (int)(0x100000000L / n);

        // Fq_freeze, F3_freeze: x mod n in [-(n - 1) / 2, (n - 1) / 2], for n = 3 or q and any x with
        // x + (n - 1) / 2 in the int range, without branches or divisions. The multiply-shift estimate of the quotient
        // is the true quotient or one off it either way, leaving a remainder in [-n, 2n) that two masked corrections
        // bring into [0, n).
        internal static int Freeze(int x, int n, int barrett)
        {
            int y = x + (n - 1) / 2;
            int r = y - n * (int)(((long)y * barrett) >> 32);
            r += n & (r >> 31);
            r -= n;
            r += n & (r >> 31);
            return r - (n - 1) / 2;
        }

        internal static int Freeze3(int x) =>
            Freeze(x, 3, Barrett3);

        // x mod 3 in {-1, 0, 1} for x in [-2, 2], without branches
        private static int SmallFreeze3(int x) =>
            x + 3 * (((1 - x) >> 31) - ((x + 1) >> 31));

        internal static int NegativeMask(int x)
        {
            return x >> 31;
        }

        internal static int NonZeroMask(int x)
        {
            /* return -1 if x!=0; else return 0 */
            return (-x | x) >> 31;
        }

        // Returns 0 if input (coefficients in {-1, 0, 1}) is invertible in R3, -1 otherwise
        internal static int R3Recip(sbyte[] output, sbyte[] input, int p)
        {
            sbyte[] f = new sbyte[p + 1];
            sbyte[] g = new sbyte[p + 1];
            sbyte[] v = new sbyte[p + 1];
            sbyte[] r = new sbyte[p + 1];

            r[0] = 1;

            f[0] = 1;
            f[p - 1] = f[p] = -1;

            for (int i = 0; i < p; ++i)
            {
                g[p - 1 - i] = input[i];
            }

            g[p] = 0;

            int delta = 1;

            // Each step multiplies v by x, conditionally swaps f with g and v with r, adds sign * f to g and sign * v to
            // r, and divides g by x. The loops below fuse those passes, running in the direction that reads each word
            // before overwriting it. input is small, so f, g, r, v and sign all stay in {-1, 0, 1} and the sums in
            // [-2, 2].
            for (int i = 0; i < 2 * p - 1; ++i)
            {
                // symmetric in f and g, so the same before or after the swap
                int sign = -g[0] * f[0];

                int swap = NegativeMask(-delta) & NonZeroMask(g[0]);

                delta ^= swap & (delta ^ -delta);
                delta += 1;

                // g's constant term becomes g[0] + sign * f[0] = g[0] * (1 - f[0]^2) = 0, since f[0] stays +-1, and the
                // division by x drops it, so at index 0 only f needs the swap
                int t = swap & (f[0] ^ g[0]);
                f[0] ^= (sbyte)t;
                Debug.Assert(f[0] == 1 || f[0] == -1);

                for (int j = 0; j < p; ++j)
                {
                    int fj = f[j + 1], gj = g[j + 1];
                    t = swap & (fj ^ gj);
                    fj ^= t;
                    f[j + 1] = (sbyte)fj;
                    g[j] = (sbyte)SmallFreeze3((gj ^ t) + sign * fj);
                }
                g[p] = 0;

                for (int j = p; j > 0; --j)
                {
                    int vj = v[j - 1], rj = r[j];
                    t = swap & (vj ^ rj);
                    vj ^= t;
                    v[j] = (sbyte)vj;
                    r[j] = (sbyte)SmallFreeze3((rj ^ t) + sign * vj);
                }

                // index 0, where x * v has a zero
                t = swap & r[0];
                v[0] = (sbyte)t;
                r[0] = (sbyte)SmallFreeze3((r[0] ^ t) + sign * t);
            }

            int scale = f[0];

            for (int i = 0; i < p; ++i)
            {
                output[i] = (sbyte)(scale * v[p - 1 - i]);
            }

            return NonZeroMask(delta);
        }

        // output = 1 / (3 * input) in Rq; returns 0 if input is invertible, -1 otherwise
        internal static int RqRecip3(short[] output, sbyte[] input, int p, int q)
        {
            int barrett = GetBarrettFactor(q);

            short[] f = new short[p + 1];
            short[] g = new short[p + 1];
            short[] v = new short[p + 1];
            short[] r = new short[p + 1];

            r[0] = (short)FqRecip(3, q);

            f[0] = 1;
            f[p - 1] = f[p] = -1;

            for (int i = 0; i < p; ++i)
            {
                g[p - 1 - i] = input[i];
            }

            g[p] = 0;

            int delta = 1;

            // Each step multiplies v by x, conditionally swaps f with g and v with r, sets g = f[0] * g - g[0] * f and
            // r = f[0] * r - g[0] * v, and divides g by x. The loops below fuse those passes, running in the direction
            // that reads each word before overwriting it.
            for (int i = 0; i < 2 * p - 1; ++i)
            {
                int swap = NegativeMask(-delta) & NonZeroMask(g[0]);

                delta ^= swap & (delta ^ -delta);
                delta += 1;

                // g's constant term becomes f0 * g0 - g0 * f0 = 0 and the division by x drops it, so at index 0 only f
                // needs the swap. f[0] is only ever replaced by a nonzero g[0], so stays nonzero.
                int t = swap & (f[0] ^ g[0]);
                int f0 = f[0] ^ t, g0 = g[0] ^ t;
                f[0] = (short)f0;
                Debug.Assert(f0 != 0);

                for (int j = 0; j < p; ++j)
                {
                    int fj = f[j + 1], gj = g[j + 1];
                    t = swap & (fj ^ gj);
                    fj ^= t;
                    f[j + 1] = (short)fj;
                    g[j] = (short)Freeze(f0 * (gj ^ t) - g0 * fj, q, barrett);
                }
                g[p] = 0;

                for (int j = p; j > 0; --j)
                {
                    int vj = v[j - 1], rj = r[j];
                    t = swap & (vj ^ rj);
                    vj ^= t;
                    v[j] = (short)vj;
                    r[j] = (short)Freeze(f0 * (rj ^ t) - g0 * vj, q, barrett);
                }

                // index 0, where x * v has a zero
                t = swap & r[0];
                v[0] = (short)t;
                r[0] = (short)Freeze(f0 * (r[0] ^ t) - g0 * t, q, barrett);
            }

            int scale = FqRecip(f[0], q);

            for (int i = 0; i < p; ++i)
            {
                output[i] = (short)Freeze(scale * v[p - 1 - i], q, barrett);
            }

            return NonZeroMask(delta);
        }

        // 1 / a in Fq (0 for a = 0), for a in [-(q - 1) / 2, (q - 1) / 2]: a^(q - 2) by square-and-multiply. The
        // exponent is public, so the sequence of operations depends on q alone.
        internal static int FqRecip(int a, int q)
        {
            int barrett = GetBarrettFactor(q);
            int e = q - 2, bit = 0;
            while ((e >> bit) > 1)
            {
                bit++;
            }

            int ai = a;
            while (--bit >= 0)
            {
                ai = Freeze(ai * ai, q, barrett);
                if (((e >> bit) & 1) != 0)
                {
                    ai = Freeze(ai * a, q, barrett);
                }
            }
            return ai;
        }

        // h = f * g in the ring Rq
        internal static void RqMult(short[] h, short[] f, sbyte[] g, int p, int q)
        {
            int[] a = new int[p];
            int[] b = new int[p];
            for (int i = 0; i < p; ++i)
            {
                a[i] = f[i];
                b[i] = g[i];
            }

            int[] fg = ProductModXpX1(a, b, p);

            int barrett = GetBarrettFactor(q);
            for (int i = 0; i < p; ++i)
            {
                h[i] = (short)Freeze(fg[i], q, barrett);
            }
        }

        // h = f * g in the ring R3
        internal static void R3Mult(sbyte[] h, sbyte[] f, sbyte[] g, int p)
        {
            int[] a = new int[p];
            int[] b = new int[p];
            for (int i = 0; i < p; ++i)
            {
                a[i] = f[i];
                b[i] = g[i];
            }

            int[] fg = ProductModXpX1(a, b, p);

            for (int i = 0; i < p; ++i)
            {
                h[i] = (sbyte)Freeze3(fg[i]);
            }
        }

        // Returns the exact product of a and b, both of degree < p, reduced modulo x^p - x - 1, in its first p words.
        //
        // One factor is always reduced, |coefficients| <= (q - 1) / 2, and the other small: in {-1, 0, 1}, or up to 2
        // from a decoded small polynomial. The product's coefficients are then below p * ((q - 1) / 2) * 2, and the
        // reduced ones below 3 times that, at most 3 * 1277 * 3939 * 2 < 2^25 (sntrup1277), so int arithmetic is exact
        // for every parameter set and each coefficient is reduced modulo q (or 3) only once.
        private static int[] ProductModXpX1(int[] a, int[] b, int p)
        {
            int[] fg = new int[p + p - 1];
            for (int i = 0; i < p; ++i)
            {
                int ai = a[i];
                for (int j = 0; j < p; ++j)
                {
                    fg[i + j] += ai * b[j];
                }
            }

            // x^p = x + 1
            for (int i = p + p - 2; i >= p; --i)
            {
                fg[i - p] += fg[i];
                fg[i - p + 1] += fg[i];
            }
            return fg;
        }

        // crypto_sort_uint32: a sorting network, so the sequence of comparisons depends only on the length
        internal static void SortUInt32(uint[] x)
        {
            int n = x.Length;
            if (n < 2)
                return;

            int top = 1;
            while (top < n - top)
            {
                top += top;
            }

            for (int p = top; p > 0; p >>= 1)
            {
                for (int i = 0; i < n - p; ++i)
                {
                    if ((i & p) == 0)
                    {
                        MinMax(ref x[i], ref x[i + p]);
                    }
                }

                int j = 0;
                for (int q = top; q > p; q >>= 1)
                {
                    for (; j < n - q; ++j)
                    {
                        if ((j & p) == 0)
                        {
                            uint a = x[j + p];
                            for (int r = q; r > p; r >>= 1)
                            {
                                MinMax(ref a, ref x[j + r]);
                            }
                            x[j + p] = a;
                        }
                    }
                }
            }
        }

        private static void MinMax(ref uint a, ref uint b)
        {
            // all ones if b < a
            uint c = (uint)(((long)b - a) >> 63) & (a ^ b);
            a ^= c;
            b ^= c;
        }
    }
}
