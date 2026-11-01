using System;

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

            int sign, swap, t;

            for (int i = 0; i < 2 * p - 1; ++i)
            {
                for (int j = p; j > 0; --j)
                {
                    v[j] = v[j - 1];
                }

                v[0] = 0;

                sign = -g[0] * f[0];

                swap = NegativeMask(-delta) & NonZeroMask(g[0]);

                delta ^= swap & (delta ^ -delta);
                delta += 1;

                for (int j = 0; j < p + 1; ++j)
                {
                    t = swap & (f[j] ^ g[j]);
                    f[j] ^= (sbyte)t;
                    g[j] ^= (sbyte)t;
                    t = swap & (v[j] ^ r[j]);
                    v[j] ^= (sbyte)t;
                    r[j] ^= (sbyte)t;
                }

                // input is small, so f, g, r, v and sign all stay in {-1, 0, 1} and the sums in [-2, 2]
                for (int j = 0; j < p + 1; ++j)
                {
                    g[j] = (sbyte)SmallFreeze3(g[j] + sign * f[j]);
                }

                for (int j = 0; j < p + 1; ++j)
                {
                    r[j] = (sbyte)SmallFreeze3(r[j] + sign * v[j]);
                }

                for (int j = 0; j < p; ++j)
                {
                    g[j] = g[j + 1];
                }
                g[p] = 0;
            }

            sign = f[0];

            for (int i = 0; i < p; ++i)
            {
                output[i] = (sbyte)(sign * v[p - 1 - i]);
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
            int swap, t;
            int scale;
            int f0, g0;

            r[0] = (short)FqRecip(3, q);

            f[0] = 1;
            f[p - 1] = f[p] = -1;

            for (int i = 0; i < p; ++i)
            {
                g[p - 1 - i] = input[i];
            }

            g[p] = 0;

            int delta = 1;

            for (int i = 0; i < 2 * p - 1; ++i)
            {
                for (int j = p; j > 0; --j)
                {
                    v[j] = v[j - 1];
                }

                v[0] = 0;

                swap = NegativeMask(-delta) & NonZeroMask(g[0]);

                delta ^= swap & (delta ^ -delta);
                delta += 1;

                for (int j = 0; j < p + 1; ++j)
                {
                    t = swap & (f[j] ^ g[j]);
                    f[j] ^= (short)t;
                    g[j] ^= (short)t;
                    t = swap & (v[j] ^ r[j]);
                    v[j] ^= (short)t;
                    r[j] ^= (short)t;
                }

                f0 = f[0];
                g0 = g[0];

                for (int j = 0; j < p + 1; ++j)
                {
                    g[j] = (short)Freeze(f0 * g[j] - g0 * f[j], q, barrett);
                }

                for (int j = 0; j < p + 1; ++j)
                {
                    r[j] = (short)Freeze(f0 * r[j] - g0 * v[j], q, barrett);
                }

                for (int j = 0; j < p; ++j)
                {
                    g[j] = g[j + 1];
                }

                g[p] = 0;
            }

            scale = FqRecip(f[0], q);

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
            int barrett = GetBarrettFactor(q);

            short[] fg = new short[p + p - 1];
            int result;

            for (int i = 0; i < p; ++i)
            {
                result = 0;
                for (int j = 0; j <= i; ++j)
                {
                    result = Freeze(result + f[j] * g[i - j], q, barrett);
                }
                fg[i] = (short)result;
            }

            for (int i = p; i < p + p - 1; ++i)
            {
                result = 0;
                for (int j = i - p + 1; j < p; ++j)
                {
                    result = Freeze(result + f[j] * g[i - j], q, barrett);
                }
                fg[i] = (short)result;
            }

            for (int i = p + p - 2; i >= p; --i)
            {
                fg[i - p] = (short)Freeze(fg[i - p] + fg[i], q, barrett);
                fg[i - p + 1] = (short)Freeze(fg[i - p + 1] + fg[i], q, barrett);
            }

            Array.Copy(fg, 0, h, 0, p);
        }

        // h = f * g in the ring R3
        internal static void R3Mult(sbyte[] h, sbyte[] f, sbyte[] g, int p)
        {
            sbyte[] fg = new sbyte[p + p - 1];
            int result;

            for (int i = 0; i < p; ++i)
            {
                result = 0;
                for (int j = 0; j <= i; ++j)
                {
                    result = Freeze3(result + f[j] * g[i - j]);
                }
                fg[i] = (sbyte)result;
            }

            for (int i = p; i < p + p - 1; ++i)
            {
                result = 0;
                for (int j = i - p + 1; j < p; ++j)
                {
                    result = Freeze3(result + f[j] * g[i - j]);
                }
                fg[i] = (sbyte)result;
            }

            for (int i = p + p - 2; i >= p; --i)
            {
                fg[i - p] = (sbyte)Freeze3(fg[i - p] + fg[i]);
                fg[i - p + 1] = (sbyte)Freeze3(fg[i - p + 1] + fg[i]);
            }

            Array.Copy(fg, 0, h, 0, p);
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
