using System;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    internal static class NtruPrimeUtilities
    {
        // int32_mod_uint14 constants for modulus 3 (see Freeze)
        internal const uint V3 = 0x80000000U / 3U, R3 = 0x80000000U % 3U;

        // Fq_freeze, F3_freeze: x mod n in [-(n - 1) / 2, (n - 1) / 2], for 0 < n < 16384 and any x with
        // x + (n - 1) / 2 in the int range; v and r are 0x80000000 / n and 0x80000000 % n
        internal static int Freeze(int x, int n, uint v, uint r)
        {
            return Int32ModUInt14(x + (n - 1) / 2, (uint)n, v, r) - (n - 1) / 2;
        }

        internal static int Freeze3(int x)
        {
            return Freeze(x, 3, V3, R3);
        }

        // int32_mod_uint14: x mod m for 0 < m < 16384, without branches or divisions; v and r are the reference
        // implementation's compile-time constants 0x80000000 / m and 0x80000000 % m
        private static int Int32ModUInt14(int x, uint m, uint v, uint r)
        {
            int d = (int)UInt32ModUInt14(0x80000000U + (uint)x, m, v) - (int)r;
            return d + ((int)m & (d >> 31));
        }

        // uint32_divmod_uint14, remainder only
        private static uint UInt32ModUInt14(uint x, uint m, uint v)
        {
            x -= (uint)((x * (ulong)v) >> 31) * m;
            x -= (uint)((x * (ulong)v) >> 31) * m;
            x -= m;
            return x + (m & (0U - (x >> 31)));
        }

        internal static int NegativeMask(int x)
        {
            return x >> 31;
        }

        internal static int NonZeroMask(int x)
        {
            /* return -1 if x!=0; else return 0 */
            return (-x | x) >> 31;
        }

        // Returns 0 if input is invertible in R3, -1 otherwise
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

                for (int j = 0; j < p + 1; ++j)
                {
                    g[j] = (sbyte)Freeze3(g[j] + sign * f[j]);
                }

                for (int j = 0; j < p + 1; ++j)
                {
                    r[j] = (sbyte)Freeze3(r[j] + sign * v[j]);
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
            uint qv = 0x80000000U / (uint)q, qr = 0x80000000U % (uint)q;

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
                    g[j] = (short)Freeze(f0 * g[j] - g0 * f[j], q, qv, qr);
                }

                for (int j = 0; j < p + 1; ++j)
                {
                    r[j] = (short)Freeze(f0 * r[j] - g0 * v[j], q, qv, qr);
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
                output[i] = (short)Freeze(scale * v[p - 1 - i], q, qv, qr);
            }

            return NonZeroMask(delta);
        }

        // 1 / a in Fq (0 for a = 0), for a in [-(q - 1) / 2, (q - 1) / 2]
        internal static int FqRecip(int a, int q)
        {
            uint qv = 0x80000000U / (uint)q, qr = 0x80000000U % (uint)q;

            int i = 1;
            int ai = a;

            while (i < q - 2)
            {
                ai = Freeze(a * ai, q, qv, qr);
                i++;
            }

            return ai;
        }

        // h = f * g in the ring Rq
        internal static void RqMult(short[] h, short[] f, sbyte[] g, int p, int q)
        {
            uint qv = 0x80000000U / (uint)q, qr = 0x80000000U % (uint)q;

            short[] fg = new short[p + p - 1];
            int result;

            for (int i = 0; i < p; ++i)
            {
                result = 0;
                for (int j = 0; j <= i; ++j)
                {
                    result = Freeze(result + f[j] * g[i - j], q, qv, qr);
                }
                fg[i] = (short)result;
            }

            for (int i = p; i < p + p - 1; ++i)
            {
                result = 0;
                for (int j = i - p + 1; j < p; ++j)
                {
                    result = Freeze(result + f[j] * g[i - j], q, qv, qr);
                }
                fg[i] = (short)result;
            }

            for (int i = p + p - 2; i >= p; --i)
            {
                fg[i - p] = (short)Freeze(fg[i - p] + fg[i], q, qv, qr);
                fg[i - p + 1] = (short)Freeze(fg[i - p + 1] + fg[i], q, qv, qr);
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
