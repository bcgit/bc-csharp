namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal static class FalconCodec
    {
        /*
        * License from the reference C code (the code was copied then modified
        * to function in C#):
        * ==========================(LICENSE BEGIN)============================
        *
        * Copyright (c) 2017-2019  Falcon Project
        *
        * Permission is hereby granted, free of charge, to any person obtaining
        * a copy of this software and associated documentation files (the
        * "Software"), to deal in the Software without restriction, including
        * without limitation the rights to use, copy, modify, merge, publish,
        * distribute, sublicense, and/or sell copies of the Software, and to
        * permit persons to whom the Software is furnished to do so, subject to
        * the following conditions:
        *
        * The above copyright notice and this permission notice shall be
        * included in all copies or substantial portions of the Software.
        *
        * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
        * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
        * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
        * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        *
        * ===========================(LICENSE END)=============================
        */

        internal static int ModQEncode(byte[] outarrsrc, int outarr, int max_out_len, ushort[] xsrc, int x, int logN)
        {
            int n = 1 << logN;

            for (int u = 0; u < n; ++u)
            {
                if (xsrc[x + u] >= 12289)
                    return 0;
            }
            int out_len = ((n * 14) + 7) >> 3;

            if (outarrsrc == null)
                return out_len;
            if (out_len > max_out_len)
                return 0;

            int buf = outarr;
            uint acc = 0U;
            int acc_len = 0;
            for (int u = 0; u < n; ++u)
            {
                acc = (acc << 14) | xsrc[x + u];
                acc_len += 14;
                while (acc_len >= 8)
                {
                    acc_len -= 8;
                    outarrsrc[buf++] = (byte)(acc >> acc_len);
                }
            }
            if (acc_len > 0)
            {
                outarrsrc[buf] = (byte)(acc << (8 - acc_len));
            }
            return out_len;
        }

        internal static int ModQDecode(ushort[] xsrc, int x, int logN, byte[] inarrsrc, int inarr, int max_in_len)
        {
            int n = 1 << logN;

            int in_len = ((n * 14) + 7) >> 3;
            if (in_len > max_in_len)
                return 0;

            int buf = inarr;
            uint acc = 0U;
            int acc_len = 0;
            int u = 0;
            while (u < n)
            {
                acc = (acc << 8) | (inarrsrc[buf ++]);
                acc_len += 8;
                if (acc_len >= 14)
                {
                    acc_len -= 14;
                    uint w = (acc >> acc_len) & 0x3FFF;
                    if (w >= 12289)
                        return 0;

                    xsrc[x + u] = (ushort)w;
                    u++;
                }
            }
            if ((acc & ((1U << acc_len) - 1)) != 0)
                return 0;

            return in_len;
        }

        //internal static int trim_i16_encode(byte[] outarrsrc, int outarr, int max_out_len, short[] xsrc, int x,
        //    int logN, int bits)
        //{
        //    int u;
        //    int n = 1 << logN;
        //    int maxv = (1 << (bits - 1)) - 1;
        //    int minv = -maxv;
        //    for (u = 0; u < n; ++u)
        //    {
        //        if (xsrc[x + u] < minv || xsrc[x + u] > maxv)
        //            return 0;
        //    }
        //    int out_len = ((n * bits) + 7) >> 3;
        //    if (outarrsrc == null)
        //        return out_len;
        //    if (out_len > max_out_len)
        //        return 0;

        //    int buf = outarr;
        //    uint acc = 0U;
        //    int acc_len = 0;
        //    uint mask = (1U << bits) - 1;
        //    for (u = 0; u < n; ++u)
        //    {
        //        acc = (acc << bits) | ((ushort)xsrc[x + u] & mask);
        //        acc_len += bits;
        //        while (acc_len >= 8)
        //        {
        //            acc_len -= 8;
        //            outarrsrc[buf++] = (byte)(acc >> acc_len);
        //        }
        //    }
        //    if (acc_len > 0)
        //    {
        //        outarrsrc[buf++] = (byte)(acc << (8 - acc_len));
        //    }
        //    return out_len;
        //}

        //internal static int trim_i16_decode(short[] xsrc, int x, int logN, int bits, byte[] inarrsrc, int inarr,
        //    int max_in_len)
        //{
        //    int n = 1 << logN;
        //    int in_len = ((n * bits) + 7) >> 3;
        //    if (in_len > max_in_len)
        //        return 0;

        //    int buf = inarr;
        //    int u = 0;
        //    uint acc = 0U;
        //    int acc_len = 0;
        //    uint mask1 = (1U << bits) - 1;
        //    uint mask2 = 1U << (bits - 1);
        //    while (u < n)
        //    {
        //        acc = (acc << 8) | inarrsrc[buf++];
        //        acc_len += 8;
        //        while (acc_len >= bits && u < n)
        //        {
        //            acc_len -= bits;
        //            uint w = (acc >> acc_len) & mask1;
        //            w = (uint)(w | -(w & mask2));
        //            w |= (uint)(-(w & mask2));
        //            if (w == -mask2)
        //            {
        //                /*
        //                * The -2^(bits-1) value is forbidden.
        //                */
        //                return 0;
        //            }
        //            w |= (uint)(-(w & mask2));
        //            xsrc[x + u] = (short)(int)w;
        //            u++;
        //        }
        //    }
        //    if ((acc & ((1U << acc_len) - 1)) != 0)
        //    {
        //        /*
        //        * Extra bits in the last byte must be zero.
        //        */
        //        return 0;
        //    }
        //    return in_len;
        //}

        internal static int TrimI8Encode(byte[] outarrsrc, int outarr, int max_out_len, sbyte[] xsrc, int x, int logN,
            int bits)
        {
            int n = 1 << logN;
            int maxv = (1 << (bits - 1)) - 1;
            int minv = -maxv;

            for (int u = 0; u < n; ++u)
            {
                if (xsrc[x+u] < minv || xsrc[x+u] > maxv)
                    return 0;
            }
            int out_len = ((n * bits) + 7) >> 3;

            if (outarrsrc == null)
                return out_len;
            if (out_len > max_out_len)
                return 0;

            int buf = outarr;
            uint acc = 0U;
            int acc_len = 0;
            uint mask = (1U << bits) - 1U;
            for (int u = 0; u < n; ++u)
            {
                acc = (acc << bits) | ((byte)xsrc[x + u] & mask);
                acc_len += bits;
                while (acc_len >= 8)
                {
                    acc_len -= 8;
                    outarrsrc[buf ++] = (byte)(acc >> acc_len);
                }
            }
            if (acc_len > 0)
            {
                outarrsrc[buf++] = (byte)(acc << (8 - acc_len));
            }
            return out_len;
        }

        internal static int TrimI8Decode(sbyte[] xsrc, int x, int logN, int bits, byte[] inarrsrc, int inarr,
            int max_in_len)
        {
            int n = 1 << logN;

            int in_len = ((n * bits) + 7) >> 3;
            if (in_len > max_in_len)
                return 0;

            int buf = inarr;
            int u = 0;
            uint acc = 0U;
            int acc_len = 0;
            uint mask1 = (1U << bits) - 1;
            uint mask2 = 1U << (bits - 1);
            while (u < n)
            {
                acc = (acc << 8) | inarrsrc[buf ++];
                acc_len += 8;
                while (acc_len >= bits && u < n)
                {
                    acc_len -= bits;
                    uint w = (acc >> acc_len) & mask1;
                    w |= (uint)(-(w & mask2));

                    // The - 2 ^ (bits - 1) value is forbidden.
                    if (w == -mask2)
                        return 0;

                    xsrc[x + u] = (sbyte)(int)w;
                    u++;
                }
            }

            // Extra bits in the last byte must be zero.
            if ((acc & ((1U << acc_len) - 1)) != 0)
                return 0;

            return in_len;
        }

        internal static int CompEncode(byte[] outarrsrc, int outarr, int max_out_len, short[] x, int xOff, int logN)
        {
            int n = 1 << logN;
            int buf = outarr;

            /*
            * Make sure that all values are within the -2047..+2047 range.
            */
            for (int u = 0; u < n; ++u)
            {
                if (x[xOff + u] < -2047 || x[xOff + u] > +2047)
                    return 0;
            }

            uint acc = 0;
            int acc_len = 0;
            int v = 0;
            for (int u = 0; u < n; ++u)
            {
                /*
                * Get sign and absolute value of next integer; push the
                * sign bit.
                */
                acc <<= 1;
                int t = x[xOff+u];
                if (t < 0)
                {
                    t = -t;
                    acc |= 1;
                }
                uint w = (uint)t;

                /*
                * Push the low 7 bits of the absolute value.
                */
                acc <<= 7;
                acc |= w & 127u;
                w >>= 7;

                /*
                * We pushed exactly 8 bits.
                */
                acc_len += 8;

                /*
                * Push as many zeros as necessary, then a one. Since the
                * absolute value is at most 2047, w can only range up to
                * 15 at this point, thus we will add at most 16 bits
                * here. With the 8 bits above and possibly up to 7 bits
                * from previous iterations, we may go up to 31 bits, which
                * will fit in the accumulator, which is an uint.
                */
                acc <<= (int)(w + 1);
                acc |= 1;
                acc_len += (int)(w + 1);

                /*
                * Produce all full bytes.
                */
                while (acc_len >= 8)
                {
                    acc_len -= 8;
                    if (outarrsrc != null)
                    {
                        if (v >= max_out_len)
                            return 0;

                        outarrsrc[buf + v] = (byte)(acc >> acc_len);
                    }
                    ++v;
                }
            }

            /*
            * Flush remaining bits (if any).
            */
            if (acc_len > 0)
            {
                if (outarrsrc != null)
                {
                    if (v >= max_out_len)
                        return 0;

                    outarrsrc[buf + v] = (byte)(acc << (8 - acc_len));
                }
                ++v;
            }

            return v;
        }

        internal static int CompDecode(short[] xsrc, int x, int logN, byte[] inarrsrc, int inarr, int max_in_len)
        {
            int n = 1 << logN;
            int buf = inarr;
            uint acc = 0;
            int acc_len = 0;
            int v = 0;

            for (int u = 0; u < n; ++u)
            {
                /*
                * Get next eight bits: sign and low seven bits of the
                * absolute value.
                */
                if (v >= max_in_len)
                    return 0;

                acc = (acc << 8) | (uint)inarrsrc[buf + v];
                ++v;
                uint b = acc >> acc_len;
                uint s = b & 128;
                uint m = b & 127;

                /*
                * Get next bits until a 1 is reached.
                */
                for (;;)
                {
                    if (acc_len == 0)
                    {
                        if (v >= max_in_len)
                            return 0;

                        acc = (acc << 8) | (uint)inarrsrc[buf + v];
                        ++v;
                        acc_len = 8;
                    }
                    --acc_len;
                    if (((acc >> acc_len) & 1) != 0)
                        break;

                    m += 128;
                    if (m > 2047)
                        return 0;
                }

                /*
                * "-0" is forbidden.
                */
                if (s != 0 && m == 0)
                    return 0;

                xsrc[x + u] = (short)(s != 0 ? -(int)m : (int)m);
            }

            /*
            * Unused bits in the last byte must be zero.
            */
            if ((acc & ((1U << acc_len) - 1U)) != 0)
                return 0;

            return v;
        }

        /*
        * Key elements and signatures are polynomials with small integer
        * coefficients. Here are some statistics gathered over many
        * generated key pairs (10000 or more for each degree):
        *
        *   log(n)     n   max(f,g)   std(f,g)   max(F,G)   std(F,G)
        *      1       2     129       56.31       143       60.02
        *      2       4     123       40.93       160       46.52
        *      3       8      97       28.97       159       38.01
        *      4      16     100       21.48       154       32.50
        *      5      32      71       15.41       151       29.36
        *      6      64      59       11.07       138       27.77
        *      7     128      39        7.91       144       27.00
        *      8     256      32        5.63       148       26.61
        *      9     512      22        4.00       137       26.46
        *     10    1024      15        2.84       146       26.41
        *
        * We want a compact storage format for private key, and, as part of
        * key generation, we are allowed to reject some keys which would
        * otherwise be fine (this does not induce any noticeable vulnerability
        * as long as we reject only a small proportion of possible keys).
        * Hence, we enforce at key generation time maximum values for the
        * elements of f, g, F and G, so that their encoding can be expressed
        * in fixed-width values. Limits have been chosen so that generated
        * keys are almost always within bounds, thus not impacting neither
        * security or performance.
        *
        * IMPORTANT: the code assumes that all coefficients of f, g, F and G
        * ultimately fit in the -127..+127 range. Thus, none of the elements
        * of max_fg_bits[] and max_FG_bits[] shall be greater than 8.
        */

        internal static readonly byte[] MaxBits_fg = { 0, /* unused */
            8, 8, 8, 8, 8, 7, 7, 6, 6, 5
        };

        internal static readonly byte[] MaxBits_FG = { 0, /* unused */
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8
        };

        /*
        * When generating a new key pair, we can always reject keys which
        * feature an abnormally large coefficient. This can also be done for
        * signatures, albeit with some care: in case the signature process is
        * used in a derandomized setup (explicitly seeded with the message and
        * private key), we have to follow the specification faithfully, and the
        * specification only enforces a limit on the L2 norm of the signature
        * vector. The limit on the L2 norm implies that the absolute value of
        * a coefficient of the signature cannot be more than the following:
        *
        *   log(n)     n   max sig coeff (theoretical)
        *      1       2       412
        *      2       4       583
        *      3       8       824
        *      4      16      1166
        *      5      32      1649
        *      6      64      2332
        *      7     128      3299
        *      8     256      4665
        *      9     512      6598
        *     10    1024      9331
        *
        * However, the largest observed signature coefficients during our
        * experiments was 1077 (in absolute value), hence we can assume that,
        * with overwhelming probability, signature coefficients will fit
        * in -2047..2047, i.e. 12 bits.
        */

        internal static readonly byte[] MaxBits_sig = { 0, /* unused */
            10, 11, 11, 12, 12, 12, 12, 12, 12, 12
        };
    }
}
