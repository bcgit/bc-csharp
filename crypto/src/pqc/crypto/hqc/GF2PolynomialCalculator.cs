﻿namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class GF2PolynomialCalculator
    {
        private readonly int _vecNSize64;
        private readonly int _paramN;
        private readonly long _redMask;

        public GF2PolynomialCalculator(int vecNSize64, int paramN, ulong redMask)
        {
            _vecNSize64 = vecNSize64;
            _paramN = paramN;
            _redMask = (long)redMask;
        }

        internal void MultLongs(long[] res, long[] a, long[] b)
        {
            long[] stack = new long[_vecNSize64 << 3];
            long[] oKarat = new long[(_vecNSize64 << 1) + 1];

            karatsuba(oKarat, 0, a, 0,  b, 0, _vecNSize64, stack, 0);
            reduce(res, oKarat);
        }


        private void base_mul(long[] c, int cOffset, long a, long b)
        {
            long h = 0;
            long l = 0;
            long g;
            long[] u = new long[16];
            long[] maskTab = new long[4];

            // Step 1
            u[0] = 0;
            u[1] = b & ((1L << (64 - 4)) - 1L);
            u[2] = u[1] << 1;
            u[3] = u[2] ^ u[1];
            u[4] = u[2] << 1;
            u[5] = u[4] ^ u[1];
            u[6] = u[3] << 1;
            u[7] = u[6] ^ u[1];
            u[8] = u[4] << 1;
            u[9] = u[8] ^ u[1];
            u[10] = u[5] << 1;
            u[11] = u[10] ^ u[1];
            u[12] = u[6] << 1;
            u[13] = u[12] ^ u[1];
            u[14] = u[7] << 1;
            u[15] = u[14] ^ u[1];

            g=0;
            long tmp1 = a & 15;

            for(int i = 0; i < 16; i++)
            {
                long tmp2 = tmp1 - i;
                g ^= (u[i] & -(1 - (long)((ulong)(tmp2 | -tmp2) >> 63)));
            }
            l = g;
            h = 0;

            // Step 2
            for (byte i = 4; i < 64; i += 4)
            {
                g = 0;
                long temp1 = (a >> i) & 15;
                for (int j = 0; j < 16; ++j)
                {
                    long tmp2 = temp1 - j;
                    g ^= (u[j] & -(1 - (long)((ulong)(tmp2 | -tmp2) >> 63)));
                }

                l ^= g << i;
                h ^= (long)((ulong)g) >> (64 - i);
            }

            // Step 3
            maskTab [0] = -((b >> 60) & 1);
            maskTab [1] = -((b >> 61) & 1);
            maskTab [2] = -((b >> 62) & 1);
            maskTab [3] = -((b >> 63) & 1);

            l ^= ((a << 60) & maskTab[0]);
            h ^= ((long)((ulong)a >> 4) & maskTab[0]);

            l ^= ((a << 61) & maskTab[1]);
            h ^= ((long)((ulong)a >> 3) & maskTab[1]);

            l ^= ((a << 62) & maskTab[2]);
            h ^= ((long)((ulong)a >> 2) & maskTab[2]);

            l ^= ((a << 63) & maskTab[3]);
            h ^= ((long)((ulong)a >> 1) & maskTab[3]);

            c[0 + cOffset] = l;
            c[1 + cOffset] = h;
        }




        private void karatsuba_add1(long[] alh, int alhOffset,
                            long[] blh, int blhOffset,
                            long[] a, int aOffset,
                            long[] b, int bOffset,
                            int size_l, int size_h)
        {
            for (int i = 0; i < size_h; i++)
            {
                alh[i + alhOffset] = a[i+ aOffset] ^ a[i + size_l + aOffset];
                blh[i + blhOffset] = b[i+ bOffset] ^ b[i + size_l + bOffset];
            }

            if (size_h < size_l)
            {
                alh[size_h + alhOffset] = a[size_h + aOffset];
                blh[size_h + blhOffset] = b[size_h + bOffset];
            }
        }



        private void karatsuba_add2(long[] o, int oOffset,
                           long[] tmp1, int tmp1Offset,
                           long[] tmp2, int tmp2Offset,
                            int size_l, int size_h)
        {
            for (int i = 0; i < (2 * size_l) ; i++)
            {
                tmp1[i + tmp1Offset] = tmp1[i + tmp1Offset] ^ o[i + oOffset];
            }

            for (int i = 0; i < ( 2 * size_h); i++)
            {
                tmp1[i + tmp1Offset] = tmp1[i + tmp1Offset] ^ tmp2[i + tmp2Offset];
            }

            for (int i = 0; i < (2 * size_l); i++)
            {
                o[i + size_l + oOffset] = o[i + size_l + oOffset] ^ tmp1[i + tmp1Offset];
            }
        }



        /**
         * Karatsuba multiplication of a and b, Implementation inspired from the NTL library.
         *
         * \param[out] o Polynomial
         * \param[in] a Polynomial
         * \param[in] b Polynomial
         * \param[in] size Length of polynomial
         * \param[in] stack Length of polynomial
         */
        private void karatsuba(long[] o, int oOffset, long[] a, int aOffset, long[] b, int bOffset, int size, long[] stack, int stackOffset)
        {
            int size_l, size_h;
            int ahOffset, bhOffset;

            if (size == 1)
            {
                base_mul(o, oOffset, a[0 + aOffset], b[0 + bOffset]);
                return;
            }

            size_h = size / 2;
            size_l = (size + 1) / 2;

            // alh = stack
            int alhOffset = stackOffset;
            // blh = stack with size_l offset
            int blhOffset = alhOffset + size_l;
            // tmp1 = stack with size_l * 2 offset;
            int tmp1Offset = blhOffset + size_l;
            // tmp2 = o with size_l * 2 offset;
            int tmp2Offset = oOffset + size_l*2;

            stackOffset += 4 * size_l;

            ahOffset = aOffset + size_l;
            bhOffset = bOffset + size_l;

            karatsuba(o, oOffset, a, aOffset, b, bOffset, size_l, stack, stackOffset);

            karatsuba(o, tmp2Offset, a, ahOffset, b, bhOffset, size_h, stack, stackOffset);

            karatsuba_add1(stack, alhOffset, stack, blhOffset, a, aOffset, b, bOffset, size_l, size_h);

            karatsuba(stack, tmp1Offset, stack, alhOffset, stack, blhOffset, size_l, stack, stackOffset);

            karatsuba_add2(o, oOffset, stack, tmp1Offset, o, tmp2Offset, size_l, size_h);
        }



        /**
         * @brief Compute o(x) = a(x) mod \f$ X^n - 1\f$
         *
         * This function computes the modular reduction of the polynomial a(x)
         *
         * @param[in] a Pointer to the polynomial a(x)
         * @param[out] o Pointer to the result
         */
        private void reduce(long[] o, long[] a)
        {
            int i;
            long r;
            long carry;

            for (i = 0; i < _vecNSize64; i++)
            {
                r = (long)((ulong)a[i + _vecNSize64 - 1] >> (_paramN & 0x3F));
                carry = a[i + _vecNSize64 ] << (int)(64 - (_paramN & 0x3FL));
                o[i] = a[i] ^ r ^ carry;
            }
            o[_vecNSize64 - 1] &= _redMask;
        }

        internal static void AddLongs(long[] res, long[] a, long[] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                res[i] = a[i] ^ b[i];
            }
        }
    }
}
