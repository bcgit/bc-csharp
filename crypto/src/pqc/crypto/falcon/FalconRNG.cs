using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    class FalconRNG
    {
        byte[] bd;
        //ulong bdummy_u64;
        byte[] sd;
        //ulong sdummy_u64;
        //int type;
        int ptr;

        internal FalconRNG()
        {
            this.bd = new byte[512];
            this.sd = new byte[256];
        }

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

        internal void prng_init(SHAKE256 src)
        {
            /*
            * For reproducibility, enforce little-endian interpretation of the state words.
            */
            byte[] tmp = new byte[56];

            src.i_shake256_extract(tmp,0, 56);
            for (int i = 0; i < 14; i ++)
            {
                uint w =  (uint)tmp[(i << 2) + 0]
                       | ((uint)tmp[(i << 2) + 1] << 8)
                       | ((uint)tmp[(i << 2) + 2] << 16)
                       | ((uint)tmp[(i << 2) + 3] << 24);
                //*(uint *)(this.sd + (i << 2)) = w;
                Pack.UInt32_To_LE(w, this.sd, i << 2);
            }
            //tl = *(uint32_t *)(p->state.d + 48);
            ulong tl = Pack.LE_To_UInt32(this.sd, 48);
            //th = *(uint32_t *)(p->state.d + 52);
            ulong th = Pack.LE_To_UInt32(this.sd, 52);
            Pack.UInt64_To_LE(tl + (th << 32), this.sd, 48);
            this.prng_refill();
        }

        /*
        * PRNG based on ChaCha20.
        *
        * State consists in key (32 bytes) then IV (16 bytes) and block counter
        * (8 bytes). Normally, we should not care about local endianness (this
        * is for a PRNG), but for the NIST competition we need reproducible KAT
        * vectors that work across architectures, so we enforce little-endian
        * interpretation where applicable. Moreover, output words are "spread
        * out" over the output buffer with the interleaving pattern that is
        * naturally obtained from the AVX2 implementation that runs eight
        * ChaCha20 instances in parallel.
        *
        * The block counter is XORed into the first 8 bytes of the IV.
        */
        private void QROUND(uint[] state, int a, int b, int c, int d)
        {
            state[a] += state[b];
            state[d] ^= state[a];
            state[d] = (state[d] << 16) | (state[d] >> 16);
            state[c] += state[d];
            state[b] ^= state[c];
            state[b] = (state[b] << 12) | (state[b] >> 20);
            state[a] += state[b];
            state[d] ^= state[a];
            state[d] = (state[d] <<  8) | (state[d] >> 24);
            state[c] += state[d];
            state[b] ^= state[c];
            state[b] = (state[b] <<  7) | (state[b] >> 25);
        }

        private void prng_refill()
        {
            uint[] CW = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

            /*
            * State uses local endianness. Only the output bytes must be
            * converted to little endian (if used on a big-endian machine).
            */

            ulong cc = Pack.LE_To_UInt64(this.sd, 48);
            uint[] state = new uint[16];

            for (int u = 0; u < 8; u ++)
            {
                Array.Copy(CW, 0, state, 0, 4);
                Pack.LE_To_UInt32(this.sd, 0, state, 4, 12);
                state[14] ^= (uint)cc;
                state[15] ^= (uint)(cc >> 32);

                for (int i = 0; i < 10; i ++)
                {
                    QROUND(state, 0,  4,  8, 12);
                    QROUND(state, 1,  5,  9, 13);
                    QROUND(state, 2,  6, 10, 14);
                    QROUND(state, 3,  7, 11, 15);
                    QROUND(state, 0,  5, 10, 15);
                    QROUND(state, 1,  6, 11, 12);
                    QROUND(state, 2,  7,  8, 13);
                    QROUND(state, 3,  4,  9, 14);
                }

                int v;
                for (v = 0; v < 4; v++)
                {
                    state[v] += CW[v];
                }
                for (v = 4; v < 14; v++)
                {
                    // we multiply the -4 by 4 to account for 4 bytes per int
                    state[v] += Pack.LE_To_UInt32(sd, (4 * v) - 16);
                }

                state[14] += Pack.LE_To_UInt32(sd, 40) ^ (uint)cc;
                state[15] += Pack.LE_To_UInt32(sd, 44) ^ (uint)(cc >> 32);
                ++cc;

                // Mimic the interleaving that is used in the AVX2 implementation.
                for (v = 0; v < 16; v ++)
                {
                    Pack.UInt32_To_LE(state[v], bd, (u << 2) + (v << 5));
                }
            }

            Pack.UInt64_To_LE(cc, sd, 48);
            this.ptr = 0;
        }

        //internal void prng_get_bytes( byte[] dstsrc, int dst, int len)
        //{
        //    int buf = dst;
        //    while (len > 0)
        //    {
        //        int clen = this.bd.Length - this.ptr;
        //        if (clen > len)
        //        {
        //            clen = len;
        //        }
        //        // memcpy(buf, this.bd, clen);
        //        Array.Copy(this.bd, 0, dstsrc, buf, clen);
        //        buf += clen;
        //        len -= clen;
        //        this.ptr += clen;
        //        if (this.ptr == this.bd.Length) {
        //            this.prng_refill();
        //        }
        //    }
        //}

        /*
         * Get a 64-bit random value from a PRNG.
         */
        internal ulong prng_get_u64()
        {
            int u;

            /*
            * If there are less than 9 bytes in the buffer, we refill it.
            * This means that we may drop the last few bytes, but this allows
            * for faster extraction code. Also, it means that we never leave
            * an empty buffer.
            */
            u = this.ptr;
            if (u >= (this.bd.Length) - 9) {
                this.prng_refill();
                u = 0;
            }
            this.ptr = u + 8;

            /*
            * On systems that use little-endian encoding and allow
            * unaligned accesses, we can simply read the data where it is.
            */
            return (ulong)this.bd[u + 0]
                | ((ulong)this.bd[u + 1] << 8)
                | ((ulong)this.bd[u + 2] << 16)
                | ((ulong)this.bd[u + 3] << 24)
                | ((ulong)this.bd[u + 4] << 32)
                | ((ulong)this.bd[u + 5] << 40)
                | ((ulong)this.bd[u + 6] << 48)
                | ((ulong)this.bd[u + 7] << 56);
        }

        /*
        * Get an 8-bit random value from a PRNG.
        */
        internal uint prng_get_u8()
        {
            uint v;

            v = this.bd[this.ptr ++];
            if (this.ptr == this.bd.Length) {
                this.prng_refill();
            }
            return v;
        }
    }
}
