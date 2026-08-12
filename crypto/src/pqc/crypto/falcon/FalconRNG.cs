using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal class FalconRng
    {
        private static readonly uint[] CW = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

        private readonly byte[] bd;
        private readonly byte[] sd;
        private int ptr;

        internal FalconRng()
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

        internal void Init(ShakeDigest src)
        {
            src.Output(sd, 0, 56);
            this.ptr = this.bd.Length;
        }

        /*
        * PRNG based on ChaCha20.
        *
        * State consists in key (32 bytes) then IV (16 bytes) and block counter (8 bytes). Normally, we should not care
        * about local endianness (this is for a PRNG), but for the NIST competition we need reproducible KAT vectors
        * that work across architectures, so we enforce little-endian interpretation where applicable. Moreover, output
        * words are "spread out" over the output buffer with the interleaving pattern that is naturally obtained from
        * the AVX2 implementation that runs eight ChaCha20 instances in parallel.
        *
        * The block counter is XORed into the first 8 bytes of the IV.
        */

        private void Refill()
        {
            ulong cc = Pack.LE_To_UInt64(this.sd, 48);

            for (int u = 0; u < 8; ++u)
            {
                uint x00 = CW[0];
                uint x01 = CW[1];
                uint x02 = CW[2];
                uint x03 = CW[3];
                uint x04 = Pack.LE_To_UInt32(sd,  0);
                uint x05 = Pack.LE_To_UInt32(sd,  4);
                uint x06 = Pack.LE_To_UInt32(sd,  8);
                uint x07 = Pack.LE_To_UInt32(sd, 12);
                uint x08 = Pack.LE_To_UInt32(sd, 16);
                uint x09 = Pack.LE_To_UInt32(sd, 20);
                uint x10 = Pack.LE_To_UInt32(sd, 24);
                uint x11 = Pack.LE_To_UInt32(sd, 28);
                uint x12 = Pack.LE_To_UInt32(sd, 32);
                uint x13 = Pack.LE_To_UInt32(sd, 36);
                uint x14 = Pack.LE_To_UInt32(sd, 40) ^ (uint)cc;
                uint x15 = Pack.LE_To_UInt32(sd, 44) ^ (uint)(cc >> 32);

                for (int i = 20; i > 0; i -= 2)
                {
                    x00 += x04; x12 = Integers.RotateLeft(x12 ^ x00, 16);
                    x01 += x05; x13 = Integers.RotateLeft(x13 ^ x01, 16);
                    x02 += x06; x14 = Integers.RotateLeft(x14 ^ x02, 16);
                    x03 += x07; x15 = Integers.RotateLeft(x15 ^ x03, 16);

                    x08 += x12; x04 = Integers.RotateLeft(x04 ^ x08, 12);
                    x09 += x13; x05 = Integers.RotateLeft(x05 ^ x09, 12);
                    x10 += x14; x06 = Integers.RotateLeft(x06 ^ x10, 12);
                    x11 += x15; x07 = Integers.RotateLeft(x07 ^ x11, 12);

                    x00 += x04; x12 = Integers.RotateLeft(x12 ^ x00,  8);
                    x01 += x05; x13 = Integers.RotateLeft(x13 ^ x01,  8);
                    x02 += x06; x14 = Integers.RotateLeft(x14 ^ x02,  8);
                    x03 += x07; x15 = Integers.RotateLeft(x15 ^ x03,  8);

                    x08 += x12; x04 = Integers.RotateLeft(x04 ^ x08,  7);
                    x09 += x13; x05 = Integers.RotateLeft(x05 ^ x09,  7);
                    x10 += x14; x06 = Integers.RotateLeft(x06 ^ x10,  7);
                    x11 += x15; x07 = Integers.RotateLeft(x07 ^ x11,  7);

                    x00 += x05; x15 = Integers.RotateLeft(x15 ^ x00, 16);
                    x01 += x06; x12 = Integers.RotateLeft(x12 ^ x01, 16);
                    x02 += x07; x13 = Integers.RotateLeft(x13 ^ x02, 16);
                    x03 += x04; x14 = Integers.RotateLeft(x14 ^ x03, 16);

                    x10 += x15; x05 = Integers.RotateLeft(x05 ^ x10, 12);
                    x11 += x12; x06 = Integers.RotateLeft(x06 ^ x11, 12);
                    x08 += x13; x07 = Integers.RotateLeft(x07 ^ x08, 12);
                    x09 += x14; x04 = Integers.RotateLeft(x04 ^ x09, 12);

                    x00 += x05; x15 = Integers.RotateLeft(x15 ^ x00,  8);
                    x01 += x06; x12 = Integers.RotateLeft(x12 ^ x01,  8);
                    x02 += x07; x13 = Integers.RotateLeft(x13 ^ x02,  8);
                    x03 += x04; x14 = Integers.RotateLeft(x14 ^ x03,  8);

                    x10 += x15; x05 = Integers.RotateLeft(x05 ^ x10,  7);
                    x11 += x12; x06 = Integers.RotateLeft(x06 ^ x11,  7);
                    x08 += x13; x07 = Integers.RotateLeft(x07 ^ x08,  7);
                    x09 += x14; x04 = Integers.RotateLeft(x04 ^ x09,  7);
                }

                x00 += CW[0];
                x01 += CW[1];
                x02 += CW[2];
                x03 += CW[3];
                x04 += Pack.LE_To_UInt32(sd,  0);
                x05 += Pack.LE_To_UInt32(sd,  4);
                x06 += Pack.LE_To_UInt32(sd,  8);
                x07 += Pack.LE_To_UInt32(sd, 12);
                x08 += Pack.LE_To_UInt32(sd, 16);
                x09 += Pack.LE_To_UInt32(sd, 20);
                x10 += Pack.LE_To_UInt32(sd, 24);
                x11 += Pack.LE_To_UInt32(sd, 28);
                x12 += Pack.LE_To_UInt32(sd, 32);
                x13 += Pack.LE_To_UInt32(sd, 36);
                x14 += Pack.LE_To_UInt32(sd, 40) ^ (uint)cc;
                x15 += Pack.LE_To_UInt32(sd, 44) ^ (uint)(cc >> 32);

                ++cc;

                Pack.UInt32_To_LE(x00, bd, (u << 2) + ( 0 << 5));
                Pack.UInt32_To_LE(x01, bd, (u << 2) + ( 1 << 5));
                Pack.UInt32_To_LE(x02, bd, (u << 2) + ( 2 << 5));
                Pack.UInt32_To_LE(x03, bd, (u << 2) + ( 3 << 5));
                Pack.UInt32_To_LE(x04, bd, (u << 2) + ( 4 << 5));
                Pack.UInt32_To_LE(x05, bd, (u << 2) + ( 5 << 5));
                Pack.UInt32_To_LE(x06, bd, (u << 2) + ( 6 << 5));
                Pack.UInt32_To_LE(x07, bd, (u << 2) + ( 7 << 5));
                Pack.UInt32_To_LE(x08, bd, (u << 2) + ( 8 << 5));
                Pack.UInt32_To_LE(x09, bd, (u << 2) + ( 9 << 5));
                Pack.UInt32_To_LE(x10, bd, (u << 2) + (10 << 5));
                Pack.UInt32_To_LE(x11, bd, (u << 2) + (11 << 5));
                Pack.UInt32_To_LE(x12, bd, (u << 2) + (12 << 5));
                Pack.UInt32_To_LE(x13, bd, (u << 2) + (13 << 5));
                Pack.UInt32_To_LE(x14, bd, (u << 2) + (14 << 5));
                Pack.UInt32_To_LE(x15, bd, (u << 2) + (15 << 5));
            }

            Pack.UInt64_To_LE(cc, sd, 48);
            this.ptr = 0;
        }

        /// <summary>Get an 8-bit random value from a PRNG.</summary>
        internal byte GetByte()
        {
            if (this.ptr > this.bd.Length - 1)
            {
                Refill();
            }

            return this.bd[this.ptr++];
        }

        internal void GetUInt24x3(out uint v0, out uint v1, out uint v2)
        {
            /*
             * If there are less than 9 bytes in the buffer, we refill it. This means that we may drop the last few
             * bytes, but this allows for faster extraction code.
             */
            if (this.ptr > this.bd.Length - 9)
            {
                Refill();
            }

            uint t0 = Pack.LE_To_UInt32(this.bd, this.ptr);
            uint t1 = Pack.LE_To_UInt32(this.bd, this.ptr + 4);
            uint t2 = this.bd[this.ptr + 8];

            v0 = t0 & 0xFFFFFFU;
            v1 = (t0 >> 24 | t1 << 8) & 0xFFFFFFU;
            v2 = t1 >> 16 | t2 << 16;

            this.ptr += 9;
        }
    }
}
