#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

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
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled)
            {
                Refill_X86_Avx2();
                return;
            }
#endif

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

#if NETCOREAPP3_0_OR_GREATER
        // PSHUFB masks for rotate-left-16 and rotate-left-8 on each uint32 lane.
        // rot16: bytes [b0 b1 b2 b3] -> [b2 b3 b0 b1]; rot8: -> [b3 b0 b1 b2].
        private static readonly Vector128<byte> Rot16Mask128 = Vector128.Create(
            (byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
        private static readonly Vector128<byte> Rot8Mask128 = Vector128.Create(
            (byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
        // AVX2 VPSHUFB operates per 128-bit lane, so the 256-bit mask is the 128-bit one duplicated.
        private static readonly Vector256<byte> Rot16Mask256 = Vector256.Create(Rot16Mask128, Rot16Mask128);
        private static readonly Vector256<byte> Rot8Mask256 = Vector256.Create(Rot8Mask128, Rot8Mask128);

        private void Refill_X86_Avx2()
        {
            if (!Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled)
                throw new PlatformNotSupportedException();

            ulong cc = Pack.LE_To_UInt64(sd, 48);

            // Eight ChaCha20 instances in parallel, one per 32-bit lane, with block counters cc..cc+7.
            var ccLo = Vector256.Create((uint)cc, (uint)(cc + 1), (uint)(cc + 2), (uint)(cc + 3),
                (uint)(cc + 4), (uint)(cc + 5), (uint)(cc + 6), (uint)(cc + 7));
            var ccHi = Vector256.Create((uint)(cc >> 32), (uint)((cc + 1) >> 32), (uint)((cc + 2) >> 32),
                (uint)((cc + 3) >> 32), (uint)((cc + 4) >> 32), (uint)((cc + 5) >> 32), (uint)((cc + 6) >> 32),
                (uint)((cc + 7) >> 32));

            var x00 = Vector256.Create(CW[0]);
            var x01 = Vector256.Create(CW[1]);
            var x02 = Vector256.Create(CW[2]);
            var x03 = Vector256.Create(CW[3]);
            var x04 = Vector256.Create(Pack.LE_To_UInt32(sd,  0));
            var x05 = Vector256.Create(Pack.LE_To_UInt32(sd,  4));
            var x06 = Vector256.Create(Pack.LE_To_UInt32(sd,  8));
            var x07 = Vector256.Create(Pack.LE_To_UInt32(sd, 12));
            var x08 = Vector256.Create(Pack.LE_To_UInt32(sd, 16));
            var x09 = Vector256.Create(Pack.LE_To_UInt32(sd, 20));
            var x10 = Vector256.Create(Pack.LE_To_UInt32(sd, 24));
            var x11 = Vector256.Create(Pack.LE_To_UInt32(sd, 28));
            var x12 = Vector256.Create(Pack.LE_To_UInt32(sd, 32));
            var x13 = Vector256.Create(Pack.LE_To_UInt32(sd, 36));
            var x14 = Avx2.Xor(Vector256.Create(Pack.LE_To_UInt32(sd, 40)), ccLo);
            var x15 = Avx2.Xor(Vector256.Create(Pack.LE_To_UInt32(sd, 44)), ccHi);

            var v00 = x00;
            var v01 = x01;
            var v02 = x02;
            var v03 = x03;
            var v04 = x04;
            var v05 = x05;
            var v06 = x06;
            var v07 = x07;
            var v08 = x08;
            var v09 = x09;
            var v10 = x10;
            var v11 = x11;
            var v12 = x12;
            var v13 = x13;
            var v14 = x14;
            var v15 = x15;

            for (int i = 20; i > 0; i -= 2)
            {
                QuarterRound(ref v00, ref v04, ref v08, ref v12);
                QuarterRound(ref v01, ref v05, ref v09, ref v13);
                QuarterRound(ref v02, ref v06, ref v10, ref v14);
                QuarterRound(ref v03, ref v07, ref v11, ref v15);

                QuarterRound(ref v00, ref v05, ref v10, ref v15);
                QuarterRound(ref v01, ref v06, ref v11, ref v12);
                QuarterRound(ref v02, ref v07, ref v08, ref v13);
                QuarterRound(ref v03, ref v04, ref v09, ref v14);
            }

            // Lane-contiguous stores reproduce the interleaved output layout of the scalar code.
            Store256_UInt32(Avx2.Add(v00, x00), bd,  0 << 5);
            Store256_UInt32(Avx2.Add(v01, x01), bd,  1 << 5);
            Store256_UInt32(Avx2.Add(v02, x02), bd,  2 << 5);
            Store256_UInt32(Avx2.Add(v03, x03), bd,  3 << 5);
            Store256_UInt32(Avx2.Add(v04, x04), bd,  4 << 5);
            Store256_UInt32(Avx2.Add(v05, x05), bd,  5 << 5);
            Store256_UInt32(Avx2.Add(v06, x06), bd,  6 << 5);
            Store256_UInt32(Avx2.Add(v07, x07), bd,  7 << 5);
            Store256_UInt32(Avx2.Add(v08, x08), bd,  8 << 5);
            Store256_UInt32(Avx2.Add(v09, x09), bd,  9 << 5);
            Store256_UInt32(Avx2.Add(v10, x10), bd, 10 << 5);
            Store256_UInt32(Avx2.Add(v11, x11), bd, 11 << 5);
            Store256_UInt32(Avx2.Add(v12, x12), bd, 12 << 5);
            Store256_UInt32(Avx2.Add(v13, x13), bd, 13 << 5);
            Store256_UInt32(Avx2.Add(v14, x14), bd, 14 << 5);
            Store256_UInt32(Avx2.Add(v15, x15), bd, 15 << 5);

            Pack.UInt64_To_LE(cc + 8, sd, 48);
            this.ptr = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c,
            ref Vector256<uint> d)
        {
            a = Avx2.Add(a, b);
            d = Avx2.Shuffle(Avx2.Xor(d, a).AsByte(), Rot16Mask256).AsUInt32();
            c = Avx2.Add(c, d);
            b = Avx2.Xor(b, c);
            b = Avx2.Xor(Avx2.ShiftLeftLogical(b, 12), Avx2.ShiftRightLogical(b, 20));
            a = Avx2.Add(a, b);
            d = Avx2.Shuffle(Avx2.Xor(d, a).AsByte(), Rot8Mask256).AsUInt32();
            c = Avx2.Add(c, d);
            b = Avx2.Xor(b, c);
            b = Avx2.Xor(Avx2.ShiftLeftLogical(b, 7), Avx2.ShiftRightLogical(b, 25));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Store256_UInt32(Vector256<uint> s, byte[] buf, int off)
        {
            if (Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPackedLittleEndian)
            {
                var t = buf.AsSpan(off);
#if NET8_0_OR_GREATER
                MemoryMarshal.Write(t, in s);
#else
                MemoryMarshal.Write(t, ref s);
#endif
                return;
            }

            for (int i = 0; i < 8; ++i)
            {
                Pack.UInt32_To_LE(s.GetElement(i), buf, off + (i << 2));
            }
        }
#endif

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
