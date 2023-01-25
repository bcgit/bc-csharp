using System;
using System.IO;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public class ISAPDigest : IDigest
    {
        private ulong x0, x1, x2, x3, x4;
        private ulong t0, t1, t2, t3, t4;
        private MemoryStream buffer = new MemoryStream();

        private void ROUND(ulong C)
        {
            t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
            t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
            t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
            t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
            t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ ROTR(t0, 19) ^ ROTR(t0, 28);
            x1 = t1 ^ ROTR(t1, 39) ^ ROTR(t1, 61);
            x2 = ~(t2 ^ ROTR(t2, 1) ^ ROTR(t2, 6));
            x3 = t3 ^ ROTR(t3, 10) ^ ROTR(t3, 17);
            x4 = t4 ^ ROTR(t4, 7) ^ ROTR(t4, 41);
        }

        private void P12()
        {
            ROUND(0xf0);
            ROUND(0xe1);
            ROUND(0xd2);
            ROUND(0xc3);
            ROUND(0xb4);
            ROUND(0xa5);
            ROUND(0x96);
            ROUND(0x87);
            ROUND(0x78);
            ROUND(0x69);
            ROUND(0x5a);
            ROUND(0x4b);
        }

        private ulong ROTR(ulong x, int n)
        {
            return (x >> n) | (x << (64 - n));
        }

        protected ulong U64BIG(ulong x)
        {
            return ((ROTR(x, 8) & (0xFF000000FF000000UL)) | (ROTR(x, 24) & (0x00FF000000FF0000UL)) |
                (ROTR(x, 40) & (0x0000FF000000FF00UL)) | (ROTR(x, 56) & (0x000000FF000000FFUL)));
        }

        public string AlgorithmName
        {
            get { return "ISAP Hash"; }
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            if (inOff + inLen > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            buffer.Write(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            buffer.Write(input.ToArray(), 0, input.Length);
        }

        public int DoFinal(Span<byte> output)
        {
            byte[] rv = new byte[32];
            int rlt = DoFinal(rv, 0);
            rv.AsSpan(0, 32).CopyTo(output);
            return rlt;
        }

#endif

        public int DoFinal(byte[] output, int outOff)
        {
            if (32 + outOff > output.Length)
            {
                throw new OutputLengthException("output buffer is too short");
            }
            t0 = t1 = t2 = t3 = t4 = 0;
            /* init state */
            x0 = 17191252062196199485UL;
            x1 = 10066134719181819906UL;
            x2 = 13009371945472744034UL;
            x3 = 4834782570098516968UL;
            x4 = 3787428097924915520UL;
            /* absorb */
            byte[] input = buffer.GetBuffer();
            int len = (int)buffer.Length;
            ulong[] in64 = new ulong[len >> 3];
            Pack.LE_To_UInt64(input, 0, in64, 0, in64.Length);
            int idx = 0;
            while (len >= 8)
            {
                x0 ^= U64BIG(in64[idx++]);
                P12();
                len -= 8;
            }
            /* absorb final input block */
            x0 ^= 0x80UL << ((7 - len) << 3);
            while (len > 0)
            {
                x0 ^= (input[(idx << 3) + --len] & 0xFFUL) << ((7 - len) << 3);
            }
            P12();
            // squeeze
            ulong[] out64 = new ulong[4];
            for (idx = 0; idx < 3; ++idx)
            {
                out64[idx] = U64BIG(x0);
                P12();
            }
            /* squeeze final output block */
            out64[idx] = U64BIG(x0);
            Pack.UInt64_To_LE(out64, output, outOff);
            return 32;
        }

        public int GetByteLength()
        {
            throw new NotImplementedException();
        }

        public int GetDigestSize()
        {
            return 32;
        }

        public void Reset()
        {
            buffer.SetLength(0);
        }

        public void Update(byte input)
        {
            buffer.Write(new byte[] { input }, 0, 1);
        }
    }
}
