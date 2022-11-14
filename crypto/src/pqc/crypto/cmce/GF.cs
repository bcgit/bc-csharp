using System;
using System.Diagnostics;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    internal interface GF
    {
        ushort GFAdd(ushort left, ushort right);
        uint GFAddExt(uint left, uint right);
        ushort GFFrac(ushort den, ushort num);
        ushort GFInv(ushort input);
        ushort GFIsZero(ushort a);
        ushort GFMul(ushort left, ushort right);
        uint GFMulExt(ushort left, ushort right);
        ushort GFReduce(uint input);
        ushort GFSq(ushort input);
        uint GFSqExt(ushort input);
    }

    internal struct GF12
        : GF
    {
        public ushort GFAdd(ushort left, ushort right)
        {
            return (ushort)(left ^ right);
        }

        public uint GFAddExt(uint left, uint right)
        {
            return left ^ right;
        }

        public ushort GFFrac(ushort den, ushort num)
        {
            return GFMul(GFInv(den), num);
        }

        public ushort GFInv(ushort input)
        {
            ushort tmp_11;
            ushort tmp_1111;

            ushort output = input;

            output = GFSq(output);
            tmp_11 = GFMul(output, input); // 11

            output = GFSq(tmp_11);
            output = GFSq(output);
            tmp_1111 = GFMul(output, tmp_11); // 1111

            output = GFSq(tmp_1111);
            output = GFSq(output);
            output = GFSq(output);
            output = GFSq(output);
            output = GFMul(output, tmp_1111); // 11111111

            output = GFSq(output);
            output = GFSq(output);
            output = GFMul(output, tmp_11); // 1111111111

            output = GFSq(output);
            output = GFMul(output, input); // 11111111111

            return GFSq(output); // 111111111110
        }

        public ushort GFIsZero(ushort a)
        {
            return (ushort)((a - 1) >> 31);
        }

        public ushort GFMul(ushort left, ushort right)
        {
            int x = left;
            int y = right;

            int z = x * (y & 1);
            for (int i = 1; i < 12; i++)
            {
                z ^= x * (y & (1 << i));
            }

            return GFReduce((uint)z);
        }

        public uint GFMulExt(ushort left, ushort right)
        {
            int x = left;
            int y = right;

            int z = x * (y & 1);
            for (int i = 1; i < 12; i++)
            {
                z ^= x * (y & (1 << i));
            }

            return (uint)z;
        }

        public ushort GFReduce(uint x)
        {
            Debug.Assert((x >> 24) == 0);

            uint u0 = x & 0x00000FFFU;
            uint u1 = x >> 12;
            uint u2 = (x & 0x001FF000U) >> 9;
            uint u3 = (x & 0x00E00000U) >> 18;
            uint u4 = x >> 21;

            return (ushort)(u0 ^ u1 ^ u2 ^ u3 ^ u4);
        }

        public ushort GFSq(ushort input)
        {
            uint z = Interleave.Expand16to32(input);
            return GFReduce(z);
        }

        public uint GFSqExt(ushort input)
        {
            return Interleave.Expand16to32(input);
        }
    }

    internal struct GF13
        : GF
    {
        private const int GFMASK = (1 << 13) - 1;

        public ushort GFAdd(ushort left, ushort right)
        {
            return (ushort)(left ^ right);
        }

        public uint GFAddExt(uint left, uint right)
        {
            return left ^ right;
        }

        /* input: field element den, num */
        /* return: (num/den) */
        public ushort GFFrac(ushort den, ushort num)
        {
            ushort tmp_11, tmp_1111, output;

            tmp_11 = GFSqMul(den, den); // ^11
            tmp_1111 = GFSq2Mul(tmp_11, tmp_11); // ^1111
            output = GFSq2(tmp_1111);
            output = GFSq2Mul(output, tmp_1111); // ^11111111
            output = GFSq2(output);
            output = GFSq2Mul(output, tmp_1111); // ^111111111111

            return GFSqMul(output, num); // ^1111111111110 = ^-1
        }

        public ushort GFInv(ushort den)
        {
            return GFFrac(den, 1);
        }

        public ushort GFIsZero(ushort a)
        {
            return (ushort)((a - 1) >> 31);
        }

        public ushort GFMul(ushort in0, ushort in1)
        {
            int x = in0;
            int y = in1;

            int z = x * (y & 1);
            for (int i = 1; i < 13; i++)
            {
                z ^= x * (y & (1 << i));
            }

            return GFReduce((uint)z);
        }

        public uint GFMulExt(ushort in0, ushort in1)
        {
            int x = in0;
            int y = in1;

            int z = x * (y & 1);
            for (int i = 1; i < 13; i++)
            {
                z ^= x * (y & (1 << i));
            }

            return (uint)z;
        }

        public ushort GFReduce(uint x)
        {
            Debug.Assert((x >> 26) == 0);

            uint u0 = x & 0x00001FFFU;
            uint u1 = x >> 13;

            uint t2 = (u1 << 4) ^ (u1 << 3) ^ (u1 << 1);

            uint u2 = t2 >> 13;
            uint u3 = t2 & 0x00001FFFU;
            uint u4 = (u2 << 4) ^ (u2 << 3) ^ (u2 << 1);

            return (ushort)(u0 ^ u1 ^ u2 ^ u3 ^ u4);
        }

        public ushort GFSq(ushort input)
        {
            uint z = Interleave.Expand16to32(input);
            return GFReduce(z);
        }

        public uint GFSqExt(ushort input)
        {
            return Interleave.Expand16to32(input);
        }

        /* input: field element in */
        /* return: (in^2)^2 */
        private ushort GFSq2(ushort input)
        {
            uint z1 = Interleave.Expand16to32(input);
            input = GFReduce(z1);
            uint z2 = Interleave.Expand16to32(input);
            return GFReduce(z2);
        }

        /* input: field element in, m */
        /* return: (in^2)*m */
        private ushort GFSqMul(ushort input, ushort m)
        {
            long t0 = input;
            long t1 = m;

            long x = (t1 << 6) * (t0 & (1 << 6));

            t0 ^= t0 << 7;

            x ^= (t1 << 0) * (t0 & 0x04001);
            x ^= (t1 << 1) * (t0 & 0x08002);
            x ^= (t1 << 2) * (t0 & 0x10004);
            x ^= (t1 << 3) * (t0 & 0x20008);
            x ^= (t1 << 4) * (t0 & 0x40010);
            x ^= (t1 << 5) * (t0 & 0x80020);

            long t;
            t  = x & 0x0000001FFC000000L;
            x ^= (t >> 18) ^ (t >> 20) ^ (t >> 24) ^ (t >> 26);

            return GFReduce((uint)x & 0x03FFFFFFU);
        }

        /* input: field element in, m */
        /* return: ((in^2)^2)*m */
        private ushort GFSq2Mul(ushort input, ushort m)
        {
            long t0 = input;
            long t1 = m;

            long x = (t1 << 18) * (t0 & (1 << 6));

            t0 ^= t0 << 21;

            x ^= (t1 <<  0) * (t0 & (0x010000001L));
            x ^= (t1 <<  3) * (t0 & (0x020000002L));
            x ^= (t1 <<  6) * (t0 & (0x040000004L));
            x ^= (t1 <<  9) * (t0 & (0x080000008L));
            x ^= (t1 << 12) * (t0 & (0x100000010L));
            x ^= (t1 << 15) * (t0 & (0x200000020L));

            long t;
            t  = x & 0x1FFFF80000000000L;
            x ^= (t >> 18) ^ (t >> 20) ^ (t >> 24) ^ (t >> 26);

            t  = x & 0x000007FFFC000000L;
            x ^= (t >> 18) ^ (t >> 20) ^ (t >> 24) ^ (t >> 26);

            return GFReduce((uint)x & 0x03FFFFFFU);
        }
    }
}
