using System;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using Org.BouncyCastle.Utilities;
#endif

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal sealed class HarakaSXof
        : HarakaSBase
    {
        public string AlgorithmName => "Haraka-S";

        public HarakaSXof(byte[] pkSeed)
        {
            byte[] buf = new byte[640];
            BlockUpdate(pkSeed, 0, pkSeed.Length);
            OutputFinal(buf, 0, buf.Length);
            haraka512_rc = new ulong[10][];
            haraka256_rc = new uint[10][];
            for (int i = 0; i < 10; ++i)
            {
                haraka512_rc[i] = new ulong[8];
                haraka256_rc[i] = new uint[8];
                InterleaveConstant32(haraka256_rc[i], buf, i << 5);
                InterleaveConstant(haraka512_rc[i], buf, i << 6);
            }
        }

        public void Update(byte input)
        {
            buffer[off++] ^= input;
            if (off == 32)
            {
                Haraka512Perm(buffer);
                off = 0;
            }
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            int i = inOff, loop = (len + off) >> 5;
            for (int j = 0; j < loop; ++j)
            {
                while (off < 32)
                {
                    buffer[off++] ^= input[i++];
                }
                Haraka512Perm(buffer);
                off = 0;
            }
            while (i < inOff + len)
            {
                buffer[off++] ^= input[i++];
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            int len = input.Length;
            int i = 0, loop = (len + off) >> 5;
            for (int j = 0; j < loop; ++j)
            {
                while (off < 32)
                {
                    buffer[off++] ^= input[i++];
                }
                Haraka512Perm(buffer);
                off = 0;
            }
            while (i < len)
            {
                buffer[off++] ^= input[i++];
            }
        }
#endif

        public int OutputFinal(byte[] output, int outOff, int len)
        {
            int outLen = len;

            //Finalize
            buffer[off] ^= 0x1F;
            buffer[31] ^= 128;

            //Squeeze
            while (len >= 32)
            {
                Haraka512Perm(buffer);
                Array.Copy(buffer, 0, output, outOff, 32);
                outOff += 32;
                len -= 32;
            }
            if (len > 0)
            {
                Haraka512Perm(buffer);
                Array.Copy(buffer, 0, output, outOff, len);
            }

            Reset();

            return outLen;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int OutputFinal(Span<byte> output)
        {
            int outLen = output.Length;

            //Finalize
            buffer[off] ^= 0x1F;
            buffer[31] ^= 128;

            //Squeeze
            while (output.Length >= 32)
            {
                Haraka512Perm(buffer);
                output[..32].CopyFrom(buffer);
                output = output[32..];
            }
            if (!output.IsEmpty)
            {
                Haraka512Perm(buffer);
                output.CopyFrom(buffer);
            }

            Reset();

            return outLen;
        }
#endif
    }
}
