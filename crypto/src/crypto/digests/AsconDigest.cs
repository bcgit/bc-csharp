using System;
using System.IO;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public class AsconDigest : IDigest
    {
        public enum AsconParameters
        {
            AsconHash,
            AsconHashA,
            AsconXof,
            AsconXofA,
        }

        public AsconDigest(AsconParameters parameters)
        {
            switch (parameters)
            {
                case AsconParameters.AsconHash:
                    ASCON_PB_ROUNDS = 12;
                    ASCON_IV = (((ulong)(ASCON_HASH_RATE * 8) << 48) |
                    ((ulong)(ASCON_PA_ROUNDS) << 40) |
                    ((ulong)(ASCON_HASH_BYTES * 8)));
                    algorithmName = "Ascon-Hash";
                    break;
                case AsconParameters.AsconHashA:
                    ASCON_PB_ROUNDS = 8;
                    ASCON_IV = (((ulong)(ASCON_HASH_RATE * 8) << 48) |
                    ((ulong)(ASCON_PA_ROUNDS) << 40) |
                    ((ulong)(ASCON_PA_ROUNDS - ASCON_PB_ROUNDS) << 32) |
                    ((ulong)(ASCON_HASH_BYTES * 8)));
                    algorithmName = "Ascon-HashA";
                    break;
                case AsconParameters.AsconXof:
                    ASCON_PB_ROUNDS = 12;
                    ASCON_IV = (((ulong)(ASCON_HASH_RATE * 8) << 48) |
                    ((ulong)(ASCON_PA_ROUNDS) << 40));
                    algorithmName = "Ascon-Xof";
                    break;
                case AsconParameters.AsconXofA:
                    ASCON_PB_ROUNDS = 8;
                    ASCON_IV = (((ulong)(ASCON_HASH_RATE * 8) << 48) |
                    ((ulong)(ASCON_PA_ROUNDS) << 40) |
                    ((ulong)(ASCON_PA_ROUNDS - ASCON_PB_ROUNDS) << 32));
                    algorithmName = "Ascon-XofA";
                    break;
                default:
                    throw new ArgumentException("Invalid parameter settings for Ascon Hash");
            }
        }

        private string algorithmName;

        private readonly MemoryStream buffer = new MemoryStream();
        private ulong x0;
        private ulong x1;
        private ulong x2;
        private ulong x3;
        private ulong x4;
        private readonly int CRYPTO_BYTES = 32;
        private readonly ulong ASCON_IV;
        private readonly int ASCON_HASH_RATE = 8;
        private readonly int ASCON_PA_ROUNDS = 12;
        private int ASCON_PB_ROUNDS;


        private uint ASCON_HASH_BYTES = 32;

        public string AlgorithmName => algorithmName;

        private ulong ROR(ulong x, int n)
        {
            return x >> n | x << (64 - n);
        }

        private void ROUND(ulong C)
        {
            ulong t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
            ulong t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
            ulong t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
            ulong t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
            ulong t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ ROR(t0, 19) ^ ROR(t0, 28);
            x1 = t1 ^ ROR(t1, 39) ^ ROR(t1, 61);
            x2 = ~(t2 ^ ROR(t2, 1) ^ ROR(t2, 6));
            x3 = t3 ^ ROR(t3, 10) ^ ROR(t3, 17);
            x4 = t4 ^ ROR(t4, 7) ^ ROR(t4, 41);
        }

        private void P(int nr)
        {
            if (nr == 12)
            {
                ROUND(0xf0UL);
                ROUND(0xe1UL);
                ROUND(0xd2UL);
                ROUND(0xc3UL);
            }
            if (nr >= 8)
            {
                ROUND(0xb4UL);
                ROUND(0xa5UL);
            }
            ROUND(0x96UL);
            ROUND(0x87UL);
            ROUND(0x78UL);
            ROUND(0x69UL);
            ROUND(0x5aUL);
            ROUND(0x4bUL);
        }

        private ulong PAD(int i)
        {
            return 0x80UL << (56 - (i << 3));
        }

        private ulong LOADBYTES(byte[] bytes, int inOff, int n)
        {
            ulong x = 0;
            for (int i = 0; i < n; ++i)
            {
                x |= (bytes[i + inOff] & 0xFFUL) << ((7 - i) << 3);
            }
            return x;
        }

        private void STOREBYTES(byte[] bytes, int inOff, ulong w, int n)
        {
            for (int i = 0; i < n; ++i)
            {
                bytes[i + inOff] = (byte)(w >> ((7 - i) << 3));
            }
        }

        public int GetDigestSize()
        {
            return CRYPTO_BYTES;
        }


        public void Update(byte input)
        {
            buffer.Write(new byte[] { input }, 0, 1);
        }


        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            if ((inOff + len) > input.Length)
            {
                throw new DataLengthException("input buffer too ushort");
            }
            buffer.Write(input, inOff, len);
        }


        public int DoFinal(byte[] output, int outOff)
        {
            if (CRYPTO_BYTES + outOff > output.Length)
            {
                throw new OutputLengthException("output buffer is too ushort");
            }
            byte[] input = buffer.GetBuffer();
            int len = (int)buffer.Length;
            int inOff = 0;
            /* initialize */
            x0 = ASCON_IV;
            x1 = 0;
            x2 = 0;
            x3 = 0;
            x4 = 0;
            P(ASCON_PA_ROUNDS);
            /* absorb full plaintext blocks */
            while (len >= ASCON_HASH_RATE)
            {
                x0 ^= LOADBYTES(input, inOff, 8);
                P(ASCON_PB_ROUNDS);
                inOff += ASCON_HASH_RATE;
                len -= ASCON_HASH_RATE;
            }
            /* absorb readonly plaintext block */
            x0 ^= LOADBYTES(input, inOff, len);
            x0 ^= PAD(len);
            P(ASCON_PA_ROUNDS);
            /* squeeze full output blocks */
            len = CRYPTO_BYTES;
            while (len > ASCON_HASH_RATE)
            {
                STOREBYTES(output, outOff, x0, 8);
                P(ASCON_PB_ROUNDS);
                outOff += ASCON_HASH_RATE;
                len -= ASCON_HASH_RATE;
            }
            /* squeeze readonly output block */
            STOREBYTES(output, outOff, x0, len);
            return CRYPTO_BYTES;
        }


        public void Reset()
        {
            buffer.SetLength(0);
        }

        public int GetByteLength()
        {
            throw new NotImplementedException();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            byte[] rv = new byte[32];
            int rlt = DoFinal(rv, 0);
            rv.AsSpan(0, 32).CopyTo(output);
            return rlt;
        }

        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            buffer.Write(input.ToArray(), 0, input.Length);
        }
#endif
    }
}

