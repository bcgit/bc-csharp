using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class HqcKeccakRandomGenerator
    {
        private static readonly ulong[] KeccakRoundConstants =
        {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
        };

        protected long[] state = new long[26];
        protected byte[] dataQueue = new byte[192];
        protected int rate;
        protected int bitsInQueue;
        protected int fixedOutputLength;
        protected bool squeezing;

        public HqcKeccakRandomGenerator()
        {
            Init(288);
        }

        public HqcKeccakRandomGenerator(int bitLength)
        {
            Init(bitLength);
        }

        private void Init(int bitLength)
        {
            switch (bitLength)
            {
            case 128:
            case 224:
            case 256:
            case 288:
            case 384:
            case 512:
                InitSponge(1600 - (bitLength << 1));
                break;
            default:
                throw new ArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
            }
        }

        private void InitSponge(int rate)
        {
            if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
                throw new InvalidOperationException("invalid rate value");

            this.rate = rate;
            for (int i = 0; i < state.Length; ++i)
            {
                state[i] = 0L;
            }
            Arrays.Fill(this.dataQueue, 0);
            this.bitsInQueue = 0;
            this.squeezing = false;
            this.fixedOutputLength = (1600 - rate) / 2;
        }

        private void KeccakPermutation()
        {
            long[] A = state;

            long a00 = A[ 0], a01 = A[ 1], a02 = A[ 2], a03 = A[ 3], a04 = A[ 4];
            long a05 = A[ 5], a06 = A[ 6], a07 = A[ 7], a08 = A[ 8], a09 = A[ 9];
            long a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
            long a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
            long a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];

            for (int i = 0; i < 24; i++)
            {
                // theta
                long c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
                long c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
                long c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
                long c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
                long c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

                long d1 = Longs.RotateLeft(c1, 1) ^ c4;
                long d2 = Longs.RotateLeft(c2, 1) ^ c0;
                long d3 = Longs.RotateLeft(c3, 1) ^ c1;
                long d4 = Longs.RotateLeft(c4, 1) ^ c2;
                long d0 = Longs.RotateLeft(c0, 1) ^ c3;

                a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
                a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
                a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
                a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
                a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

                // rho/pi
                c1  = Longs.RotateLeft(a01,  1);
                a01 = Longs.RotateLeft(a06, 44);
                a06 = Longs.RotateLeft(a09, 20);
                a09 = Longs.RotateLeft(a22, 61);
                a22 = Longs.RotateLeft(a14, 39);
                a14 = Longs.RotateLeft(a20, 18);
                a20 = Longs.RotateLeft(a02, 62);
                a02 = Longs.RotateLeft(a12, 43);
                a12 = Longs.RotateLeft(a13, 25);
                a13 = Longs.RotateLeft(a19,  8);
                a19 = Longs.RotateLeft(a23, 56);
                a23 = Longs.RotateLeft(a15, 41);
                a15 = Longs.RotateLeft(a04, 27);
                a04 = Longs.RotateLeft(a24, 14);
                a24 = Longs.RotateLeft(a21,  2);
                a21 = Longs.RotateLeft(a08, 55);
                a08 = Longs.RotateLeft(a16, 45);
                a16 = Longs.RotateLeft(a05, 36);
                a05 = Longs.RotateLeft(a03, 28);
                a03 = Longs.RotateLeft(a18, 21);
                a18 = Longs.RotateLeft(a17, 15);
                a17 = Longs.RotateLeft(a11, 10);
                a11 = Longs.RotateLeft(a07,  6);
                a07 = Longs.RotateLeft(a10,  3);
                a10 = c1;

                // chi
                c0 = a00 ^ (~a01 & a02);
                c1 = a01 ^ (~a02 & a03);
                a02 ^= ~a03 & a04;
                a03 ^= ~a04 & a00;
                a04 ^= ~a00 & a01;
                a00 = c0;
                a01 = c1;

                c0 = a05 ^ (~a06 & a07);
                c1 = a06 ^ (~a07 & a08);
                a07 ^= ~a08 & a09;
                a08 ^= ~a09 & a05;
                a09 ^= ~a05 & a06;
                a05 = c0;
                a06 = c1;

                c0 = a10 ^ (~a11 & a12);
                c1 = a11 ^ (~a12 & a13);
                a12 ^= ~a13 & a14;
                a13 ^= ~a14 & a10;
                a14 ^= ~a10 & a11;
                a10 = c0;
                a11 = c1;

                c0 = a15 ^ (~a16 & a17);
                c1 = a16 ^ (~a17 & a18);
                a17 ^= ~a18 & a19;
                a18 ^= ~a19 & a15;
                a19 ^= ~a15 & a16;
                a15 = c0;
                a16 = c1;

                c0 = a20 ^ (~a21 & a22);
                c1 = a21 ^ (~a22 & a23);
                a22 ^= ~a23 & a24;
                a23 ^= ~a24 & a20;
                a24 ^= ~a20 & a21;
                a20 = c0;
                a21 = c1;

                // iota
                a00 ^= (long) KeccakRoundConstants[i];
            }

            A[0] = a00;
            A[1] = a01;
            A[2] = a02;
            A[3] = a03;
            A[4] = a04;
            A[5] = a05;
            A[6] = a06;
            A[7] = a07;
            A[8] = a08;
            A[9] = a09;
            A[10] = a10;
            A[11] = a11;
            A[12] = a12;
            A[13] = a13;
            A[14] = a14;
            A[15] = a15;
            A[16] = a16;
            A[17] = a17;
            A[18] = a18;
            A[19] = a19;
            A[20] = a20;
            A[21] = a21;
            A[22] = a22;
            A[23] = a23;
            A[24] = a24;
        }

        private void KeccakIncAbsorb(byte[] input, int inputLen)
        {
            if (input == null)
            {
                return;
            }

            int count = 0;
            int rateBytes = rate >> 3;
            while (inputLen + state[25] >= rateBytes)
            {
                for (int i = 0; i < rateBytes - state[25]; i++)
                {
                    int tmp = (int)(state[25] + i) >> 3;
                    state[tmp] ^= (long) (((ulong) (input[i + count] & 0xff)) << (int) (8 * ((state[25] + i) & 0x07)));
                }
                inputLen -= (int) (rateBytes - state[25]);
                count += (int) (rateBytes - state[25]);
                state[25] = 0;
                KeccakPermutation();
            }

            for (int i = 0; i < inputLen; i++)
            {
                int tmp = (int)(state[25] + i) >> 3;
                state[tmp] ^= (long) (((ulong) (input[i + count] & 0xff)) << (int) (8 * ((state[25] + i) & 0x07)));
            }

            state[25] += inputLen;
        }

        private void KeccakIncFinalize(int p)
        {
            int rateBytes = rate >> 3;

            state[(int)state[25] >> 3] ^= (long) (((ulong) (p)) << (int) (8 * ((state[25]) & 0x07)));
            state[(rateBytes - 1) >> 3] ^=((long) (128)) << (8 * ((rateBytes - 1) & 0x07));


            state[25] = 0;
        }

        private void KeccakIncSqueeze(byte[] output, int outLen)
        {
            int rateBytes = rate >> 3;
            int i;
            for (i = 0; i < outLen && i < state[25]; i++)
            {
                output[i] = (byte)(state[(int)((rateBytes - state[25] + i) >> 3)] >> (int) (8 * ((rateBytes - state[25] + i) & 0x07)));
            }

            int count = i;
            outLen -= i;
            state[25] -= i;

            while (outLen > 0)
            {
                KeccakPermutation();

                for (i = 0; i < outLen && i < rateBytes; i++)
                {
                    byte t = (byte)(state[i >> 3] >> (8 * (i & 0x07)));
                    output[count + i] = (byte)(state[i >> 3] >> (8 * (i & 0x07)));
                }
                count = count + i;
                outLen -= i;
                state[25] = rateBytes - i;
            }
        }

        public void Squeeze(byte[] output, int outLen)
        {
            KeccakIncSqueeze(output, outLen);
        }

        public void RandomGeneratorInit(byte[] entropyInput, byte[] personalizationString, int entropyLen, int perLen)
        {
            byte[] domain = new byte[] { 1 };
            KeccakIncAbsorb(entropyInput, entropyLen);
            KeccakIncAbsorb(personalizationString, perLen);
            KeccakIncAbsorb(domain, domain.Length);
            KeccakIncFinalize(0x1F);
        }

        public void SeedExpanderInit(byte[] seed, int seedLen)
        {
            byte[] domain = new byte[] { 2 };
            KeccakIncAbsorb(seed, seedLen);
            KeccakIncAbsorb(domain, 1);
            KeccakIncFinalize(0x1F);
        }

        public void ExpandSeed(byte[] output, int outLen)
        {
            int bSize = 8;
            int r = outLen % bSize;
            byte[] tmp = new byte[bSize];
            KeccakIncSqueeze(output, outLen - r);

            if (r != 0)
            {
                KeccakIncSqueeze(tmp, bSize);
                int count = outLen - r;
                for (int i = 0; i < r; i++)
                {
                    output[count + i] = tmp[i];
                }
            }
        }

        public void SHAKE256_512_ds(byte[] output, byte[] input, int inLen, byte[] domain)
        {
            for (int i = 0; i < state.Length; i++)
            {
                state[i] = 0;
            }
            KeccakIncAbsorb(input, inLen);
            KeccakIncAbsorb(domain, domain.Length);
            KeccakIncFinalize(0x1F);
            KeccakIncSqueeze(output, 512 / 8);
        }
    }
}
