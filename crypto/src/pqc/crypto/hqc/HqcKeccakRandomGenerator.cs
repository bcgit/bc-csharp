using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal sealed class HqcKeccakRandomGenerator
    {
        private readonly ulong[] state = new ulong[26];
        private readonly byte[] dataQueue = new byte[192];
        private int rate;

        public HqcKeccakRandomGenerator()
            : this(288)
        {
        }

        public HqcKeccakRandomGenerator(int bitLength)
        {
            switch (bitLength)
            {
            case 128:
            case 224:
            case 256:
            case 288:
            case 384:
            case 512:
            {
                this.rate = 1600 - (bitLength << 1);

                if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
                    throw new InvalidOperationException("invalid rate value");

                //Arrays.Fill(state, 0UL);
                //Arrays.Fill(dataQueue, 0);
                break;
            }
            default:
                throw new ArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
            }
        }

        private void KeccakIncAbsorb(byte[] input, int inputLen)
        {
            int count = 0;
            int rateBytes = rate >> 3;
            while (inputLen + (long)state[25] >= rateBytes)
            {
                for (int i = 0; i < rateBytes - (long)state[25]; i++)
                {
                    int tmp = (int)((long)state[25] + i) >> 3;
                    state[tmp] ^= (ulong)input[i + count] << (8 * (((int)state[25] + i) & 0x07));
                }
                inputLen -= (int)(rateBytes - (long)state[25]);
                count += (int) (rateBytes - (long)state[25]);
                state[25] = 0UL;
                KeccakDigest.KeccakPermutation(state);
            }

            for (int i = 0; i < inputLen; i++)
            {
                int tmp = (int)((long)state[25] + i) >> 3;
                state[tmp] ^= (ulong)input[i + count] << (8 * (((int)state[25] + i) & 0x07));
            }

            state[25] = (ulong)((long)state[25] + inputLen);
        }

        private void KeccakIncFinalize(int p)
        {
            int rateBytes = rate >> 3;

            state[(int)state[25] >> 3] ^= (ulong)p << (int)(8 * (((long)state[25]) & 0x07));
            state[(rateBytes - 1) >> 3] ^= 128UL << (8 * ((rateBytes - 1) & 0x07));
            state[25] = 0UL;
        }

        private void KeccakIncSqueeze(byte[] output, int outLen)
        {
            int rateBytes = rate >> 3;
            int i;
            for (i = 0; i < outLen && i < (long)state[25]; i++)
            {
                output[i] = (byte)(state[(int)((rateBytes - (long)state[25] + i) >> 3)] >> (int)(8 * ((rateBytes - (long)state[25] + i) & 0x07)));
            }

            int count = i;
            outLen -= i;
            state[25] = (ulong)((long)state[25] - i);

            while (outLen > 0)
            {
                KeccakDigest.KeccakPermutation(state);

                for (i = 0; i < outLen && i < rateBytes; i++)
                {
                    output[count + i] = (byte)(state[i >> 3] >> (8 * (i & 0x07)));
                }
                count = count + i;
                outLen -= i;
                state[25] = (ulong)(long)(rateBytes - i);
            }
        }

        public void Squeeze(byte[] output, int outLen)
        {
            KeccakIncSqueeze(output, outLen);
        }

        public void RandomGeneratorInit(byte[] entropyInput, byte[] personalizationString, int entropyLen, int perLen)
        {
            byte[] domain = { 1 };
            KeccakIncAbsorb(entropyInput, entropyLen);
            KeccakIncAbsorb(personalizationString, perLen);
            KeccakIncAbsorb(domain, domain.Length);
            KeccakIncFinalize(0x1F);
        }

        public void SeedExpanderInit(byte[] seed, int seedLen)
        {
            byte[] domain = { 2 };
            KeccakIncAbsorb(seed, seedLen);
            KeccakIncAbsorb(domain, 1);
            KeccakIncFinalize(0x1F);
        }

        public void ExpandSeed(byte[] output, int outLen)
        {
            int r = outLen & 7;
            KeccakIncSqueeze(output, outLen - r);

            if (r != 0)
            {
                byte[] tmp = new byte[8];
                KeccakIncSqueeze(tmp, 8);
                Array.Copy(tmp, 0, output, outLen - r, r);
            }
        }

        public void SHAKE256_512_ds(byte[] output, byte[] input, int inLen, byte[] domain)
        {
            Arrays.Fill(state, 0UL);
            KeccakIncAbsorb(input, inLen);
            KeccakIncAbsorb(domain, domain.Length);
            KeccakIncFinalize(0x1F);
            KeccakIncSqueeze(output, 512 / 8);
        }
    }
}
