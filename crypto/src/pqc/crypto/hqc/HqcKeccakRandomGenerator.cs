using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal sealed class HqcKeccakRandomGenerator
    {
        private readonly ulong[] m_state = new ulong[26];
        private readonly int m_rate;

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
                int rate = 1600 - (bitLength << 1);

                if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
                    throw new InvalidOperationException("invalid rate value");

                m_rate = rate;
                break;
            }
            default:
                throw new ArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
            }
        }

        private void KeccakIncAbsorb(byte[] input, int inputLen)
        {
            int count = 0;
            int rateBytes = m_rate >> 3;
            while (inputLen + (long)m_state[25] >= rateBytes)
            {
                for (int i = 0; i < rateBytes - (long)m_state[25]; i++)
                {
                    int tmp = (int)((long)m_state[25] + i) >> 3;
                    m_state[tmp] ^= (ulong)input[i + count] << (8 * (((int)m_state[25] + i) & 0x07));
                }
                inputLen -= (int)(rateBytes - (long)m_state[25]);
                count += (int)(rateBytes - (long)m_state[25]);
                m_state[25] = 0UL;
                KeccakDigest.KeccakPermutation(m_state);
            }

            for (int i = 0; i < inputLen; i++)
            {
                int tmp = (int)((long)m_state[25] + i) >> 3;
                m_state[tmp] ^= (ulong)input[i + count] << (8 * (((int)m_state[25] + i) & 0x07));
            }

            m_state[25] = (ulong)((long)m_state[25] + inputLen);
        }

        private void KeccakIncFinalize(int p)
        {
            int rateBytes = m_rate >> 3;

            m_state[(int)m_state[25] >> 3] ^= (ulong)p << (int)(8 * (((long)m_state[25]) & 0x07));
            m_state[(rateBytes - 1) >> 3] ^= 128UL << (8 * ((rateBytes - 1) & 0x07));
            m_state[25] = 0UL;
        }

        private void KeccakIncSqueeze(byte[] output, int outLen)
        {
            int rateBytes = m_rate >> 3;
            int i;
            for (i = 0; i < outLen && i < (long)m_state[25]; i++)
            {
                output[i] = (byte)(m_state[(int)((rateBytes - (long)m_state[25] + i) >> 3)] >> (int)(8 * ((rateBytes - (long)m_state[25] + i) & 0x07)));
            }

            int count = i;
            outLen -= i;
            m_state[25] = (ulong)((long)m_state[25] - i);

            while (outLen > 0)
            {
                KeccakDigest.KeccakPermutation(m_state);

                for (i = 0; i < outLen && i < rateBytes; i++)
                {
                    output[count + i] = (byte)(m_state[i >> 3] >> (8 * (i & 0x07)));
                }
                count = count + i;
                outLen -= i;
                m_state[25] = (ulong)(long)(rateBytes - i);
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
            Arrays.Fill(m_state, 0UL);
            KeccakIncAbsorb(input, inLen);
            KeccakIncAbsorb(domain, domain.Length);
            KeccakIncFinalize(0x1F);
            KeccakIncSqueeze(output, 512 / 8);
        }
    }
}
