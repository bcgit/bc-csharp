using System;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal static class ReedMuller
    {
        internal static void EncodeSub(int[] output, int m)
        {
            int w0 = Bit0Mask(m >> 7);
            w0 ^= (int)(Bit0Mask(m >> 0) & 0xAAAAAAAA);
            w0 ^= (int)(Bit0Mask(m >> 1) & 0xCCCCCCCC);
            w0 ^= (int)(Bit0Mask(m >> 2) & 0xF0F0F0F0);
            w0 ^= (int)(Bit0Mask(m >> 3) & 0xFF00FF00);
            w0 ^= (int)(Bit0Mask(m >> 4) & 0xFFFF0000);

            int w1 = w0 ^ Bit0Mask(m >> 5);

            int bit0Mask6 = Bit0Mask(m >> 6);
            int w2 = w0 ^ bit0Mask6;
            int w3 = w1 ^ bit0Mask6;

            output[0] = w0;
            output[1] = w1;
            output[2] = w2;
            output[3] = w3;
        }

        private static void HadamardTransform(int[] src, int[] dst)
        {
            for (int i = 0; i < 7; i++)
            {
                for (int j = 0; j < 64; j++)
                {
                    int u = src[2 * j], v = src[2 * j + 1];
                    dst[j     ] = u + v;
                    dst[j + 64] = u - v;
                }

                // Swap
                int[] tmp = src; src = dst; dst = tmp;
            }
        }

        private static void ExpandThenSum(int[] dst, int[] src, int off, int mulParam)
        {
            int srcOff = off * 4;
            {
                for (int j = 0; j < 4; j++)
                {
                    int t = src[srcOff + j];
                    int dstOff = j * 32;
                    for (int k = 0; k < 32; k++)
                    {
                        dst[dstOff + k] = (t >> k) & 1;
                    }
                }
            }

            for (int i = 1; i < mulParam; i++)
            {
                srcOff += 4;
                for (int j = 0; j < 4; j++)
                {
                    int t = src[srcOff + j];
                    int dstOff = j * 32;
                    for (int k = 0; k < 32; k++)
                    {
                        dst[dstOff + k] += (t >> k) & 1;
                    }
                }
            }
        }

        private static int FindPeaks(int[] input)
        {
            int peakAbsVal = 0;
            int peakVal = 0;
            int peakPos = 0;

            for (int i = 0; i < 128; i++)
            {
                int t = input[i];
                int posMask = t > 0 ? -1 : 0;
                int abs = (posMask & t) | (~posMask & -t);

                peakVal = abs > peakAbsVal ? t : peakVal;
                peakPos = abs > peakAbsVal ? i : peakPos;
                peakAbsVal = abs > peakAbsVal ? abs : peakAbsVal;
            }
            int tmp = peakVal > 0 ? 1 : 0;
            peakPos |= 128 * tmp;
            return peakPos;
        }

        private static int Bit0Mask(int b) => -(b & 1);

        public static void Encode(ulong[] codeword, byte[] m, int n1, int mulParam)
        {
            int[] word32 = new int[4];
            int outOff = 0;
            for (int i = 0; i < n1; i++)
            {
                EncodeSub(word32, m[i]);
                long lo = (word32[0] & 0xFFFFFFFFL) | ((long)word32[1] << 32);
                long hi = (word32[2] & 0xFFFFFFFFL) | ((long)word32[3] << 32);
                for (int j = 0; j < mulParam; j++)
                {
                    codeword[outOff    ] = (ulong)lo;
                    codeword[outOff + 1] = (ulong)hi;
                    outOff += 2;
                }
            }
        }

        public static void Decode(byte[] m, ulong[] codeword, int n1, int mulParam)
        {
            int[] byteCodeWords = new int[codeword.Length * 2];
            Utils.FromUInt64ArrayToByte32Array(byteCodeWords, codeword);

            int[] expandedCodeword = new int[128];
            int[] tmp = new int[128];

            for (int i = 0; i < n1; i++)
            {
                ExpandThenSum(expandedCodeword, byteCodeWords, i * mulParam, mulParam);
                HadamardTransform(expandedCodeword, tmp);
                tmp[0] -= 64 * mulParam;
                m[i] = (byte)FindPeaks(tmp);
            }
        }
    }
}
