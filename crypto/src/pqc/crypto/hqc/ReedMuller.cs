using System;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal static class ReedMuller
    {
        internal class Codeword
        {
            internal readonly int[] type32;
            internal readonly int[] type8;

            public Codeword()
            {
                type32 = new int[4];
                type8 = new int[16];
            }
        }

        internal static void EncodeSub(Codeword codeword, int m)
        {
            int word1 = Bit0Mask(m >> 7);
            word1 ^= (int)(Bit0Mask(m >> 0) & 0xaaaaaaaa);
            word1 ^= (int)(Bit0Mask(m >> 1) & 0xcccccccc);
            word1 ^= (int)(Bit0Mask(m >> 2) & 0xf0f0f0f0);
            word1 ^= (int)(Bit0Mask(m >> 3) & 0xff00ff00);
            word1 ^= (int)(Bit0Mask(m >> 4) & 0xffff0000);
            codeword.type32[0] = word1;

            word1 ^= Bit0Mask(m >> 5);
            codeword.type32[1] = word1;

            word1 ^= Bit0Mask(m >> 6);
            codeword.type32[3] = word1;

            word1 ^= Bit0Mask(m >> 5);
            codeword.type32[2] = word1;
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

        private static void ExpandThenSum(int[] desCode, Codeword[] srcCode, int off, int mulParam)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 32; j++)
                {
                    desCode[i * 32 + j] = srcCode[off].type32[i] >> j & 1;
                }
            }

            for (int i = 1; i < mulParam; i++)
            {
                int[] type32 = srcCode[off + i].type32;
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 32; k++)
                    {
                        desCode[j * 32 + k] += type32[j] >> k & 1;
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
            Codeword[] codewordCopy = new Codeword[n1 * mulParam];
            for (int i = 0; i < codewordCopy.Length; i++)
            {
                codewordCopy[i] = new Codeword();
            }

            for (int i = 0; i < n1; i++)
            {
                int pos = i * mulParam;
                EncodeSub(codewordCopy[pos], m[i]);

                for (int j = 1; j < mulParam; j++)
                {
                    codewordCopy[pos + j] = codewordCopy[pos];
                }
            }

            CopyCodeword(codeword, codewordCopy);
        }

        public static void Decode(byte[] m, ulong[] codeword, int n1, int mulParam)
        {
            Codeword[] codewordCopy = new Codeword[codeword.Length / 2]; // because each codewordCopy has a 32 bit array size 4
            int[] byteCodeWords = new int[codeword.Length * 2];
            Utils.FromUInt64ArrayToByte32Array(byteCodeWords, codeword);

            for (int i = 0; i < codewordCopy.Length; i++)
            {
                codewordCopy[i] = new Codeword();
                Array.Copy(byteCodeWords, i * 4, codewordCopy[i].type32, 0, 4);
            }

            int[] expandedCodeword = new int[128];
            int[] tmp = new int[128];

            for (int i = 0; i < n1; i++)
            {
                ExpandThenSum(expandedCodeword, codewordCopy, i * mulParam, mulParam);
                HadamardTransform(expandedCodeword, tmp);
                tmp[0] -= 64 * mulParam;
                m[i] = (byte)FindPeaks(tmp);
            }

            CopyCodeword(codeword, codewordCopy);
        }

        private static void CopyCodeword(ulong[] codeword, Codeword[] codewordCopy)
        {
            int[] cwd64 = new int[codewordCopy.Length * 4];
            int off = 0;
            for (int i = 0; i < codewordCopy.Length; i++)
            {
                Array.Copy(codewordCopy[i].type32, 0, cwd64, off, 4);
                off += 4;
            }
            Utils.FromByte32ArrayToUInt64Array(codeword, cwd64);
        }
    }
}
