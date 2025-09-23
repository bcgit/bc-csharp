using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class ReedMuller
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

        static void EncodeSub(Codeword codeword, int m)
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

        private static void HadamardTransform(int[] srcCode, int[] desCode)
        {
            int[] srcCodeCopy = Arrays.Clone(srcCode);
            int[] desCodeCopy = Arrays.Clone(desCode);

            for (int i = 0; i < 7; i++)
            {
                for (int j = 0; j < 64; j++)
                {
                    desCodeCopy[j] = srcCodeCopy[2 * j] + srcCodeCopy[2 * j + 1];
                    desCodeCopy[j + 64] = srcCodeCopy[2 * j] - srcCodeCopy[2 * j + 1];
                }

                //swap srcCode and desCode
                int[] tmp = srcCodeCopy; srcCodeCopy = desCodeCopy; desCodeCopy = tmp;
            }

            // swap
            Array.Copy(desCodeCopy, 0, srcCode, 0, srcCode.Length);
            Array.Copy(srcCodeCopy, 0, desCode, 0, desCode.Length);
        }


        private static void ExpandThenSum(int[] desCode, Codeword[] srcCode, int off, int mulParam)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 32; j++)
                {
                    long ii = srcCode[0 + off].type32[i] >> j & 1;
                    desCode[i * 32 + j] = srcCode[0 + off].type32[i] >> j & 1;
                }
            }

            for (int i = 1; i < mulParam; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 32; k++)
                    {
                        desCode[j * 32 + k] += srcCode[i + off].type32[j] >> k & 1;
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

        public static void Encode(long[] codeword, byte[] m, int n1, int mulParam)
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


            int[] cwd64 = new int[codewordCopy.Length * 4];
            int off = 0;
            for (int i = 0; i < codewordCopy.Length; i++)
            {
                Array.Copy(codewordCopy[i].type32, 0, cwd64, off, codewordCopy[i].type32.Length);
                off += 4;
            }

            Utils.FromByte32ArrayToLongArray(codeword, cwd64);
        }

        public static void Decode(byte[] m, long[] codeword, int n1, int mulParam)
        {
            Codeword[] codewordCopy = new Codeword[codeword.Length / 2]; // because each codewordCopy has a 32 bit array size 4
            int[] byteCodeWords = new int[codeword.Length * 2];
            Utils.FromLongArrayToByte32Array(byteCodeWords, codeword);

            for (int i = 0; i < codewordCopy.Length; i++)
            {
                codewordCopy[i] = new Codeword();
                for (int j = 0; j < 4; j++)
                {
                    codewordCopy[i].type32[j] = byteCodeWords[i * 4 + j];
                }
            }

            int[] expandedCodeword = new int[128];


            for (int i = 0; i < n1; i++)
            {
                ExpandThenSum(expandedCodeword, codewordCopy, i * mulParam, mulParam);


                int[] tmp = new int[128];
                HadamardTransform(expandedCodeword, tmp);

                tmp[0] -= 64 * mulParam;
                m[i] = (byte)FindPeaks(tmp);
            }

            int[] cwd64 = new int[codewordCopy.Length * 4];
            int off = 0;
            for (int i = 0; i < codewordCopy.Length; i++)
            {
                Array.Copy(codewordCopy[i].type32, 0, cwd64, off, 4);
                off += 4;
            }
            Utils.FromByte32ArrayToLongArray(codeword, cwd64);
        }
    }
}
