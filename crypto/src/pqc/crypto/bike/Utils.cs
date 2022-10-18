using System;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal class Utils
    {
        internal static byte[] XorBytes(byte[] a, byte[] b, int size)
        {
            byte[] output = new byte[size];

            for (int i = 0; i < size; i++)
            {
                output[i] = (byte)(a[i] ^ b[i]);
            }
            return output;
        }

        internal static int GetHammingWeight(byte[] bytes)
        {
            int hammingWeight = 0;
            for (int i = 0; i < bytes.Length; i++)
            {
                hammingWeight += bytes[i];
            }
            return hammingWeight;
        }

        internal static void FromByteArrayToBitArray(byte[] output, byte[] input)
        {
            int max = (output.Length / 8);
            for (int i = 0; i < max; i++)
            {
                for (int j = 0; j != 8; j++)
                {
                    output[i * 8 + j] = (byte)((input[i] >> j) & 1);
                }
            }
            if (output.Length % 8 != 0)
            {
                int off = max * 8;
                int count = 0;
                while (off < output.Length)
                {
                    output[off++] = (byte)((input[max] >> count) & 1);
                    count++;
                }
            }
        }

        internal static void FromBitArrayToByteArray(byte[] output, byte[] input)
        {
            int count = 0;
            int pos = 0;
            long len = input.Length;
            while (count < len)
            {
                if (count + 8 >= input.Length)
                {// last set of bits cannot have enough 8 bits
                    int b = input[count];
                    for (int j = input.Length - count - 1; j >= 1; j--)
                    { //bin in reversed order
                        b |= input[count + j] << j;
                    }
                    output[pos] = (byte)b;
                }
                else
                {
                    int b = input[count];
                    for (int j = 7; j >= 1; j--)
                    { //bin in reversed order
                        b |= input[count + j] << j;
                    }
                    output[pos] = (byte)b;
                }

                count += 8;
                pos++;
            }
        }

        internal static byte[] RemoveLast0Bits(byte[] output)
        {
            int lastIndexOf1 = 0;
            for (int i = output.Length - 1; i >= 0; i--)
            {
                if (output[i] == 1)
                {
                    lastIndexOf1 = i;
                    break;
                }
            }
            byte[] res = new byte[lastIndexOf1 + 1];
            Array.Copy(output, 0, res, 0, res.Length);
            return res;
        }

        internal static byte[] Append0s(byte[] input, int length)
        {
            byte[] output = new byte[length];
            Array.Copy(input, 0, output, 0, input.Length);
            return output;
        }
    }
}
