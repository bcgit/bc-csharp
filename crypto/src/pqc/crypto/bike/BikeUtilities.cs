using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal class BikeUtilities
    {
        internal static void XorTo(byte[] x, byte[] z, int zLen)
        {
            for (int i = 0; i < zLen; ++i)
            {
                z[i] ^= x[i];
            }
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

        internal static byte[] GenerateRandomByteArray(int mod, int size, int weight, IXof digest)
        {
            byte[] buf = new byte[4];
            int highest = Integers.HighestOneBit(mod);
            int mask = highest | (highest - 1);

            byte[] res = new byte[size];
            int count = 0;
            while (count < weight)
            {
                digest.Output(buf, 0, 4);
                int tmp = (int)Pack.LE_To_UInt32(buf) & mask;

                if (tmp < mod && SetBit(res, tmp))
                {
                    ++count;
                }
            }
            return res;
        }

        private static bool SetBit(byte[] a, int position)
        {
            int index = position / 8;
            int pos = position % 8;
            int selector = 1 << pos;
            bool result = (a[index] & selector) == 0;
            a[index] |= (byte)selector;
            return result;
        }
    }
}
