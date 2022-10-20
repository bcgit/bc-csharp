using Org.BouncyCastle.Crypto.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class Utils
    {
        internal static void ResizeArray(long[] output, int sizeOutBits, long[] input, int sizeInBits, int n1n2ByteSize, int n1n2Byte64Size)
        {

            long mask = 0x7FFFFFFFFFFFFFFFl;
            int val = 0;
            if (sizeOutBits < sizeInBits)
            {
                if (sizeOutBits % 64 != 0)
                {
                    val = 64 - (sizeOutBits % 64);
                }

                Array.Copy(input, 0, output, 0, n1n2ByteSize);

                for (int i = 0; i < val; ++i)
                {
                    output[n1n2Byte64Size - 1] &= (mask >> i);
                }
            }
            else
            {
                Array.Copy(input, 0, output, 0, (sizeInBits + 7) / 8);
            }
        }

        internal static long[] FromULongArrayToLongArray(ulong[] input)
        {
            long[] output = new long[input.Length];
            for (int i =0; i< output.Length; i++)
            {
                output[i] = (long) input[i];
            }
            return output;
        }

        internal static void FromByteArrayToBitArray(byte[] output, byte[] input)
        {
            int max = (output.Length / 8);
            for (int i = 0; i < max; i++)
            {
                for (int j = 0; j != 8; j++)
                {
                    output[i * 8 + j] = (byte) UnsignedRightBitShiftLong((input[i] & (1 << j)), j);
                }
            }
            if (output.Length % 8 != 0)
            {
                int off = max * 8;
                int count = 0;
                while (off < output.Length)
                {
                    output[off++] = (byte) UnsignedRightBitShiftLong((input[max] & (1 << count)), count);
                    count++;
                }
            }
        }

        internal static void FromLongArrayToBitArray(byte[] output, long[] input)
        {
            int max = (output.Length / 64);
            for (int i = 0; i < max; i++)
            {
                for (int j = 0; j != 64; j++)
                {
                    output[i * 64 + j] = (byte)UnsignedRightBitShiftLong((input[i] & (1L << j)), j);
                }
            }
            if (output.Length % 64 != 0)
            {
                int off = max * 64;
                int count = 0;
                while (off < output.Length)
                {
                    output[off++] = (byte) UnsignedRightBitShiftLong((input[max] & (1L << count)), count);
                    count++;
                }
            }
        }

        internal static void FromLongArrayToByteArray(byte[] output, long[] input)
        {
            int max = output.Length / 8;
            for (int i = 0; i != max; i++)
            {
                Pack.UInt64_To_LE((ulong) input[i], output, i * 8); 
            }

            if (output.Length % 8 != 0)
            {
                int off = max * 8;
                int count = 0;
                while (off < output.Length)
                {
                    output[off++] = (byte) UnsignedRightBitShiftLong(input[max], (count++ * 8));
                }
            }
        }

        internal static void FromULongArrayToByteArray(byte[] output, ulong[] input)
        {
            int max = output.Length / 8;
            for (int i = 0; i != max; i++)
            {
                Pack.UInt64_To_LE(input[i], output, i * 8);
            }

            if (output.Length % 8 != 0)
            {
                int off = max * 8;
                int count = 0;
                while (off < output.Length)
                {
                    output[off++] = (byte)(input[max] >> (count++ * 8));
                }
            }
        }

        internal static long BitMask(long a, long b)
        {
            int tmp = (int) (a % b);
            return ((1L << tmp) - 1);
        }

        internal static void FromByteArrayToLongArray(long[] output, byte[] input)
        {
            byte[] tmp = input;
            if (input.Length % 8 != 0)
            {
                tmp = new byte[((input.Length + 7) / 8) * 8];
                Array.Copy(input, 0, tmp, 0, input.Length);
            }

            int off = 0;
            for (int i = 0; i < output.Length; i++)
            {
                output[i] = (long) Pack.LE_To_UInt64(tmp, off);
                off += 8;
            }
        }

        internal static void FromByteArrayToByte16Array(int[] output, byte[] input)
        {
            byte[] tmp = input;
            if (input.Length % 2 != 0)
            {
                tmp = new byte[((input.Length + 1) / 2) * 2];
                Array.Copy(input, 0, tmp, 0, input.Length);
            }

            int off = 0;
            for (int i = 0; i < output.Length; i++)
            {
                output[i] = (int)Pack.LE_To_UInt16(tmp, off);
                off += 2;
            }
        }

        internal static void FromByte32ArrayToLongArray(long[] output, int[] input)
        {
            for (int i = 0; i != input.Length; i += 2)
            {
                output[i / 2] = input[i] & 0xffffffffL;
                output[i / 2] |= (long)input[i + 1] << 32;
            }
        }

        internal static void FromByte16ArrayToLongArray(ulong[] output, int[] input)
        {
            for (int i = 0; i != input.Length; i += 4)
            {
                output[i / 4] = (ulong) input[i] & 0xffffL;
                output[i / 4] |= (ulong) input[i + 1] << 16;
                output[i / 4] |= (ulong) input[i + 2] << 32;
                output[i / 4] |= (ulong) input[i + 3] << 48;
            }
        }

        internal static void FromULongArrayToByte16Array(int[] output, ulong[] input)
        {
            for (int i = 0; i != input.Length; i++)
            {
                output[4 * i] = (UInt16)input[i];
                output[4 * i + 1] = (UInt16)(input[i] >> 16);
                output[4 * i + 2] = (UInt16)(input[i] >> 32);
                output[4 * i + 3] = (UInt16)(input[i] >> 48);
            }
        }

        internal static void FromLongArrayToByte32Array(int[] output, long[] input)
        {
            for (int i = 0; i != input.Length; i++)
            {
                output[2 * i] = (int)input[i];
                output[2 * i + 1] = (int)(input[i] >> 32);
            }
        }

        internal static void CopyBytes(int[] src, int offsetSrc, int[] dst, int offsetDst, int lengthBytes)
        {
            Array.Copy(src, offsetSrc, dst, offsetDst, lengthBytes / 2);
        }

        internal static int GetByteSizeFromBitSize(int size)
        {
            return (size + 7) / 8;
        }

        internal  static int GetByte64SizeFromBitSize(int size)
        {
            return (size + 63) / 64;
        }

        internal static int ToUnsigned8bits(int a)
        {
            return a & 0xff;
        }

        internal static int ToUnsigned16Bits(int a)
        {
            return a & 0xffff;
        }

        internal static long UnsignedRightBitShiftLong(long a, int b)
        {
            ulong tmp = (ulong)a;
            tmp >>= b;
            return (long)tmp;
        }

    }
}
