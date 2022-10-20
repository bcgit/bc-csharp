using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class Utils
    {
        internal static void ResizeArray(ulong[] output, int sizeOutBits, ulong[] input, int sizeInBits,
            int n1n2ByteSize, int n1n2Byte64Size)
        {
            ulong mask = 0x7FFFFFFFFFFFFFFFUL;
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
                    output[n1n2Byte64Size - 1] &= mask >> i;
                }
            }
            else
            {
                Array.Copy(input, 0, output, 0, (sizeInBits + 7) / 8);
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

        internal static ulong BitMask(ulong a, ulong b)
        {
            uint tmp = (uint)(a % b);
            return ((1UL << (int)tmp) - 1);
        }

        internal static void FromByteArrayToULongArray(ulong[] output, byte[] input)
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
                output[i] = Pack.LE_To_UInt64(tmp, off);
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

        internal static void FromByte32ArrayToULongArray(ulong[] output, int[] input)
        {
            for (int i = 0; i != input.Length; i += 2)
            {
                output[i / 2] = (uint)input[i];
                output[i / 2] |= (ulong)input[i + 1] << 32;
            }
        }

        internal static void FromByte16ArrayToULongArray(ulong[] output, ushort[] input)
        {
            for (int i = 0; i != input.Length; i += 4)
            {
                output[i / 4] = input[i];
                output[i / 4] |= (ulong)input[i + 1] << 16;
                output[i / 4] |= (ulong)input[i + 2] << 32;
                output[i / 4] |= (ulong)input[i + 3] << 48;
            }
        }

        internal static void FromULongArrayToByte32Array(int[] output, ulong[] input)
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

        internal static void XorULongToByte16Array(ushort[] output, int outOff, ulong input)
        {
            output[outOff + 0] ^= (ushort)input;
            output[outOff + 1] ^= (ushort)(input >> 16);
            output[outOff + 2] ^= (ushort)(input >> 32);
            output[outOff + 3] ^= (ushort)(input >> 48);
        }
    }
}
