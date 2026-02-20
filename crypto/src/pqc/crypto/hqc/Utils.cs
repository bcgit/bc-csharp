using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal static class Utils
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

        internal static void FromUInt64ArrayToByteArray(byte[] output, ulong[] input) =>
            FromUInt64ArrayToByteArray(output, 0, output.Length, input);

        internal static void FromUInt64ArrayToByteArray(byte[] output, int outOff, int outLen, ulong[] input)
        {
            int nsLen = outLen >> 3;
            Pack.UInt64_To_LE(input, 0, nsLen, output, outOff);

            int partial = outLen & 7;
            if (partial != 0)
            {
                Pack.UInt64_To_LE_Low(input[nsLen], output, outOff + outLen - partial, partial);
            }
        }

        internal static void FromByteArrayToUInt64Array(ulong[] output, byte[] input) =>
            FromByteArrayToUInt64Array(output, input, 0, input.Length);

        internal static void FromByteArrayToUInt64Array(ulong[] output, byte[] input, int inOff, int inLen)
        {
            int nsLen = inLen >> 3;
            Pack.LE_To_UInt64(input, inOff, output, 0, nsLen);

            int partial = inLen & 7;
            if (partial != 0)
            {
                output[nsLen] = Pack.LE_To_UInt64_Low(input, inOff + inLen - partial, partial);
            }
        }

        internal static void FromByte32ArrayToUInt64Array(ulong[] output, int[] input)
        {
            for (int i = 0; i != input.Length; i += 2)
            {
                output[i / 2] = (uint)input[i];
                output[i / 2] |= (ulong)input[i + 1] << 32;
            }
        }

        internal static void FromUInt64ArrayToByte32Array(int[] output, ulong[] input)
        {
            for (int i = 0; i != input.Length; i++)
            {
                output[2 * i] = (int)input[i];
                output[2 * i + 1] = (int)(input[i] >> 32);
            }
        }

        internal static int GetByteSizeFromBitSize(int size) => (size + 7) / 8;

        internal static int GetByte64SizeFromBitSize(int size) => (size + 63) / 64;

        internal static int ToUnsigned16Bits(int a) => a & 0xFFFF;
    }
}
