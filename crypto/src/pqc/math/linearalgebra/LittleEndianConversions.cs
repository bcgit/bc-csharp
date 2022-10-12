
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    /**
 * This is a utility class containing data type conversions using little-endian
 * byte order.
 *
 */
    class LittleEndianConversions
    {
        /**
     * Default constructor (private).
     */
        private LittleEndianConversions()
        {
            // empty
        }

        /**
         * Convert an octet string of length 4 to an integer. No length checking is
         * performed.
         *
         * @param input the byte array holding the octet string
         * @return an integer representing the octet string <tt>input</tt>
         * @throws ArithmeticException if the length of the given octet string is larger than 4.
         */
        public static int OS2IP(byte[] input)
        {
            return (int)Pack.LE_To_UInt32(input);
        }

        /**
         * Convert an byte array of length 4 beginning at <tt>offset</tt> into an
         * integer.
         *
         * @param input the byte array
         * @param inOff the offset into the byte array
         * @return the resulting integer
         */
        public static int OS2IP(byte[] input, int inOff)
        {
            return (int)Pack.LE_To_UInt32(input, inOff);
        }

        /**
         * Convert a byte array of the given length beginning at <tt>offset</tt>
         * into an integer.
         *
         * @param input the byte array
         * @param inOff the offset into the byte array
         * @param inLen the length of the encoding
         * @return the resulting integer
         */
        public static int OS2IP(byte[] input, int inOff, int inLen)
        {
            int result = 0;
            for (int i = inLen - 1; i >= 0; i--)
            {
                result |= (input[inOff + i] & 0xff) << (8 * i);
            }
            return result;
        }

        /**
         * Convert a byte array of length 8 beginning at <tt>inOff</tt> into a
         * long integer.
         *
         * @param input the byte array
         * @param inOff the offset into the byte array
         * @return the resulting long integer
         */
        public static long OS2LIP(byte[] input, int inOff)
        {
            return (long)Pack.LE_To_UInt64(input, inOff);
        }

        /**
         * Convert an integer to an octet string of length 4.
         *
         * @param x the integer to convert
         * @return the converted integer
         */
        public static byte[] I2OSP(int x)
        {
            return Pack.UInt32_To_LE((uint)x);
        }

        /**
         * Convert an integer into a byte array beginning at the specified offset.
         *
         * @param value  the integer to convert
         * @param output the byte array to hold the result
         * @param outOff the integer offset into the byte array
         */
        public static void I2OSP(int value, byte[] output, int outOff)
        {
            Pack.UInt32_To_LE((uint)value, output, outOff);
        }

        /**
         * Convert an integer to a byte array beginning at the specified offset. No
         * length checking is performed (i.e., if the integer cannot be encoded with
         * <tt>length</tt> octets, it is truncated).
         *
         * @param value  the integer to convert
         * @param output the byte array to hold the result
         * @param outOff the integer offset into the byte array
         * @param outLen the length of the encoding
         */
        public static void I2OSP(int value, byte[] output, int outOff, int outLen)
        {
            uint valueTmp = (uint)value;
            for (int i = outLen - 1; i >= 0; i--)
            {
                output[outOff + i] = (byte)(valueTmp >> (8 * i));
            }
        }

        /**
         * Convert an integer to a byte array of length 8.
         *
         * @param input the integer to convert
         * @return the converted integer
         */
        public static byte[] I2OSP(long input)
        {
            return Pack.UInt64_To_LE((ulong)input);
        }

        /**
         * Convert an integer to a byte array of length 8.
         *
         * @param input  the integer to convert
         * @param output byte array holding the output
         * @param outOff offset in output array where the result is stored
         */
        public static void I2OSP(long input, byte[] output, int outOff)
        {
            Pack.UInt64_To_LE((ulong)input, output, outOff);
        }

        /**
         * Convert an int array to a byte array of the specified length. No length
         * checking is performed (i.e., if the last integer cannot be encoded with
         * <tt>length % 4</tt> octets, it is truncated).
         *
         * @param input  the int array
         * @param outLen the length of the converted array
         * @return the converted array
         */
        public static byte[] ToByteArray(int[] input, int outLen)
        {
            int intLen = input.Length;
            byte[] result = new byte[outLen];
            int index = 0;
            for (int i = 0; i <= intLen - 2; i++, index += 4)
            {
                I2OSP(input[i], result, index);
            }
            I2OSP(input[intLen - 1], result, index, outLen - index);
            return result;
        }

        /**
         * Convert a byte array to an int array.
         *
         * @param input the byte array
         * @return the converted array
         */
        public static int[] ToIntArray(byte[] input)
        {
            int intLen = (input.Length + 3) / 4;
            int lastLen = input.Length & 0x03;
            int[] result = new int[intLen];

            int index = 0;
            for (int i = 0; i <= intLen - 2; i++, index += 4)
            {
                result[i] = OS2IP(input, index);
            }
            if (lastLen != 0)
            {
                result[intLen - 1] = OS2IP(input, index, lastLen);
            }
            else
            {
                result[intLen - 1] = OS2IP(input, index);
            }

            return result;
        }
    }
}
