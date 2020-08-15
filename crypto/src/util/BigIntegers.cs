using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Utilities
{
    /**
     * BigInteger utilities.
     */
    public abstract class BigIntegers
    {
        private const int MaxIterations = 1000;

        /**
        * Return the passed in value as an unsigned byte array.
        *
        * @param value the value to be converted.
        * @return a byte array without a leading zero byte if present in the signed encoding.
        */
        public static byte[] AsUnsignedByteArray(
            BigInteger n)
        {
            return n.ToByteArrayUnsigned();
        }

        /**
         * Return the passed in value as an unsigned byte array of the specified length, padded with
         * leading zeros as necessary.
         * @param length the fixed length of the result.
         * @param n the value to be converted.
         * @return a byte array padded to a fixed length with leading zeros.
         */
        public static byte[] AsUnsignedByteArray(int length, BigInteger n)
        {
            byte[] bytes = n.ToByteArrayUnsigned();

            if (bytes.Length > length)
                throw new ArgumentException("standard length exceeded", "n");

            if (bytes.Length == length)
                return bytes;

            byte[] tmp = new byte[length];
            Array.Copy(bytes, 0, tmp, tmp.Length - bytes.Length, bytes.Length);
            return tmp;
        }

        /**
         * Write the passed in value as unsigned bytes to the specified buffer range, padded with
         * leading zeros as necessary.
         *
         * @param value
         *            the value to be converted.
         * @param buf
         *            the buffer to which the value is written.
         * @param off
         *            the start offset in array <code>buf</code> at which the data is written.
         * @param len
         *            the fixed length of data written (possibly padded with leading zeros).
         */
        public static void AsUnsignedByteArray(BigInteger value, byte[] buf, int off, int len)
        {
            byte[] bytes = value.ToByteArrayUnsigned();
            if (bytes.Length == len)
            {
                Array.Copy(bytes, 0, buf, off, len);
                return;
            }

            int start = bytes[0] == 0 ? 1 : 0;
            int count = bytes.Length - start;

            if (count > len)
                throw new ArgumentException("standard length exceeded for value");

            int padLen = len - count;
            Arrays.Fill(buf, off, off + padLen, 0);
            Array.Copy(bytes, start, buf, off + padLen, count);
        }

        /// <summary>
        /// Creates a Random BigInteger from the secure random of a given bit length.
        /// </summary>
        /// <param name="bitLength"></param>
        /// <param name="secureRandom"></param>
        /// <returns></returns>
        public static BigInteger CreateRandomBigInteger(int bitLength, SecureRandom secureRandom)
        {
            return new BigInteger(bitLength, secureRandom);
        }

        /**
        * Return a random BigInteger not less than 'min' and not greater than 'max'
        * 
        * @param min the least value that may be generated
        * @param max the greatest value that may be generated
        * @param random the source of randomness
        * @return a random BigInteger value in the range [min,max]
        */
        public static BigInteger CreateRandomInRange(
            BigInteger		min,
            BigInteger		max,
            // TODO Should have been just Random class
            SecureRandom	random)
        {
            int cmp = min.CompareTo(max);
            if (cmp >= 0)
            {
                if (cmp > 0)
                    throw new ArgumentException("'min' may not be greater than 'max'");

                return min;
            }

            if (min.BitLength > max.BitLength / 2)
            {
                return CreateRandomInRange(BigInteger.Zero, max.Subtract(min), random).Add(min);
            }

            for (int i = 0; i < MaxIterations; ++i)
            {
                BigInteger x = new BigInteger(max.BitLength, random);
                if (x.CompareTo(min) >= 0 && x.CompareTo(max) <= 0)
                {
                    return x;
                }
            }

            // fall back to a faster (restricted) method
            return new BigInteger(max.Subtract(min).BitLength - 1, random).Add(min);
        }

        public static int GetUnsignedByteLength(BigInteger n)
        {
            return (n.BitLength + 7) / 8;
        }
    }
}
