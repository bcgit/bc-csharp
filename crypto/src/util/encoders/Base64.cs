using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
    /// <summary>Utility class to decode and encode Base64.</summary>
    // TODO[api] Make static
    public sealed class Base64
    {
        private Base64()
        {
        }

        /// <summary>Encode data as a Base64 string.</summary>
        /// <param name="data">The data to encode.</param>
        /// <returns>The Base64 string.</returns>
        public static string ToBase64String(byte[] data) => Convert.ToBase64String(data, 0, data.Length);

        /// <summary>Encode data as a Base64 string.</summary>
        /// <param name="data">The data to encode.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the data starts.</param>
        /// <param name="length">The number of bytes to encode.</param>
        /// <returns>The Base64 string.</returns>
        public static string ToBase64String(byte[] data, int off, int length) =>
            Convert.ToBase64String(data, off, length);

        /**
         * encode the input data producing a base 64 encoded byte array.
         *
         * @return a byte array containing the base 64 encoded data.
         */
        public static byte[] Encode(byte[] data) => Encode(data, 0, data.Length);

        /**
         * encode the input data producing a base 64 encoded byte array.
         *
         * @return a byte array containing the base 64 encoded data.
         */
        public static byte[] Encode(byte[] data, int off, int length)
        {
            string s = Convert.ToBase64String(data, off, length);
            return Strings.ToAsciiByteArray(s);
        }

        /**
         * Encode the byte data to base 64 writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int Encode(byte[] data, Stream outStream)
        {
            byte[] encoded = Encode(data);
            outStream.Write(encoded, 0, encoded.Length);
            return encoded.Length;
        }

        /**
         * Encode the byte data to base 64 writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int Encode(byte[] data, int off, int length, Stream outStream)
        {
            byte[] encoded = Encode(data, off, length);
            outStream.Write(encoded, 0, encoded.Length);
            return encoded.Length;
        }

        /**
         * decode the base 64 encoded input data. It is assumed the input data is valid.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] Decode(byte[] data) => Decode(data, 0, data.Length);

        /// <summary>Decode Base64 encoded data given as ASCII bytes.</summary>
        /// <param name="data">The encoded data.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the encoded data starts.</param>
        /// <param name="length">The number of bytes of encoded data.</param>
        /// <returns>The decoded bytes.</returns>
        public static byte[] Decode(byte[] data, int off, int length)
        {
            string s = Strings.FromAsciiByteArray(data, off, length);
            return Convert.FromBase64String(s);
        }

        /**
         * decode the base 64 encoded string data - whitespace will be ignored.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] Decode(string data) => Convert.FromBase64String(data);

        /**
         * decode the base 64 encoded string data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
        public static int Decode(string data, Stream outStream)
        {
            byte[] decoded = Decode(data);
            outStream.Write(decoded, 0, decoded.Length);
            return decoded.Length;
        }
    }
}
