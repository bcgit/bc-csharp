#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Diagnostics;
#endif
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
    /// <summary>
    /// Class to decode and encode Hex.
    /// </summary>
    // TODO[api] Make static
    public sealed class Hex
    {
        private static readonly HexEncoder encoder = new HexEncoder();

        private Hex()
        {
        }

        public static string ToHexString(byte[] data) => ToHexString(data, false);

        public static string ToHexString(byte[] data, bool upperCase) => ToHexString(data, 0, data.Length, upperCase);

        public static string ToHexString(byte[] data, int off, int length) => ToHexString(data, off, length, false);

        public static string ToHexString(byte[] data, int off, int length, bool upperCase)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ToHexString(data.AsMemory(off, length), upperCase);
#else
            byte[] hex = Encode(data, off, length);
            var result = Strings.FromAsciiByteArray(hex);
            if (upperCase)
            {
                result = result.ToUpperInvariant();
            }
            return result;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static string ToHexString(ReadOnlyMemory<byte> data, bool upperCase = false)
        {
            if (data.Length == 0)
                return string.Empty;
            if (data.Length > int.MaxValue / 2)
                throw new ArgumentOutOfRangeException(nameof(data));

            if (upperCase)
            {
                return string.Create(data.Length * 2, data, (chars, data) =>
                {
                    int length = HexEncoder.EncodeUpper(data.Span, chars);
                    Debug.Assert(chars.Length == length);
                });
            }
            else
            {
                return string.Create(data.Length * 2, data, (chars, data) =>
                {
                    int length = HexEncoder.EncodeLower(data.Span, chars);
                    Debug.Assert(chars.Length == length);
                });
            }
        }
#endif

        /**
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
        public static byte[] Encode(byte[] data) => Encode(data, 0, data.Length);

        /**
         * encode the input data producing a Hex encoded byte array.
         *
         * @return a byte array containing the Hex encoded data.
         */
        public static byte[] Encode(byte[] data, int off, int length)
        {
            MemoryStream bOut = new MemoryStream(length * 2);

            encoder.Encode(data, off, length, bOut);

            return bOut.ToArray();
        }

        /**
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int Encode(byte[] data, Stream outStream) => encoder.Encode(data, 0, data.Length, outStream);

        /**
         * Hex encode the byte data writing it to the given output stream.
         *
         * @return the number of bytes produced.
         */
        public static int Encode(byte[] data, int off, int length, Stream outStream) =>
            encoder.Encode(data, off, length, outStream);

        /**
         * decode the Hex encoded input data. It is assumed the input data is valid.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] Decode(byte[] data) => Decode(data, 0, data.Length);

        public static byte[] Decode(byte[] data, int off, int length)
        {
            MemoryStream bOut = new MemoryStream((length + 1) / 2);

            encoder.Decode(data, off, length, bOut);

            return bOut.ToArray();
        }

        /**
         * decode the Hex encoded string data - whitespace will be ignored.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] Decode(string data)
        {
            MemoryStream bOut = new MemoryStream((data.Length + 1) / 2);

            encoder.DecodeString(data, bOut);

            return bOut.ToArray();
        }

        /**
         * decode the Hex encoded string data writing it to the given output stream,
         * whitespace characters will be ignored.
         *
         * @return the number of bytes produced.
         */
        public static int Decode(string data, Stream outStream) => encoder.DecodeString(data, outStream);

        /**
         * Decode the hexadecimal-encoded string strictly i.e. any non-hexadecimal characters will be
         * considered an error.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] DecodeStrict(string str) => encoder.DecodeStrict(str, 0, str.Length);

        /**
         * Decode the hexadecimal-encoded string strictly i.e. any non-hexadecimal characters will be
         * considered an error.
         *
         * @return a byte array representing the decoded data.
         */
        public static byte[] DecodeStrict(string str, int off, int len) => encoder.DecodeStrict(str, off, len);
    }
}
