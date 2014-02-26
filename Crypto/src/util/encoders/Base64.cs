using System;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Utilities.Encoders
{
	public sealed class Base64
	{
		private Base64()
		{
		}

		/**
		 * encode the input data producing a base 64 encoded byte array.
		 *
		 * @return a byte array containing the base 64 encoded data.
		 */
		public static byte[] Encode(
			byte[] data)
		{
			string s = Convert.ToBase64String(data, 0, data.Length);
            return Strings.ToAsciiByteArray(s);
		}

		/**
		 * Encode the byte data to base 64 writing it to the given output stream.
		 *
		 * @return the number of bytes produced.
		 */
		public static int Encode(
			byte[]	data,
			Stream	outStream)
		{
			string s = Convert.ToBase64String(data, 0, data.Length);
            byte[] encoded = Strings.ToAsciiByteArray(s);
			outStream.Write(encoded, 0, encoded.Length);
			return encoded.Length;
		}

		/**
		 * Encode the byte data to base 64 writing it to the given output stream.
		 *
		 * @return the number of bytes produced.
		 */
		public static int Encode(
			byte[]	data,
			int		off,
			int		length,
			Stream	outStream)
		{
			string s = Convert.ToBase64String(data, off, length);
            byte[] encoded = Strings.ToAsciiByteArray(s);
			outStream.Write(encoded, 0, encoded.Length);
			return encoded.Length;
		}

		/**
		 * decode the base 64 encoded input data. It is assumed the input data is valid.
		 *
		 * @return a byte array representing the decoded data.
		 */
		public static byte[] Decode(
			byte[] data)
		{
            string s = Strings.FromAsciiByteArray(data);
			return Convert.FromBase64String(s);
		}

		/**
		 * decode the base 64 encoded string data - whitespace will be ignored.
		 *
		 * @return a byte array representing the decoded data.
		 */
		public static byte[] Decode(
			string data)
		{
			return Convert.FromBase64String(data);
		}

		/**
		 * decode the base 64 encoded string data writing it to the given output stream,
		 * whitespace characters will be ignored.
		 *
		 * @return the number of bytes produced.
		 */
		public static int Decode(
			string	data,
			Stream	outStream)
		{
			byte[] decoded = Decode(data);
			outStream.Write(decoded, 0, decoded.Length);
			return decoded.Length;
		}
	}
}
