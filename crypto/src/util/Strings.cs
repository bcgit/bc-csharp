using System;
using System.Diagnostics;
using System.Text;

namespace Org.BouncyCastle.Utilities
{
    /// <summary> General string utilities.</summary>
    public static class Strings
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

        /// <summary>
        /// Use instead of <see cref="System.Text.Encoding.UTF8"/> to enable validation.
        /// </summary>
        public static Encoding UTF8 => StrictUtf8;

        internal static void AppendFromByteArray(StringBuilder sb, byte[] buf, int off, int len)
        {
            sb.EnsureCapacity(sb.Length + len);

            for (int i = 0; i < len; ++i)
            {
                sb.Append(Convert.ToChar(buf[off + i]));
            }
        }

        internal static bool IsOneOf(string s, params string[] candidates)
        {
            foreach (string candidate in candidates)
            {
                if (s == candidate)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Convert a byte array (or a segment of one) to a string, treating each byte as one character (ISO 8859-1).
        /// </summary>
        /// <param name="bs">The bytes to convert.</param>
        /// <returns>The resulting string.</returns>
        public static string FromByteArray(byte[] bs)
        {
            if (bs == null)
                throw new ArgumentNullException(nameof(bs));

            int len = bs.Length;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return string.Create(len, bs, (chars, bytes) =>
            {
                for (int i = 0; i < chars.Length; ++i)
                {
                    chars[i] = Convert.ToChar(bytes[i]);
                }
            });
#else
            char[] cs = new char[len];
            for (int i = 0; i < len; ++i)
            {
                cs[i] = Convert.ToChar(bs[i]);
            }
            return new string(cs);
#endif
        }

        /// <summary>
        /// Convert a byte array (or a segment of one) to a string, treating each byte as one character (ISO 8859-1).
        /// </summary>
        /// <param name="buf">The buffer holding the bytes.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the bytes start.</param>
        /// <param name="len">The number of bytes to convert.</param>
        /// <returns>The resulting string.</returns>
        public static string FromByteArray(byte[] buf, int off, int len)
        {
            Arrays.ValidateSegment(buf, off, len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return string.Create(len, buf.AsMemory(off, len), (chars, bytes) =>
            {
                var span = bytes.Span;
                for (int i = 0; i < chars.Length; ++i)
                {
                    chars[i] = Convert.ToChar(span[i]);
                }
            });
#else
            char[] cs = new char[len];
            for (int i = 0; i < len; ++i)
            {
                cs[i] = Convert.ToChar(buf[off + i]);
            }
            return new string(cs);
#endif
        }

        /// <summary>
        /// Convert characters to bytes, one byte per character; the characters must be in the range 0 to 255.
        /// </summary>
        /// <param name="cs">The characters to convert.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] ToByteArray(char[] cs)
        {
            byte[] bs = new byte[cs.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(cs[i]);
            }
            return bs;
        }

        /// <summary>
        /// Convert characters to bytes, one byte per character; the characters must be in the range 0 to 255.
        /// </summary>
        /// <param name="s">The string to convert.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] ToByteArray(string s)
        {
            byte[] bs = new byte[s.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(s[i]);
            }
            return bs;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Convert characters to bytes, one byte per character; the characters must be in the range 0 to 255.
        /// </summary>
        /// <param name="cs">The characters to convert.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] ToByteArray(ReadOnlySpan<char> cs)
        {
            byte[] bs = new byte[cs.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(cs[i]);
            }
            return bs;
        }
#endif

        /// <summary>Decode ASCII bytes into a string.</summary>
        /// <param name="bytes">The bytes to decode.</param>
        /// <returns>The decoded string.</returns>
        public static string FromAsciiByteArray(byte[] bytes) => Encoding.ASCII.GetString(bytes);

        /// <summary>Decode ASCII bytes into a string.</summary>
        /// <param name="bytes">The bytes to decode.</param>
        /// <param name="index">The index of the first byte to decode.</param>
        /// <param name="count">The number of bytes to decode.</param>
        /// <returns>The decoded string.</returns>
        public static string FromAsciiByteArray(byte[] bytes, int index, int count) =>
            Encoding.ASCII.GetString(bytes, index, count);

        /// <summary>Encode characters as ASCII bytes.</summary>
        /// <param name="cs">The characters to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToAsciiByteArray(char[] cs) => Encoding.ASCII.GetBytes(cs);

        /// <summary>Encode characters as ASCII bytes.</summary>
        /// <param name="chars">The characters to encode.</param>
        /// <param name="index">The index of the first character to encode.</param>
        /// <param name="count">The number of characters to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToAsciiByteArray(char[] chars, int index, int count) =>
            Encoding.ASCII.GetBytes(chars, index, count);

        /// <summary>Encode characters as ASCII bytes.</summary>
        /// <param name="s">The string to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToAsciiByteArray(string s) => Encoding.ASCII.GetBytes(s);

        /// <summary>Decode UTF-8 bytes into a string, rejecting invalid sequences.</summary>
        /// <param name="bytes">The bytes to decode.</param>
        /// <returns>The decoded string.</returns>
        public static string FromUtf8ByteArray(byte[] bytes) => StrictUtf8.GetString(bytes);

        /// <summary>Decode UTF-8 bytes into a string, rejecting invalid sequences.</summary>
        /// <param name="bytes">The bytes to decode.</param>
        /// <param name="index">The index of the first byte to decode.</param>
        /// <param name="count">The number of bytes to decode.</param>
        /// <returns>The decoded string.</returns>
        public static string FromUtf8ByteArray(byte[] bytes, int index, int count) =>
            StrictUtf8.GetString(bytes, index, count);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Decode UTF-8 bytes into a string, rejecting invalid sequences.</summary>
        /// <param name="bytes">The bytes to decode.</param>
        /// <returns>The decoded string.</returns>
        public static string FromUtf8ByteArray(ReadOnlySpan<byte> bytes) => StrictUtf8.GetString(bytes);
#endif

        /// <summary>Encode characters as UTF-8 bytes, rejecting invalid surrogate sequences.</summary>
        /// <param name="cs">The characters to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToUtf8ByteArray(char[] cs) => StrictUtf8.GetBytes(cs);

        /// <summary>Encode characters as UTF-8 bytes, rejecting invalid surrogate sequences.</summary>
        /// <param name="chars">The characters to encode.</param>
        /// <param name="index">The index of the first character to encode.</param>
        /// <param name="count">The number of characters to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToUtf8ByteArray(char[] chars, int index, int count) =>
            StrictUtf8.GetBytes(chars, index, count);

        /// <summary>Encode characters as UTF-8 bytes, rejecting invalid surrogate sequences.</summary>
        /// <param name="s">The string to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToUtf8ByteArray(string s) => StrictUtf8.GetBytes(s);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Encode characters as UTF-8 bytes, rejecting invalid surrogate sequences.</summary>
        /// <param name="cs">The characters to encode.</param>
        /// <returns>The encoded bytes.</returns>
        public static byte[] ToUtf8ByteArray(ReadOnlySpan<char> cs)
        {
            int count = StrictUtf8.GetByteCount(cs);
            byte[] bytes = new byte[count];
            StrictUtf8.GetBytes(cs, bytes);
            return bytes;
        }
#endif

        /// <summary>
        /// Encode a string as UTF-8, in an array with extra unused space before and after the encoding.
        /// </summary>
        /// <param name="s">The string to encode.</param>
        /// <param name="preAlloc">The number of unused bytes to leave at the start of the array.</param>
        /// <param name="postAlloc">The number of unused bytes to leave at the end of the array.</param>
        /// <returns>A new array holding the encoding between the reserved regions.</returns>
        public static byte[] ToUtf8ByteArray(string s, int preAlloc, int postAlloc)
        {
            int byteCount = StrictUtf8.GetByteCount(s);
            byte[] array = new byte[preAlloc + byteCount + postAlloc];
            int bytes = StrictUtf8.GetBytes(s, 0, s.Length, array, preAlloc);
            Debug.Assert(bytes == byteCount);
            return array;
        }

        /// <summary>Split a string at each occurrence of a delimiter.</summary>
        /// <param name="input">The string to split.</param>
        /// <param name="delimiter">The delimiter character.</param>
        /// <returns>The parts of the string.</returns>
        public static string[] Split(string input, char delimiter) => input.Split(delimiter);
    }
}
