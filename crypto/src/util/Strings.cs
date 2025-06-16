using System;
using System.Diagnostics;
using System.Text;

namespace Org.BouncyCastle.Utilities
{
    /// <summary> General string utilities.</summary>
    public static class Strings
    {
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

        public static byte[] ToByteArray(char[] cs)
        {
            byte[] bs = new byte[cs.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(cs[i]);
            }
            return bs;
        }

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

        public static string FromAsciiByteArray(byte[] bytes) => Encoding.ASCII.GetString(bytes);

        public static string FromAsciiByteArray(byte[] bytes, int index, int count) =>
            Encoding.ASCII.GetString(bytes, index, count);

        public static byte[] ToAsciiByteArray(char[] cs) => Encoding.ASCII.GetBytes(cs);

        public static byte[] ToAsciiByteArray(char[] chars, int index, int count) =>
            Encoding.ASCII.GetBytes(chars, index, count);

        public static byte[] ToAsciiByteArray(string s) => Encoding.ASCII.GetBytes(s);

        public static string FromUtf8ByteArray(byte[] bytes) => Encoding.UTF8.GetString(bytes);

        public static string FromUtf8ByteArray(byte[] bytes, int index, int count) =>
            Encoding.UTF8.GetString(bytes, index, count);

        public static byte[] ToUtf8ByteArray(char[] cs) => Encoding.UTF8.GetBytes(cs);

        public static byte[] ToUtf8ByteArray(char[] chars, int index, int count) =>
            Encoding.UTF8.GetBytes(chars, index, count);

        public static byte[] ToUtf8ByteArray(string s) => Encoding.UTF8.GetBytes(s);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static byte[] ToUtf8ByteArray(ReadOnlySpan<char> cs)
        {
            int count = Encoding.UTF8.GetByteCount(cs);
            byte[] bytes = new byte[count];
            Encoding.UTF8.GetBytes(cs, bytes);
            return bytes;
        }
#endif

        public static byte[] ToUtf8ByteArray(string s, int preAlloc, int postAlloc)
        {
            int byteCount = Encoding.UTF8.GetByteCount(s);
            byte[] array = new byte[preAlloc + byteCount + postAlloc];
            int bytes = Encoding.UTF8.GetBytes(s, 0, s.Length, array, preAlloc);
            Debug.Assert(bytes == byteCount);
            return array;
        }
    }
}
