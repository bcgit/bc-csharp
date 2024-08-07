using System;
using System.Runtime.CompilerServices;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.InteropServices;
using System.Security.Cryptography;
#endif
using System.Text;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Utilities
{
    /// <summary> General array utilities.</summary>
    public static class Arrays
    {
        public static readonly byte[] EmptyBytes = new byte[0];
        public static readonly int[] EmptyInts = new int[0];

        public static bool AreAllZeroes(byte[] buf, int off, int len)
        {
            uint bits = 0;
            for (int i = 0; i < len; ++i)
            {
                bits |= buf[off + i];
            }
            return bits == 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool AreAllZeroes(ReadOnlySpan<byte> buf)
        {
            uint bits = 0;
            for (int i = 0; i < buf.Length; ++i)
            {
                bits |= buf[i];
            }
            return bits == 0;
        }
#endif

        public static bool AreEqual(
            bool[]  a,
            bool[]  b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        public static bool AreEqual(
            char[] a,
            char[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        /// <summary>
        /// Are two arrays equal.
        /// </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(byte[] a, byte[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        public static bool AreEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex)
        {
            int aLength = aToIndex - aFromIndex;
            int bLength = bToIndex - bFromIndex;

            if (aLength != bLength)
                return false;

            for (int i = 0; i < aLength; ++i)
            {
                if (a[aFromIndex + i] != b[bFromIndex + i])
                    return false;
            }

            return true;
        }

        [CLSCompliant(false)]
        public static bool AreEqual(ulong[] a, int aFromIndex, int aToIndex, ulong[] b, int bFromIndex, int bToIndex)
        {
            int aLength = aToIndex - aFromIndex;
            int bLength = bToIndex - bFromIndex;

            if (aLength != bLength)
                return false;

            for (int i = 0; i < aLength; ++i)
            {
                if (a[aFromIndex + i] != b[bFromIndex + i])
                    return false;
            }

            return true;
        }

        public static bool AreEqual(object[] a, object[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            int length = a.Length;
            if (length != b.Length)
                return false;

            for (int i = 0; i < length; ++i)
            {
                if (!Objects.Equals(a[i], b[i]))
                    return false;
            }

            return true;
        }

        public static bool AreEqual(object[] a, int aFromIndex, int aToIndex, object[] b, int bFromIndex, int bToIndex)
        {
            int aLength = aToIndex - aFromIndex;
            int bLength = bToIndex - bFromIndex;

            if (aLength != bLength)
                return false;

            for (int i = 0; i < aLength; ++i)
            {
                if (!Objects.Equals(a[aFromIndex + i], b[bFromIndex + i]))
                    return false;
            }

            return true;
        }

        [Obsolete("Use 'FixedTimeEquals' instead")]
        public static bool ConstantTimeAreEqual(byte[] a, byte[] b)
        {
            return FixedTimeEquals(a, b);
        }

        [Obsolete("Use 'FixedTimeEquals' instead")]
        public static bool ConstantTimeAreEqual(int len, byte[] a, int aOff, byte[] b, int bOff)
        {
            return FixedTimeEquals(len, a, aOff, b, bOff);
        }

#if !(NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
#endif
        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (null == a || null == b)
                return false;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a, b);
#else
            int len = a.Length;
            if (len != b.Length)
                return false;

            int d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= a[i] ^ b[i];
            }
            return 0 == d;
#endif
        }

#if !(NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
#endif
        public static bool FixedTimeEquals(int len, byte[] a, int aOff, byte[] b, int bOff)
        {
            if (null == a)
                throw new ArgumentNullException("a");
            if (null == b)
                throw new ArgumentNullException("b");
            if (len < 0)
                throw new ArgumentException("cannot be negative", "len");
            if (aOff > (a.Length - len))
                throw new IndexOutOfRangeException("'aOff' value invalid for specified length");
            if (bOff > (b.Length - len))
                throw new IndexOutOfRangeException("'bOff' value invalid for specified length");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a.AsSpan(aOff, len), b.AsSpan(bOff, len));
#else
            int d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= a[aOff + i] ^ b[bOff + i];
            }
            return 0 == d;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [Obsolete("Use 'FixedTimeEquals' instead")]
        public static bool ConstantTimeAreEqual(Span<byte> a, Span<byte> b)
        {
            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            return CryptographicOperations.FixedTimeEquals(a, b);
        }
#endif

        public static bool AreEqual(
            int[]	a,
            int[]	b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        [CLSCompliant(false)]
        public static bool AreEqual(uint[] a, uint[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        public static bool AreEqual(long[] a, long[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        [CLSCompliant(false)]
        public static bool AreEqual(ulong[] a, ulong[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        private static bool HaveSameContents(
            bool[] a,
            bool[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(
            char[] a,
            char[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(
            byte[]	a,
            byte[]	b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(
            int[]	a,
            int[]	b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(uint[] a, uint[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(long[] a, long[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(ulong[] a, ulong[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        public static string ToString(
            object[] a)
        {
            StringBuilder sb = new StringBuilder("[");
            if (a.Length > 0)
            {
                sb.Append(a[0]);
                for (int index = 1; index < a.Length; ++index)
                {
                    sb.Append(", ").Append(a[index]);
                }
            }
            sb.Append(']');
            return sb.ToString();
        }

        public static int GetHashCode(byte[] data)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(data);
            return hc.ToHashCode();
#else
            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
#endif
        }

        public static int GetHashCode(byte[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(data.AsSpan(off, len));
            return hc.ToHashCode();
#else
            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[off + i];
            }

            return hc;
#endif
        }

        public static int GetHashCode(int[] data)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan()));
            return hc.ToHashCode();
#else
            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
#endif
        }

        [CLSCompliant(false)]
        public static int GetHashCode(ushort[] data)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan()));
            return hc.ToHashCode();
#else
            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
#endif
        }

        public static int GetHashCode(int[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan(off, len)));
            return hc.ToHashCode();
#else
            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[off + i];
            }

            return hc;
#endif
        }

        [CLSCompliant(false)]
        public static int GetHashCode(uint[] data)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan()));
            return hc.ToHashCode();
#else
            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= (int)data[i];
            }

            return hc;
#endif
        }

        [CLSCompliant(false)]
        public static int GetHashCode(uint[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan(off, len)));
            return hc.ToHashCode();
#else
            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= (int)data[off + i];
            }

            return hc;
#endif
        }

        [CLSCompliant(false)]
        public static int GetHashCode(ulong[] data)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan()));
            return hc.ToHashCode();
#else
            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                ulong di = data[i];
                hc *= 257;
                hc ^= (int)di;
                hc *= 257;
                hc ^= (int)(di >> 32);
            }

            return hc;
#endif
        }

        [CLSCompliant(false)]
        public static int GetHashCode(ulong[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.AddBytes(MemoryMarshal.AsBytes(data.AsSpan(off, len)));
            return hc.ToHashCode();
#else
            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                ulong di = data[off + i];
                hc *= 257;
                hc ^= (int)di;
                hc *= 257;
                hc ^= (int)(di >> 32);
            }

            return hc;
#endif
        }

        public static int GetHashCode(object[] data)
        {
            if (data == null)
                return 0;

            int len = data.Length;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            for (int i = 0; i < len; ++i)
            {
                hc.Add(data[i]);
            }
            return hc.ToHashCode();
#else
            int hc = len + 1;
            for (int i = 0; i < len; ++i)
            {
                hc *= 257;
                hc ^= Objects.GetHashCode(data[i]);
            }
            return hc;
#endif
        }

        public static int GetHashCode(object[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            for (int i = 0; i < len; ++i)
            {
                hc.Add(data[off + i]);
            }
            return hc.ToHashCode();
#else
            int hc = len + 1;
            for (int i = 0; i < len; ++i)
            {
                hc *= 257;
                hc ^= Objects.GetHashCode(data[off + i]);
            }
            return hc;
#endif
        }

        public static bool[] Clone(bool[] data)
        {
            return data == null ? null : (bool[])data.Clone();
        }

        public static byte[] Clone(byte[] data)
        {
            return data == null ? null : (byte[])data.Clone();
        }

        public static short[] Clone(short[] data)
        {
            return data == null ? null : (short[])data.Clone();
        }

        [CLSCompliant(false)]
        public static ushort[] Clone(ushort[] data)
        {
            return data == null ? null : (ushort[])data.Clone();
        }

        public static int[] Clone(int[] data)
        {
            return data == null ? null : (int[])data.Clone();
        }

        [CLSCompliant(false)]
        public static uint[] Clone(uint[] data)
        {
            return data == null ? null : (uint[])data.Clone();
        }

        public static long[] Clone(long[] data)
        {
            return data == null ? null : (long[])data.Clone();
        }

        [CLSCompliant(false)]
        public static ulong[] Clone(ulong[] data)
        {
            return data == null ? null : (ulong[])data.Clone();
        }

        public static byte[] Clone(byte[] data, byte[] existing)
        {
            if (data == null)
                return null;
            if (existing == null || existing.Length != data.Length)
                return Clone(data);
            Array.Copy(data, 0, existing, 0, existing.Length);
            return existing;
        }

        [CLSCompliant(false)]
        public static ulong[] Clone(ulong[] data, ulong[] existing)
        {
            if (data == null)
                return null;
            if (existing == null || existing.Length != data.Length)
                return Clone(data);
            Array.Copy(data, 0, existing, 0, existing.Length);
            return existing;
        }

        public static bool Contains(byte[] a, byte n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        public static bool Contains(short[] a, short n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        public static bool Contains(int[] a, int n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        public static void Fill(byte[] buf, byte b)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Array.Fill(buf, b);
#else
            int i = buf.Length;
            while (i > 0)
            {
                buf[--i] = b;
            }
#endif
        }

        [CLSCompliant(false)]
        public static void Fill(ulong[] buf, ulong b)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Array.Fill(buf, b);
#else
            int i = buf.Length;
            while (i > 0)
            {
                buf[--i] = b;
            }
#endif
        }

        public static void Fill(byte[] buf, int from, int to, byte b)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Array.Fill(buf, b, from, count: to - from);
#else
            for (int i = from; i < to; ++i)
            {
                buf[i] = b;
            }
#endif
        }

        public static void Fill<T>(T[] ts, T t)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Array.Fill(ts, t);
#else
            for (int i = 0; i < ts.Length; ++i)
            {
                ts[i] = t;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Fill<T>(Span<T> ts, T t)
        {
            ts.Fill(t);
        }
#endif

        public static byte[] CopyOf(byte[] data, int newLength)
        {
            byte[] tmp = new byte[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static char[] CopyOf(char[] data, int newLength)
        {
            char[] tmp = new char[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static int[] CopyOf(int[] data, int newLength)
        {
            int[] tmp = new int[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        [CLSCompliant(false)]
        public static uint[] CopyOf(uint[] data, int newLength)
        {
            uint[] tmp = new uint[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static long[] CopyOf(long[] data, int newLength)
        {
            long[] tmp = new long[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static BigInteger[] CopyOf(BigInteger[] data, int newLength)
        {
            BigInteger[] tmp = new BigInteger[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /**
         * Make a copy of a range of bytes from the passed in data array. The range can
         * extend beyond the end of the input array, in which case the return array will
         * be padded with zeroes.
         *
         * @param data the array from which the data is to be copied.
         * @param from the start index at which the copying should take place.
         * @param to the final index of the range (exclusive).
         *
         * @return a new byte array containing the range given.
         */
        public static byte[] CopyOfRange(byte[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            byte[] tmp = new byte[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        public static int[] CopyOfRange(int[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            int[] tmp = new int[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        public static long[] CopyOfRange(long[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            long[] tmp = new long[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        public static BigInteger[] CopyOfRange(BigInteger[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            BigInteger[] tmp = new BigInteger[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        private static int GetLength(int from, int to)
        {
            int newLength = to - from;
            if (newLength < 0)
                throw new ArgumentException(from + " > " + to);
            return newLength;
        }

        public static byte[] Append(byte[] a, byte b)
        {
            if (a == null)
                return new byte[] { b };

            int length = a.Length;
            byte[] result = new byte[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static short[] Append(short[] a, short b)
        {
            if (a == null)
                return new short[] { b };

            int length = a.Length;
            short[] result = new short[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static int[] Append(int[] a, int b)
        {
            if (a == null)
                return new int[] { b };

            int length = a.Length;
            int[] result = new int[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static byte[] Concatenate(byte[] a, byte[] b)
        {
            if (a == null)
                return Clone(b);
            if (b == null)
                return Clone(a);

            byte[] rv = new byte[a.Length + b.Length];
            Array.Copy(a, 0, rv, 0, a.Length);
            Array.Copy(b, 0, rv, a.Length, b.Length);
            return rv;
        }

        [CLSCompliant(false)]
        public static ushort[] Concatenate(ushort[] a, ushort[] b)
        {
            if (a == null)
                return Clone(b);
            if (b == null)
                return Clone(a);

            ushort[] rv = new ushort[a.Length + b.Length];
            Array.Copy(a, 0, rv, 0, a.Length);
            Array.Copy(b, 0, rv, a.Length, b.Length);
            return rv;
        }

        public static byte[] ConcatenateAll(params byte[][] vs)
        {
            byte[][] nonNull = new byte[vs.Length][];
            int count = 0;
            int totalLength = 0;

            for (int i = 0; i < vs.Length; ++i)
            {
                byte[] v = vs[i];
                if (v != null)
                {
                    nonNull[count++] = v;
                    totalLength += v.Length;
                }
            }

            byte[] result = new byte[totalLength];
            int pos = 0;

            for (int j = 0; j < count; ++j)
            {
                byte[] v = nonNull[j];
                Array.Copy(v, 0, result, pos, v.Length);
                pos += v.Length;
            }

            return result;
        }

        public static int[] Concatenate(int[] a, int[] b)
        {
            if (a == null)
                return Clone(b);
            if (b == null)
                return Clone(a);

            int[] rv = new int[a.Length + b.Length];
            Array.Copy(a, 0, rv, 0, a.Length);
            Array.Copy(b, 0, rv, a.Length, b.Length);
            return rv;
        }

        [CLSCompliant(false)]
        public static uint[] Concatenate(uint[] a, uint[] b)
        {
            if (a == null)
                return Clone(b);
            if (b == null)
                return Clone(a);

            uint[] rv = new uint[a.Length + b.Length];
            Array.Copy(a, 0, rv, 0, a.Length);
            Array.Copy(b, 0, rv, a.Length, b.Length);
            return rv;
        }

        public static byte[] Prepend(byte[] a, byte b)
        {
            if (a == null)
                return new byte[] { b };

            int length = a.Length;
            byte[] result = new byte[length + 1];
            Array.Copy(a, 0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static short[] Prepend(short[] a, short b)
        {
            if (a == null)
                return new short[] { b };

            int length = a.Length;
            short[] result = new short[length + 1];
            Array.Copy(a, 0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static int[] Prepend(int[] a, int b)
        {
            if (a == null)
                return new int[] { b };

            int length = a.Length;
            int[] result = new int[length + 1];
            Array.Copy(a, 0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static T[] Prepend<T>(T[] a, T b)
        {
            if (a == null)
                return new T[1]{ b };

            T[] result = new T[1 + a.Length];
            result[0] = b;
            a.CopyTo(result, 1);
            return result;
        }

        public static byte[] Reverse(byte[] a)
        {
            if (a == null)
                return null;

            int p1 = 0, p2 = a.Length;
            byte[] result = new byte[p2];

            while (--p2 >= 0)
            {
                result[p2] = a[p1++];
            }

            return result;
        }

        public static int[] Reverse(int[] a)
        {
            if (a == null)
                return null;

            int p1 = 0, p2 = a.Length;
            int[] result = new int[p2];

            while (--p2 >= 0)
            {
                result[p2] = a[p1++];
            }

            return result;
        }

        internal static void Reverse<T>(T[] input, T[] output)
        {
            int last = input.Length - 1;
            for (int i = 0; i <= last; ++i)
            {
                output[i] = input[last - i];
            }
        }

        public static T[] ReverseInPlace<T>(T[] array)
        {
            if (null == array)
                return null;

            Array.Reverse(array);
            return array;
        }

        public static void Clear(byte[] data)
        {
            if (null != data)
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        public static void Clear(int[] data)
        {
            if (null != data)
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        public static bool IsNullOrContainsNull(object[] array)
        {
            if (null == array)
                return true;

            int count = array.Length;
            for (int i = 0; i < count; ++i)
            {
                if (null == array[i])
                    return true;
            }
            return false;
        }

        public static bool IsNullOrEmpty(byte[] array)
        {
            return null == array || array.Length < 1;
        }

        public static bool IsNullOrEmpty(object[] array)
        {
            return null == array || array.Length < 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER

        public static byte[] Concatenate(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            byte[] rv = new byte[a.Length + b.Length];
            a.CopyTo(rv);
            b.CopyTo(rv.AsSpan(a.Length));
            return rv;
        }

        public static byte[] Concatenate(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
        {
            byte[] rv = new byte[a.Length + b.Length + c.Length];
            a.CopyTo(rv);
            b.CopyTo(rv.AsSpan(a.Length));
            c.CopyTo(rv.AsSpan(a.Length + b.Length));
            return rv;
        }

        public static byte[] Concatenate(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c,
            ReadOnlySpan<byte> d)
        {
            byte[] rv = new byte[a.Length + b.Length + c.Length + d.Length];
            a.CopyTo(rv);
            b.CopyTo(rv.AsSpan(a.Length));
            c.CopyTo(rv.AsSpan(a.Length + b.Length));
            d.CopyTo(rv.AsSpan(a.Length + b.Length + c.Length));
            return rv;
        }

        public static T[] Prepend<T>(ReadOnlySpan<T> a, T b)
        {
            T[] result = new T[1 + a.Length];
            result[0] = b;
            a.CopyTo(result.AsSpan(1));
            return result;
        }
#endif
    }
}
