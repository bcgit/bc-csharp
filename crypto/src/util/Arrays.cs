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
        /// <summary>An empty <see cref="byte"/> array, shared to avoid allocations.</summary>
        public static readonly byte[] EmptyBytes = Array.Empty<byte>();
        /// <summary>An empty <see cref="int"/> array, shared to avoid allocations.</summary>
        public static readonly int[] EmptyInts = Array.Empty<int>();

        /// <summary>
        /// Determine whether every byte in a range of a buffer is zero, without exiting early on the first non-zero
        /// byte.
        /// </summary>
        /// <param name="buf">The buffer to examine.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the range starts.</param>
        /// <param name="len">The number of bytes in the range.</param>
        /// <returns>true if all bytes in the range are zero, false otherwise.</returns>
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
        /// <summary>
        /// Determine whether every byte in a range of a buffer is zero, without exiting early on the first non-zero
        /// byte.
        /// </summary>
        /// <param name="buf">The buffer to examine.</param>
        /// <returns>true if all bytes in the range are zero, false otherwise.</returns>
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

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(bool[] a, bool[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(char[] a, char[] b)
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

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="aFromIndex">The a from index.</param>
        /// <param name="aToIndex">The a to index.</param>
        /// <param name="b">Right side.</param>
        /// <param name="bFromIndex">The b from index.</param>
        /// <param name="bToIndex">The b to index.</param>
        /// <returns>True if equal.</returns>
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

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="aFromIndex">The a from index.</param>
        /// <param name="aToIndex">The a to index.</param>
        /// <param name="b">Right side.</param>
        /// <param name="bFromIndex">The b from index.</param>
        /// <param name="bToIndex">The b to index.</param>
        /// <returns>True if equal.</returns>
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

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
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

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="aFromIndex">The a from index.</param>
        /// <param name="aToIndex">The a to index.</param>
        /// <param name="b">Right side.</param>
        /// <param name="bFromIndex">The b from index.</param>
        /// <param name="bToIndex">The b to index.</param>
        /// <returns>True if equal.</returns>
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

        /// <summary>Compare two byte arrays (or segments of them) in fixed time.</summary>
        /// <param name="a">The first array.</param>
        /// <param name="b">The second array.</param>
        /// <returns>true if the contents are equal, false otherwise.</returns>
        [Obsolete("Use 'FixedTimeEquals' instead")]
        public static bool ConstantTimeAreEqual(byte[] a, byte[] b) => FixedTimeEquals(a, b);

        /// <summary>Compare two byte arrays (or segments of them) in fixed time.</summary>
        /// <param name="len">The number of bytes to compare.</param>
        /// <param name="a">The first array.</param>
        /// <param name="aOff">The offset into <paramref name="a"/> at which to start comparing.</param>
        /// <param name="b">The second array.</param>
        /// <param name="bOff">The offset into <paramref name="b"/> at which to start comparing.</param>
        /// <returns>true if the contents are equal, false otherwise.</returns>
        [Obsolete("Use 'FixedTimeEquals' instead")]
        public static bool ConstantTimeAreEqual(int len, byte[] a, int aOff, byte[] b, int bOff) =>
            FixedTimeEquals(len, a, aOff, b, bOff);

        /// <summary>
        /// Compare two arrays (or segments of them) for equal contents, in time that depends only on the length and not
        /// on the contents.
        /// </summary>
        /// <param name="a">The first array.</param>
        /// <param name="b">The second array.</param>
        /// <returns>true if the contents are equal, false otherwise (including when either array is null).</returns>
        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (null == a || null == b)
                return false;

            return InternalFixedTimeEquals(a, b);
        }

        /// <summary>
        /// Compare two arrays (or segments of them) for equal contents, in time that depends only on the length and not
        /// on the contents.
        /// </summary>
        /// <param name="len">The number of elements to compare.</param>
        /// <param name="a">The first array.</param>
        /// <param name="aOff">The offset into <paramref name="a"/> at which to start comparing.</param>
        /// <param name="b">The second array.</param>
        /// <param name="bOff">The offset into <paramref name="b"/> at which to start comparing.</param>
        /// <returns>true if the contents are equal, false otherwise (including when either array is null).</returns>
        public static bool FixedTimeEquals(int len, byte[] a, int aOff, byte[] b, int bOff)
        {
            if (len < 0)
                throw new ArgumentOutOfRangeException(nameof(len), "cannot be negative");

            ValidateSegment(a, aOff, len);
            ValidateSegment(b, bOff, len);

            return InternalFixedTimeEquals(len, a, aOff, b, bOff);
        }

        /// <summary>
        /// Compare two arrays (or segments of them) for equal contents, in time that depends only on the length and not
        /// on the contents.
        /// </summary>
        /// <param name="len">The number of elements to compare.</param>
        /// <param name="a">The first array.</param>
        /// <param name="aOff">The offset into <paramref name="a"/> at which to start comparing.</param>
        /// <param name="b">The second array.</param>
        /// <param name="bOff">The offset into <paramref name="b"/> at which to start comparing.</param>
        /// <returns>true if the contents are equal, false otherwise (including when either array is null).</returns>
        [CLSCompliant(false)]
        public static bool FixedTimeEquals(int len, ulong[] a, int aOff, ulong[] b, int bOff)
        {
            if (len < 0)
                throw new ArgumentOutOfRangeException(nameof(len), "cannot be negative");

            ValidateSegment(a, aOff, len);
            ValidateSegment(b, bOff, len);

            return InternalFixedTimeEquals(len, a, aOff, b, bOff);
        }

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(int[] a, int[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        [CLSCompliant(false)]
        public static bool AreEqual(uint[] a, uint[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(long[] a, long[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        /// <summary> Are two arrays equal. </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        [CLSCompliant(false)]
        public static bool AreEqual(ulong[] a, ulong[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        private static bool HaveSameContents(bool[] a, bool[] b)
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

        private static bool HaveSameContents(char[] a, char[] b)
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

        private static bool HaveSameContents(byte[] a, byte[] b)
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

        private static bool HaveSameContents(int[] a, int[] b)
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

        /// <summary>Format the elements of an array as a comma-separated list enclosed in square brackets.</summary>
        /// <param name="a">The array to format.</param>
        /// <returns>The string representation of the array.</returns>
        public static string ToString(object[] a)
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        public static int GetHashCode(byte[] data)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the range starts.</param>
        /// <param name="len">The number of elements in the range.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        public static int GetHashCode(byte[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        public static int GetHashCode(int[] data)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        [CLSCompliant(false)]
        public static int GetHashCode(ushort[] data)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the range starts.</param>
        /// <param name="len">The number of elements in the range.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        public static int GetHashCode(int[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        [CLSCompliant(false)]
        public static int GetHashCode(uint[] data)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the range starts.</param>
        /// <param name="len">The number of elements in the range.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        [CLSCompliant(false)]
        public static int GetHashCode(uint[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        [CLSCompliant(false)]
        public static int GetHashCode(ulong[] data)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the range starts.</param>
        /// <param name="len">The number of elements in the range.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
        [CLSCompliant(false)]
        public static int GetHashCode(ulong[] data, int off, int len)
        {
            if (data == null)
                return 0;

#if NET6_0_OR_GREATER
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
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

        /// <summary>Calculate a hash code from the contents of an array (or a range of it).</summary>
        /// <param name="data">The array to hash.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the range starts.</param>
        /// <param name="len">The number of elements in the range.</param>
        /// <returns>The content-based hash code, or 0 if <paramref name="data"/> is null.</returns>
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

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        public static bool[] Clone(bool[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            bool[] result = GC.AllocateUninitializedArray<bool>(data.Length);
#else
            bool[] result = new bool[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(bool));
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        public static byte[] Clone(byte[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            byte[] result = GC.AllocateUninitializedArray<byte>(data.Length);
#else
            byte[] result = new byte[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        public static short[] Clone(short[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            short[] result = GC.AllocateUninitializedArray<short>(data.Length);
#else
            short[] result = new short[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(short));
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        [CLSCompliant(false)]
        public static ushort[] Clone(ushort[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            ushort[] result = GC.AllocateUninitializedArray<ushort>(data.Length);
#else
            ushort[] result = new ushort[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(ushort));
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        public static int[] Clone(int[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            int[] result = GC.AllocateUninitializedArray<int>(data.Length);
#else
            int[] result = new int[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(int));
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        [CLSCompliant(false)]
        public static uint[] Clone(uint[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            uint[] result = GC.AllocateUninitializedArray<uint>(data.Length);
#else
            uint[] result = new uint[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(uint));
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        public static long[] Clone(long[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            long[] result = GC.AllocateUninitializedArray<long>(data.Length);
#else
            long[] result = new long[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(long));
            return result;
        }

        /// <summary>Create a copy of an array.</summary>
        /// <param name="data">The array to copy.</param>
        /// <returns>
        /// A new array with the same contents as <paramref name="data"/>, or null if <paramref name="data"/> is null.
        /// </returns>
        [CLSCompliant(false)]
        public static ulong[] Clone(ulong[] data)
        {
            if (data == null)
                return null;

#if NET5_0_OR_GREATER
            ulong[] result = GC.AllocateUninitializedArray<ulong>(data.Length);
#else
            ulong[] result = new ulong[data.Length];
#endif
            Buffer.BlockCopy(data, 0, result, 0, data.Length * sizeof(ulong));
            return result;
        }

        /// <summary>Copy an array, reusing an existing array for the result when its length matches.</summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="existing">An array that may be overwritten with the copy, or null.</param>
        /// <returns>
        /// <paramref name="existing"/> filled with the contents of <paramref name="data"/> if the lengths match,
        /// otherwise a new copy, or null if <paramref name="data"/> is null.
        /// </returns>
        public static byte[] Clone(byte[] data, byte[] existing)
        {
            if (data == null)
                return null;
            if (existing == null || existing.Length != data.Length)
                return Clone(data);
            Array.Copy(data, 0, existing, 0, existing.Length);
            return existing;
        }

        /// <summary>Copy an array, reusing an existing array for the result when its length matches.</summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="existing">An array that may be overwritten with the copy, or null.</param>
        /// <returns>
        /// <paramref name="existing"/> filled with the contents of <paramref name="data"/> if the lengths match,
        /// otherwise a new copy, or null if <paramref name="data"/> is null.
        /// </returns>
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

        /// <summary>Determine whether an array contains a given value.</summary>
        /// <param name="a">The array to search.</param>
        /// <param name="n">The value to look for.</param>
        /// <returns>true if the value is present in the array, false otherwise.</returns>
        public static bool Contains(byte[] a, byte n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        /// <summary>Determine whether an array contains a given value.</summary>
        /// <param name="a">The array to search.</param>
        /// <param name="n">The value to look for.</param>
        /// <returns>true if the value is present in the array, false otherwise.</returns>
        public static bool Contains(short[] a, short n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        /// <summary>Determine whether an array contains a given value.</summary>
        /// <param name="a">The array to search.</param>
        /// <param name="n">The value to look for.</param>
        /// <returns>true if the value is present in the array, false otherwise.</returns>
        public static bool Contains(int[] a, int n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        /// <summary>Fill an array (or a range of it) with a given value.</summary>
        /// <param name="buf">The array to fill.</param>
        /// <param name="b">The value to store.</param>
        // TODO[api] Redundant with generic version
        public static void Fill(byte[] buf, byte b) => Fill<byte>(buf, b);

        /// <summary>Fill an array (or a range of it) with a given value.</summary>
        /// <param name="buf">The array to fill.</param>
        /// <param name="b">The value to store.</param>
        // TODO[api] Redundant with generic version
        [CLSCompliant(false)]
        public static void Fill(ulong[] buf, ulong b) => Fill<ulong>(buf, b);

        /// <summary>Fill an array (or a range of it) with a given value.</summary>
        /// <param name="buf">The array to fill.</param>
        /// <param name="from">The index at which to start filling (inclusive).</param>
        /// <param name="to">The index at which to stop filling (exclusive).</param>
        /// <param name="b">The value to store.</param>
        // TODO[api] Redundant with generic version
        public static void Fill(byte[] buf, int from, int to, byte b) => Fill<byte>(buf, from, to, b);

        /// <summary>Fill an array (or a range of it) with a given value.</summary>
        /// <param name="ts">The array to fill.</param>
        /// <param name="t">The value to store.</param>
        public static void Fill<T>(T[] ts, T t)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Array.Fill(ts, t);
#else
            ValidateBuffer(ts);
            for (int i = 0; i < ts.Length; ++i)
            {
                ts[i] = t;
            }
#endif
        }

        /// <summary>Fill an array (or a range of it) with a given value.</summary>
        /// <param name="ts">The array to fill.</param>
        /// <param name="from">The index at which to start filling (inclusive).</param>
        /// <param name="to">The index at which to stop filling (exclusive).</param>
        /// <param name="t">The value to store.</param>
        public static void Fill<T>(T[] ts, int from, int to, T t)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Array.Fill(ts, t, startIndex: from, count: to - from);
#else
            ValidateRange(ts, from, to);
            for (int i = from; i < to; ++i)
            {
                ts[i] = t;
            }
#endif
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="newLength">The length of the new array.</param>
        /// <returns>The new array.</returns>
        public static byte[] CopyOf(byte[] data, int newLength)
        {
            byte[] tmp = new byte[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="newLength">The length of the new array.</param>
        /// <returns>The new array.</returns>
        public static char[] CopyOf(char[] data, int newLength)
        {
            char[] tmp = new char[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="newLength">The length of the new array.</param>
        /// <returns>The new array.</returns>
        public static int[] CopyOf(int[] data, int newLength)
        {
            int[] tmp = new int[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="newLength">The length of the new array.</param>
        /// <returns>The new array.</returns>
        [CLSCompliant(false)]
        public static uint[] CopyOf(uint[] data, int newLength)
        {
            uint[] tmp = new uint[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="newLength">The length of the new array.</param>
        /// <returns>The new array.</returns>
        public static long[] CopyOf(long[] data, int newLength)
        {
            long[] tmp = new long[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="newLength">The length of the new array.</param>
        /// <returns>The new array.</returns>
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

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="from">The from.</param>
        /// <param name="to">The to.</param>
        /// <returns>The new array.</returns>
        public static int[] CopyOfRange(int[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            int[] tmp = new int[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="from">The from.</param>
        /// <param name="to">The to.</param>
        /// <returns>The new array.</returns>
        public static long[] CopyOfRange(long[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            long[] tmp = new long[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        /// <summary>
        /// Create a copy of an array with a new length, truncating or padding with default values as needed.
        /// </summary>
        /// <param name="data">The array to copy.</param>
        /// <param name="from">The from.</param>
        /// <param name="to">The to.</param>
        /// <returns>The new array.</returns>
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

        /// <summary>Create a copy of an array with an extra element added at the end.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to append.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
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

        /// <summary>Create a copy of an array with an extra element added at the end.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to append.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
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

        /// <summary>Create a copy of an array with an extra element added at the end.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to append.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
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

        /// <summary>Concatenate two arrays.</summary>
        /// <param name="a">The first array, or null.</param>
        /// <param name="b">The second array, or null.</param>
        /// <returns>
        /// A new array holding the elements of <paramref name="a"/> followed by those of <paramref name="b"/>; null
        /// arrays are treated as empty.
        /// </returns>
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

        /// <summary>Concatenate two arrays.</summary>
        /// <param name="a">The first array, or null.</param>
        /// <param name="b">The second array, or null.</param>
        /// <returns>
        /// A new array holding the elements of <paramref name="a"/> followed by those of <paramref name="b"/>; null
        /// arrays are treated as empty.
        /// </returns>
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

        /// <summary>Concatenate any number of arrays, ignoring null entries.</summary>
        /// <param name="vs">The arrays to concatenate.</param>
        /// <returns>A new array holding the elements of all the non-null arrays, in order.</returns>
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

        /// <summary>Concatenate two arrays.</summary>
        /// <param name="a">The first array, or null.</param>
        /// <param name="b">The second array, or null.</param>
        /// <returns>
        /// A new array holding the elements of <paramref name="a"/> followed by those of <paramref name="b"/>; null
        /// arrays are treated as empty.
        /// </returns>
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

        /// <summary>Concatenate two arrays.</summary>
        /// <param name="a">The first array, or null.</param>
        /// <param name="b">The second array, or null.</param>
        /// <returns>
        /// A new array holding the elements of <paramref name="a"/> followed by those of <paramref name="b"/>; null
        /// arrays are treated as empty.
        /// </returns>
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

        /// <summary>Create a copy of an array with an extra element added at the start.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to prepend.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
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

        /// <summary>Create a copy of an array with an extra element added at the start.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to prepend.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
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

        /// <summary>Create a copy of an array with an extra element added at the start.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to prepend.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
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

        /// <summary>Create a copy of an array with an extra element added at the start.</summary>
        /// <param name="a">The array to extend, or null.</param>
        /// <param name="b">The element to prepend.</param>
        /// <returns>
        /// A new array one element longer than <paramref name="a"/>; if <paramref name="a"/> is null, an array
        /// containing only <paramref name="b"/>.
        /// </returns>
        public static T[] Prepend<T>(T[] a, T b)
        {
            if (a == null)
                return new T[1] { b };

            T[] result = new T[1 + a.Length];
            result[0] = b;
            a.CopyTo(result, 1);
            return result;
        }

        /// <summary>Create a copy of an array with the order of the elements reversed.</summary>
        /// <param name="a">The array to reverse.</param>
        /// <returns>A new array with the elements in reverse order, or null if <paramref name="a"/> is null.</returns>
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

        /// <summary>Create a copy of an array with the order of the elements reversed.</summary>
        /// <param name="a">The array to reverse.</param>
        /// <returns>A new array with the elements in reverse order, or null if <paramref name="a"/> is null.</returns>
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

        /// <summary>Reverse the order of the elements of an array in place.</summary>
        /// <param name="array">The array to reverse.</param>
        /// <returns>The same array, or null if <paramref name="array"/> is null.</returns>
        public static T[] ReverseInPlace<T>(T[] array)
        {
            if (null == array)
                return null;

            Array.Reverse(array);
            return array;
        }

        /// <summary>Reverse the order of a range of elements of an array in place.</summary>
        /// <param name="array">The array to modify.</param>
        /// <param name="index">The index of the first element of the range.</param>
        /// <param name="length">The number of elements in the range.</param>
        public static void ReverseInPlace<T>(T[] array, int index, int length)
        {
            Array.Reverse(array, index, length);
        }

        /// <summary>Set all the elements of an array to zero. Does nothing if the array is null.</summary>
        /// <param name="data">The array to clear.</param>
        public static void Clear(byte[] data)
        {
            if (null != data)
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        /// <summary>Set all the elements of an array to zero. Does nothing if the array is null.</summary>
        /// <param name="data">The array to clear.</param>
        public static void Clear(int[] data)
        {
            if (null != data)
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        /// <summary>Determine whether an array is null or has a null element.</summary>
        /// <param name="array">The array to examine.</param>
        /// <returns>true if the array is null or any element is null, false otherwise.</returns>
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

        /// <summary>Determine whether an array is null or empty.</summary>
        /// <param name="array">The array to examine.</param>
        /// <returns>true if the array is null or has no elements, false otherwise.</returns>
        public static bool IsNullOrEmpty(byte[] array)
        {
            return null == array || array.Length < 1;
        }

        /// <summary>Determine whether an array is null or empty.</summary>
        /// <param name="array">The array to examine.</param>
        /// <returns>true if the array is null or has no elements, false otherwise.</returns>
        public static bool IsNullOrEmpty(object[] array)
        {
            return null == array || array.Length < 1;
        }

        /// <summary>Create a copy of a whole buffer after checking it is not null.</summary>
        /// <param name="buf">The buffer to copy.</param>
        /// <returns>A new array with the same contents.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="buf"/> is null.</exception>
        public static T[] CopyBuffer<T>(T[] buf)
        {
            ValidateBuffer(buf);
            return InternalCopyBuffer(buf);
        }

        /// <summary>
        /// Copy a whole buffer into a segment of another buffer, which must be the same length as the source.
        /// </summary>
        /// <param name="srcBuf">The buffer to copy from.</param>
        /// <param name="dstBuf">The buffer to copy into.</param>
        /// <param name="dstOff">The offset into <paramref name="dstBuf"/> at which to start writing.</param>
        /// <param name="dstLen">
        /// The length of the destination segment, which must equal the length of <paramref name="srcBuf"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="srcBuf"/> or <paramref name="dstBuf"/> is null.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The destination segment is invalid or its length does not match the source.
        /// </exception>
        public static void CopyBufferToSegment<T>(T[] srcBuf, T[] dstBuf, int dstOff, int dstLen)
        {
            ValidateBuffer(srcBuf);
            ValidateSegment(dstBuf, dstOff, dstLen);
            InternalCopyBufferToSegment(srcBuf, dstBuf, dstOff, dstLen);
        }

        /// <summary>Create a copy of a segment of a buffer after validating the segment.</summary>
        /// <param name="buf">The buffer to copy from.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the segment starts.</param>
        /// <param name="len">The length of the segment.</param>
        /// <returns>A new array holding the segment.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="buf"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The segment is not within <paramref name="buf"/>.</exception>
        public static T[] CopySegment<T>(T[] buf, int off, int len)
        {
            ValidateSegment(buf, off, len);
            return InternalCopySegment(buf, off, len);
        }

        /// <summary>Create a new buffer of the given length after validating the length.</summary>
        /// <param name="len">The length of the new buffer.</param>
        /// <returns>A new array of <paramref name="len"/> elements.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="len"/> is negative.</exception>
        public static T[] CreateBuffer<T>(int len)
        {
            ValidateBufferLength(len);
            return new T[len];
        }

        internal static T[] InternalCopyBuffer<T>(T[] buf)
        {
#if NET5_0_OR_GREATER
            T[] result = GC.AllocateUninitializedArray<T>(buf.Length);
#else
            T[] result = new T[buf.Length];
#endif
            Array.Copy(buf, 0, result, 0, buf.Length);
            return result;
        }

        internal static void InternalCopyBufferToSegment<T>(T[] srcBuf, T[] dstBuf, int dstOff, int dstLen)
        {
            if (srcBuf.Length != dstLen)
                throw new ArgumentOutOfRangeException(nameof(dstLen));

            Array.Copy(srcBuf, 0, dstBuf, dstOff, dstLen);
        }

        internal static T[] InternalCopySegment<T>(T[] buf, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return buf.AsSpan(off, len).ToArray();
#else
            T[] result = new T[len];
            Array.Copy(buf, off, result, 0, len);
            return result;
#endif
        }

#if NET6_0_OR_GREATER
        /// <summary>Gets the max length.</summary>
        public static int MaxLength => Array.MaxLength;
#else
        /// <summary>Gets the max length.</summary>
        public static int MaxLength => 0X7FFFFFC7;
#endif

        /// <summary>Determine whether two segments (each given as an offset and a length) overlap.</summary>
        /// <param name="aOff">The offset of the first segment.</param>
        /// <param name="aLen">The length of the first segment.</param>
        /// <param name="bOff">The offset of the second segment.</param>
        /// <param name="bLen">The length of the second segment.</param>
        /// <returns>true if both segments are non-empty and share at least one position, false otherwise.</returns>
        public static bool SegmentsOverlap(int aOff, int aLen, int bOff, int bLen)
        {
            return aLen > 0
                && bLen > 0
                && aOff - bOff < bLen
                && bOff - aOff < aLen;
        }

        /// <summary>Check that a buffer is not null.</summary>
        /// <param name="buf">The buffer to check.</param>
        /// <exception cref="ArgumentNullException"><paramref name="buf"/> is null.</exception>
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void ValidateBuffer<T>(T[] buf)
        {
            if (buf == null)
                throw new ArgumentNullException(nameof(buf));
        }

        /// <summary>Check that a buffer length is not negative.</summary>
        /// <param name="len">The length to check.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="len"/> is negative.</exception>
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void ValidateBufferLength(int len)
        {
            if (len < 0)
                throw new ArgumentOutOfRangeException(nameof(len));
        }

        /// <summary>Check that a range of a buffer is valid.</summary>
        /// <param name="buf">The buffer to check.</param>
        /// <param name="from">The index at which the range starts (inclusive).</param>
        /// <param name="to">The index at which the range ends (exclusive).</param>
        /// <exception cref="ArgumentNullException"><paramref name="buf"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The range is not within <paramref name="buf"/>.</exception>
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void ValidateRange<T>(T[] buf, int from, int to)
        {
            if (buf == null)
                throw new ArgumentNullException(nameof(buf));
            if ((uint)to > buf.Length)
                throw new ArgumentOutOfRangeException(nameof(to));
            if ((uint)from > to)
                throw new ArgumentOutOfRangeException(nameof(from));
        }

        /// <summary>Check that a segment of a buffer is valid.</summary>
        /// <param name="buf">The buffer to check.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the segment starts.</param>
        /// <param name="len">The length of the segment.</param>
        /// <exception cref="ArgumentNullException"><paramref name="buf"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The segment is not within <paramref name="buf"/>.</exception>
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void ValidateSegment<T>(T[] buf, int off, int len)
        {
            if (buf == null)
                throw new ArgumentNullException(nameof(buf));
            if ((uint)off > buf.Length)
                throw new ArgumentOutOfRangeException(nameof(off));
            if ((uint)len > buf.Length - off)
                throw new ArgumentOutOfRangeException(nameof(len));
        }

        /// <summary>
        /// Overwrite a buffer (or a segment of it) with zeros in a way that the compiler is not allowed to optimize
        /// away.
        /// </summary>
        /// <param name="buf">The buffer to wipe.</param>
        public static void ZeroMemory(byte[] buf)
        {
            ValidateBuffer(buf);
            InternalZeroMemory(buf);
        }

        /// <summary>
        /// Overwrite a buffer (or a segment of it) with zeros in a way that the compiler is not allowed to optimize
        /// away.
        /// </summary>
        /// <param name="buf">The buffer to wipe.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the segment starts.</param>
        /// <param name="len">The length of the segment.</param>
        public static void ZeroMemory(byte[] buf, int off, int len)
        {
            ValidateSegment(buf, off, len);
            InternalZeroMemory(buf, off, len);
        }

        /// <summary>
        /// Overwrite a buffer (or a segment of it) with zeros in a way that the compiler is not allowed to optimize
        /// away.
        /// </summary>
        /// <param name="buf">The buffer to wipe.</param>
        public static void ZeroMemory(char[] buf)
        {
            ValidateBuffer(buf);
            InternalZeroMemory(buf);
        }

        internal static void ZeroMemory(sbyte[] buf)
        {
            ValidateBuffer(buf);
            InternalZeroMemory(buf);
        }

        internal static void ZeroMemory(uint[] buf)
        {
            ValidateBuffer(buf);
            InternalZeroMemory(buf);
        }

        internal static void ZeroMemory(uint[] buf, int off, int len)
        {
            ValidateSegment(buf, off, len);
            InternalZeroMemory(buf, off, len);
        }

        internal static void ZeroMemory(ulong[] buf)
        {
            ValidateBuffer(buf);
            InternalZeroMemory(buf);
        }

        internal static void ZeroMemory(ulong[] buf, int off, int len)
        {
            ValidateSegment(buf, off, len);
            InternalZeroMemory(buf, off, len);
        }

        internal static void ZeroMemory(ushort[] buf)
        {
            ValidateBuffer(buf);
            InternalZeroMemory(buf);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Concatenate several spans into a new array.</summary>
        /// <param name="a">The first span.</param>
        /// <param name="b">The second span.</param>
        /// <returns>A new array holding the contents of the spans, in order.</returns>
        public static byte[] Concatenate(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            byte[] rv = new byte[a.Length + b.Length];
            a.CopyTo(rv);
            b.CopyTo(rv.AsSpan(a.Length));
            return rv;
        }

        /// <summary>Concatenate several spans into a new array.</summary>
        /// <param name="a">The first span.</param>
        /// <param name="b">The second span.</param>
        /// <param name="c">The third span.</param>
        /// <returns>A new array holding the contents of the spans, in order.</returns>
        public static byte[] Concatenate(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
        {
            byte[] rv = new byte[a.Length + b.Length + c.Length];
            a.CopyTo(rv);
            b.CopyTo(rv.AsSpan(a.Length));
            c.CopyTo(rv.AsSpan(a.Length + b.Length));
            return rv;
        }

        /// <summary>Concatenate several spans into a new array.</summary>
        /// <param name="a">The first span.</param>
        /// <param name="b">The second span.</param>
        /// <param name="c">The third span.</param>
        /// <param name="d">The fourth span.</param>
        /// <returns>A new array holding the contents of the spans, in order.</returns>
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

        /// <summary>Compare two spans for equal contents, in fixed time.</summary>
        /// <param name="a">The first span.</param>
        /// <param name="b">The second span.</param>
        /// <returns>true if the contents are equal, false otherwise.</returns>
        [Obsolete("Use 'FixedTimeEquals' instead")]
        public static bool ConstantTimeAreEqual(Span<byte> a, Span<byte> b) => FixedTimeEquals(a, b);

        /// <summary>Fill an array (or a range of it) with a given value.</summary>
        /// <param name="ts">The array to fill.</param>
        /// <param name="t">The value to store.</param>
        public static void Fill<T>(Span<T> ts, T t) => ts.Fill(t);

        /// <summary>
        /// Compare two arrays (or segments of them) for equal contents, in time that depends only on the length and not
        /// on the contents.
        /// </summary>
        /// <param name="a">The first array.</param>
        /// <param name="b">The second array.</param>
        /// <returns>true if the contents are equal, false otherwise (including when either array is null).</returns>
        public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
            CryptographicOperations.FixedTimeEquals(a, b);

        internal static bool InternalFixedTimeEquals(byte[] a, byte[] b) =>
            CryptographicOperations.FixedTimeEquals(a, b);

        internal static bool InternalFixedTimeEquals(int len, byte[] a, int aOff, byte[] b, int bOff) =>
            CryptographicOperations.FixedTimeEquals(a.AsSpan(aOff, len), b.AsSpan(bOff, len));

        internal static bool InternalFixedTimeEquals(int len, ulong[] a, int aOff, ulong[] b, int bOff) =>
            CryptographicOperations.FixedTimeEquals(
                MemoryMarshal.AsBytes(a.AsSpan(aOff, len)),
                MemoryMarshal.AsBytes(b.AsSpan(bOff, len)));

        internal static void InternalZeroMemory(byte[] buf) => CryptographicOperations.ZeroMemory(buf);

        internal static void InternalZeroMemory(byte[] buf, int off, int len) =>
            CryptographicOperations.ZeroMemory(buf.AsSpan(off, len));

        internal static void InternalZeroMemory(char[] buf) =>
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buf.AsSpan()));

        internal static void InternalZeroMemory(sbyte[] buf) =>
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buf.AsSpan()));

        internal static void InternalZeroMemory(ushort[] buf) =>
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buf.AsSpan()));

        internal static void InternalZeroMemory(uint[] buf) => ZeroMemory(buf.AsSpan());

        internal static void InternalZeroMemory(uint[] buf, int off, int len) => ZeroMemory(buf.AsSpan(off, len));

        internal static void InternalZeroMemory(ulong[] buf) => ZeroMemory(buf.AsSpan());

        internal static void InternalZeroMemory(ulong[] buf, int off, int len) => ZeroMemory(buf.AsSpan(off, len));

        /// <summary>Create a new array with an extra element added at the start of a span's contents.</summary>
        /// <param name="a">The span holding the existing elements.</param>
        /// <param name="b">The element to prepend.</param>
        /// <returns>A new array one element longer than <paramref name="a"/>.</returns>
        public static T[] Prepend<T>(ReadOnlySpan<T> a, T b)
        {
            T[] result = new T[1 + a.Length];
            result[0] = b;
            a.CopyTo(result.AsSpan(1));
            return result;
        }

        /// <summary>
        /// Overwrite a buffer (or a segment of it) with zeros in a way that the compiler is not allowed to optimize
        /// away.
        /// </summary>
        /// <param name="buffer">The buffer to wipe.</param>
        public static void ZeroMemory(Span<byte> buffer) => CryptographicOperations.ZeroMemory(buffer);

        internal static void ZeroMemory(Span<uint> buffer) =>
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer));

        internal static void ZeroMemory(Span<ulong> buffer) =>
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer));
#else
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool InternalFixedTimeEquals(byte[] a, byte[] b)
        {
            int len = a.Length;
            if (len != b.Length)
                return false;

            int d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= a[i] ^ b[i];
            }
            return 0 == d;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool InternalFixedTimeEquals(int len, byte[] a, int aOff, byte[] b, int bOff)
        {
            int d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= a[aOff + i] ^ b[bOff + i];
            }
            return 0 == d;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool InternalFixedTimeEquals(int len, ulong[] a, int aOff, ulong[] b, int bOff)
        {
            ulong d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= a[aOff + i] ^ b[bOff + i];
            }
            return 0UL == d;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(byte[] buf)
        {
            for (int i = 0; i < buf.Length; ++i)
            {
                buf[i] = 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(char[] buf)
        {
            for (int i = 0; i < buf.Length; ++i)
            {
                buf[i] = '\0';
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(byte[] buf, int off, int len)
        {
            for (int i = 0; i < len; ++i)
            {
                buf[off + i] = 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(sbyte[] buf)
        {
            for (int i = 0; i < buf.Length; ++i)
            {
                buf[i] = 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(ushort[] buf)
        {
            for (int i = 0; i < buf.Length; ++i)
            {
                buf[i] = 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(uint[] buf)
        {
            for (int i = 0; i < buf.Length; ++i)
            {
                buf[i] = 0U;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(uint[] buf, int off, int len)
        {
            for (int i = 0; i < len; ++i)
            {
                buf[off + i] = 0U;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(ulong[] buf)
        {
            for (int i = 0; i < buf.Length; ++i)
            {
                buf[i] = 0UL;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static void InternalZeroMemory(ulong[] buf, int off, int len)
        {
            for (int i = 0; i < len; ++i)
            {
                buf[off + i] = 0UL;
            }
        }
#endif
    }
}
