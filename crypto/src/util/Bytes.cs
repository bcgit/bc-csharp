using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Numerics;
#endif

namespace Org.BouncyCastle.Utilities
{
    public static class Bytes
    {
        public const int NumBits = 8;
        public const int NumBytes = 1;

        public static void Xor(int len, byte[] x, byte[] y, byte[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor(len, x.AsSpan(0, len), y.AsSpan(0, len), z.AsSpan(0, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] = (byte)(x[i] ^ y[i]);
            }
#endif
        }

        public static void Xor(int len, byte[] x, int xOff, byte[] y, int yOff, byte[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor(len, x.AsSpan(xOff, len), y.AsSpan(yOff, len), z.AsSpan(zOff, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Xor(int len, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, Span<byte> z)
        {
            int i = 0;
            if (Vector.IsHardwareAccelerated)
            {
                int limit = len - Vector<byte>.Count;
                while (i <= limit)
                {
                    var vx = new Vector<byte>(x[i..]);
                    var vy = new Vector<byte>(y[i..]);
                    (vx ^ vy).CopyTo(z[i..]);
                    i += Vector<byte>.Count;
                }
            }
            {
                int limit = len - 4;
                while (i <= limit)
                {
                    z[i + 0] = (byte)(x[i + 0] ^ y[i + 0]);
                    z[i + 1] = (byte)(x[i + 1] ^ y[i + 1]);
                    z[i + 2] = (byte)(x[i + 2] ^ y[i + 2]);
                    z[i + 3] = (byte)(x[i + 3] ^ y[i + 3]);
                    i += 4;
                }
            }
            {
                while (i < len)
                {
                    z[i] = (byte)(x[i] ^ y[i]);
                    ++i;
                }
            }
        }
#endif

        public static void XorTo(int len, byte[] x, byte[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo(len, x.AsSpan(0, len), z.AsSpan(0, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] ^= x[i];
            }
#endif
        }

        public static void XorTo(int len, byte[] x, int xOff, byte[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo(len, x.AsSpan(xOff, len), z.AsSpan(zOff, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[zOff + i] ^= x[xOff + i];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void XorTo(int len, ReadOnlySpan<byte> x, Span<byte> z)
        {
            int i = 0;
            if (Vector.IsHardwareAccelerated)
            {
                int limit = len - Vector<byte>.Count;
                while (i <= limit)
                {
                    var vx = new Vector<byte>(x[i..]);
                    var vz = new Vector<byte>(z[i..]);
                    (vx ^ vz).CopyTo(z[i..]);
                    i += Vector<byte>.Count;
                }
            }
            {
                int limit = len - 4;
                while (i <= limit)
                {
                    z[i + 0] ^= x[i + 0];
                    z[i + 1] ^= x[i + 1];
                    z[i + 2] ^= x[i + 2];
                    z[i + 3] ^= x[i + 3];
                    i += 4;
                }
            }
            {
                while (i < len)
                {
                    z[i] ^= x[i];
                    ++i;
                }
            }
        }
#endif
    }
}
