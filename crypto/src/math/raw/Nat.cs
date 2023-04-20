using System;
using System.Diagnostics;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Numerics;
#endif

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Math.Raw
{
    internal static class Nat
    {
        private const ulong M = 0xFFFFFFFFUL;

        public static uint Add(int len, uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0UL;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Add(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            ulong c = 0UL;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }
#endif

        public static uint Add33At(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zPos + 0] + x;
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zPos + 1] + 1;
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 2);
        }

        public static uint Add33At(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zOff + zPos] + x;
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + zPos + 1] + 1;
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zOff, zPos + 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Add33At(int len, uint x, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zPos + 0] + x;
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zPos + 1] + 1;
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 2);
        }
#endif

        public static uint Add33To(int len, uint x, uint[] z)
        {
            ulong c = (ulong)z[0] + x;
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)z[1] + 1;
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, 2);
        }

        public static uint Add33To(int len, uint x, uint[] z, int zOff)
        {
            ulong c = (ulong)z[zOff + 0] + x;
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1] + 1;
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zOff, 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Add33To(int len, uint x, Span<uint> z)
        {
            ulong c = (ulong)z[0] + x;
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)z[1] + 1;
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, 2);
        }
#endif

        public static uint AddBothTo(int len, uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint AddBothTo(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[xOff + i] + y[yOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddBothTo(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }
#endif

        public static uint AddDWordAt(int len, ulong x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = z[zPos + 0] + (x & M);
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += z[zPos + 1] + (x >> 32);
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 2);
        }

        public static uint AddDWordAt(int len, ulong x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = z[zOff + zPos] + (x & M);
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += z[zOff + zPos + 1] + (x >> 32);
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zOff, zPos + 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddDWordAt(int len, ulong x, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = z[zPos + 0] + (x & M);
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += z[zPos + 1] + (x >> 32);
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 2);
        }
#endif

        public static uint AddDWordTo(int len, ulong x, uint[] z)
        {
            ulong c = (ulong)z[0] + (x & M);
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)z[1] + (x >> 32);
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, 2);
        }

        public static uint AddDWordTo(int len, ulong x, uint[] z, int zOff)
        {
            ulong c = (ulong)z[zOff + 0] + (x & M);
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1] + (x >> 32);
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zOff, 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddDWordTo(int len, ulong x, Span<uint> z)
        {
            ulong c = z[0] + (x & M);
            z[0] = (uint)c;
            c >>= 32;
            c += z[1] + (x >> 32);
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, 2);
        }
#endif

        public static uint AddTo(int len, uint[] x, uint[] z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint AddTo(int len, uint[] x, int xOff, uint[] z, int zOff)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[xOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddTo(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }
#endif

        public static uint AddTo(int len, uint[] x, int xOff, uint[] z, int zOff, uint cIn)
        {
            ulong c = cIn;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[xOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddTo(int len, ReadOnlySpan<uint> x, Span<uint> z, uint cIn)
        {
            ulong c = cIn;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }
#endif

        public static uint AddToEachOther(int len, uint[] u, int uOff, uint[] v, int vOff)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)u[uOff + i] + v[vOff + i];
                u[uOff + i] = (uint)c;
                v[vOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddToEachOther(int len, Span<uint> u, Span<uint> v)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)u[i] + v[i];
                u[i] = (uint)c;
                v[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }
#endif

        public static uint AddWordAt(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            ulong c = (ulong)x + z[zPos];
            z[zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 1);
        }

        public static uint AddWordAt(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            ulong c = (ulong)x + z[zOff + zPos];
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zOff, zPos + 1);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddWordAt(int len, uint x, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            ulong c = (ulong)x + z[zPos];
            z[zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 1);
        }
#endif

        public static uint AddWordTo(int len, uint x, uint[] z)
        {
            ulong c = (ulong)x + z[0];
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, 1);
        }

        public static uint AddWordTo(int len, uint x, uint[] z, int zOff)
        {
            ulong c = (ulong)x + z[zOff];
            z[zOff] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zOff, 1);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint AddWordTo(int len, uint x, Span<uint> z)
        {
            ulong c = (ulong)x + z[0];
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, 1);
        }
#endif

        public static uint CAdd(int len, int mask, uint[] x, uint[] y, uint[] z)
        {
            uint MASK = (uint)-(mask & 1);

            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + (y[i] & MASK);
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint CAdd(int len, int mask, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            uint MASK = (uint)-(mask & 1);

            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + (y[i] & MASK);
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }
#endif

        public static void CMov(int len, int mask, uint[] x, int xOff, uint[] z, int zOff)
        {
            uint MASK = (uint)-(mask & 1);

            for (int i = 0; i < len; ++i)
            {
                uint z_i = z[zOff + i], diff = z_i ^ x[xOff + i];
                z_i ^= diff & MASK;
                z[zOff + i] = z_i;
            }

            //uint half = 0x55555555U, rest = half << (-(int)MASK);

            //for (int i = 0; i < len; ++i)
            //{
            //    uint z_i = z[zOff + i], diff = z_i ^ x[xOff + i];
            //    z_i ^= (diff & half);
            //    z_i ^= (diff & rest);
            //    z[zOff + i] = z_i;
            //}
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void CMov(int len, int mask, ReadOnlySpan<uint> x, Span<uint> z)
        {
            uint MASK = (uint)-(mask & 1);

            for (int i = 0; i < len; ++i)
            {
                uint z_i = z[i], diff = z_i ^ x[i];
                z_i ^= diff & MASK;
                z[i] = z_i;
            }

            //uint half = 0x55555555U, rest = half << (-(int)MASK);

            //for (int i = 0; i < len; ++i)
            //{
            //    uint z_i = z[i], diff = z_i ^ x[i];
            //    z_i ^= (diff & half);
            //    z_i ^= (diff & rest);
            //    z[i] = z_i;
            //}
        }
#endif

        public static int Compare(int len, uint[] x, uint[] y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                uint x_i = x[i];
                uint y_i = y[i];
                if (x_i < y_i)
                    return -1;
                if (x_i > y_i)
                    return 1;
            }
            return 0;
        }

        public static int Compare(int len, uint[] x, int xOff, uint[] y, int yOff)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                uint x_i = x[xOff + i];
                uint y_i = y[yOff + i];
                if (x_i < y_i)
                    return -1;
                if (x_i > y_i)
                    return 1;
            }
            return 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Compare(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                uint x_i = x[i];
                uint y_i = y[i];
                if (x_i < y_i)
                    return -1;
                if (x_i > y_i)
                    return 1;
            }
            return 0;
        }
#endif

        public static uint[] Copy(int len, uint[] x)
        {
            uint[] z = new uint[len];
            Array.Copy(x, 0, z, 0, len);
            return z;
        }

        public static void Copy(int len, uint[] x, uint[] z)
        {
            Array.Copy(x, 0, z, 0, len);
        }

        public static void Copy(int len, uint[] x, int xOff, uint[] z, int zOff)
        {
            Array.Copy(x, xOff, z, zOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Copy(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            x[..len].CopyTo(z);
        }
#endif

        public static ulong[] Copy64(int len, ulong[] x)
        {
            ulong[] z = new ulong[len];
            Array.Copy(x, 0, z, 0, len);
            return z;
        }

        public static void Copy64(int len, ulong[] x, ulong[] z)
        {
            Array.Copy(x, 0, z, 0, len);
        }

        public static void Copy64(int len, ulong[] x, int xOff, ulong[] z, int zOff)
        {
            Array.Copy(x, xOff, z, zOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Copy64(int len, ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            x[..len].CopyTo(z);
        }
#endif

        public static uint[] Create(int len)
        {
            return new uint[len];
        }

        public static ulong[] Create64(int len)
        {
            return new ulong[len];
        }

        public static int CSub(int len, int mask, uint[] x, uint[] y, uint[] z)
        {
            long MASK = (uint)-(mask & 1);
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += x[i] - (y[i] & MASK);
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int CSub(int len, int mask, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            long MASK = (uint)-(mask & 1);
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += x[xOff + i] - (y[yOff + i] & MASK);
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int CSub(int len, int mask, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            long MASK = (uint)-(mask & 1);
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += x[i] - (y[i] & MASK);
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }
#endif

        public static int Dec(int len, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                    return 0;
            }
            return -1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Dec(int len, Span<uint> z)
        {
            for (int i = 0; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                    return 0;
            }
            return -1;
        }
#endif

        public static int Dec(int len, uint[] x, uint[] z)
        {
            int i = 0;
            while (i < len)
            {
                uint c = x[i] - 1;
                z[i] = c;
                ++i;
                if (c != uint.MaxValue)
                {
                    while (i < len)
                    {
                        z[i] = x[i];
                        ++i;
                    }
                    return 0;
                }
            }
            return -1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Dec(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            int i = 0;
            while (i < len)
            {
                uint c = x[i] - 1;
                z[i] = c;
                ++i;
                if (c != uint.MaxValue)
                {
                    while (i < len)
                    {
                        z[i] = x[i];
                        ++i;
                    }
                    return 0;
                }
            }
            return -1;
        }
#endif

        public static int DecAt(int len, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                    return 0;
            }
            return -1;
        }

        public static int DecAt(int len, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (--z[zOff + i] != uint.MaxValue)
                    return 0;
            }
            return -1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int DecAt(int len, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                    return 0;
            }
            return -1;
        }
#endif

        public static bool Eq(int len, uint[] x, uint[] y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                if (x[i] != y[i])
                    return false;
            }
            return true;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool Eq(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                if (x[i] != y[i])
                    return false;
            }
            return true;
        }
#endif

        public static uint EqualTo(int len, uint[] x, uint y)
        {
            uint d = x[0] ^ y;
            for (int i = 1; i < len; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }

        public static uint EqualTo(int len, uint[] x, int xOff, uint y)
        {
            uint d = x[xOff] ^ y;
            for (int i = 1; i < len; ++i)
            {
                d |= x[xOff + i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint EqualTo(int len, ReadOnlySpan<uint> x, uint y)
        {
            uint d = x[0] ^ y;
            for (int i = 1; i < len; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }
#endif

        public static uint EqualTo(int len, uint[] x, uint[] y)
        {
            uint d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= x[i] ^ y[i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }

        public static uint EqualTo(int len, uint[] x, int xOff, uint[] y, int yOff)
        {
            uint d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= x[xOff + i] ^ y[yOff + i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint EqualTo(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
        {
            uint d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= x[i] ^ y[i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }
#endif

        public static uint EqualToZero(int len, uint[] x)
        {
            uint d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }

        public static uint EqualToZero(int len, uint[] x, int xOff)
        {
            uint d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= x[xOff + i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint EqualToZero(int len, ReadOnlySpan<uint> x)
        {
            uint d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return (uint)(((int)d - 1) >> 31);
        }
#endif

        public static uint[] FromBigInteger(int bits, BigInteger x)
        {
            if (x.SignValue < 0 || x.BitLength > bits)
                throw new ArgumentException();

            int len = GetLengthForBits(bits);
            uint[] z = Create(len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int xLen = x.GetLengthofUInt32ArrayUnsigned();
            x.ToUInt32ArrayLittleEndianUnsigned(z.AsSpan(0, xLen));
            //z.AsSpan(xLen).Fill(0x00);
#else
            // NOTE: Use a fixed number of loop iterations
            z[0] = (uint)x.IntValue;
            for (int i = 1; i < len; ++i)
            {
                x = x.ShiftRight(32);
                z[i] = (uint)x.IntValue;
            }
#endif

            return z;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void FromBigInteger(int bits, BigInteger x, Span<uint> z)
        {
            if (x.SignValue < 0 || x.BitLength > bits)
                throw new ArgumentException();

            int len = GetLengthForBits(bits);
            if (z.Length < len)
                throw new ArgumentException();

            int xLen = x.GetLengthofUInt32ArrayUnsigned();
            x.ToUInt32ArrayLittleEndianUnsigned(z[..xLen]);
            z[xLen..].Fill(0x00);
        }
#endif

        public static ulong[] FromBigInteger64(int bits, BigInteger x)
        {
            if (x.SignValue < 0 || x.BitLength > bits)
                throw new ArgumentException();

            int len = GetLengthForBits64(bits);
            ulong[] z = Create64(len);

            // NOTE: Use a fixed number of loop iterations
            z[0] = (ulong)x.LongValue;
            for (int i = 1; i < len; ++i)
            {
                x = x.ShiftRight(64);
                z[i] = (ulong)x.LongValue;
            }
            return z;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void FromBigInteger64(int bits, BigInteger x, Span<ulong> z)
        {
            if (x.SignValue < 0 || x.BitLength > bits)
                throw new ArgumentException();

            int len = GetLengthForBits64(bits);
            if (z.Length < len)
                throw new ArgumentException();

            // NOTE: Use a fixed number of loop iterations
            z[0] = (ulong)x.LongValue;
            for (int i = 1; i < len; ++i)
            {
                x = x.ShiftRight(64);
                z[i] = (ulong)x.LongValue;
            }
        }
#endif

        public static uint GetBit(uint[] x, int bit)
        {
            if (bit == 0)
                return x[0] & 1;

            int w = bit >> 5;
            if (w < 0 || w >= x.Length)
                return 0;

            int b = bit & 31;
            return (x[w] >> b) & 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint GetBit(ReadOnlySpan<uint> x, int bit)
        {
            if (bit == 0)
                return x[0] & 1;

            int w = bit >> 5;
            if (w < 0 || w >= x.Length)
                return 0;

            int b = bit & 31;
            return (x[w] >> b) & 1;
        }
#endif

        public static int GetLengthForBits(int bits)
        {
            if (bits < 1)
                throw new ArgumentException();

            return (int)(((uint)bits + 31) >> 5);
        }

        public static int GetLengthForBits64(int bits)
        {
            if (bits < 1)
                throw new ArgumentException();

            return (int)(((uint)bits + 63) >> 6);
        }

        public static bool Gte(int len, uint[] x, uint[] y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                uint x_i = x[i], y_i = y[i];
                if (x_i < y_i)
                    return false;
                if (x_i > y_i)
                    return true;
            }
            return true;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool Gte(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                uint x_i = x[i], y_i = y[i];
                if (x_i < y_i)
                    return false;
                if (x_i > y_i)
                    return true;
            }
            return true;
        }
#endif

        public static uint Inc(int len, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                    return 0;
            }
            return 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Inc(int len, Span<uint> z)
        {
            for (int i = 0; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                    return 0;
            }
            return 1;
        }
#endif

        public static uint Inc(int len, uint[] x, uint[] z)
        {
            int i = 0;
            while (i < len)
            {
                uint c = x[i] + 1;
                z[i] = c;
                ++i;
                if (c != 0)
                {
                    while (i < len)
                    {
                        z[i] = x[i];
                        ++i;
                    }
                    return 0;
                }
            }
            return 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Inc(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            int i = 0;
            while (i < len)
            {
                uint c = x[i] + 1;
                z[i] = c;
                ++i;
                if (c != 0)
                {
                    while (i < len)
                    {
                        z[i] = x[i];
                        ++i;
                    }
                    return 0;
                }
            }
            return 1;
        }
#endif

        public static uint IncAt(int len, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                    return 0;
            }
            return 1;
        }

        public static uint IncAt(int len, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (++z[zOff + i] != uint.MinValue)
                    return 0;
            }
            return 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint IncAt(int len, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                    return 0;
            }
            return 1;
        }
#endif

        public static bool IsOne(int len, uint[] x)
        {
            if (x[0] != 1)
                return false;

            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                    return false;
            }
            return true;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool IsOne(int len, ReadOnlySpan<uint> x)
        {
            if (x[0] != 1)
                return false;

            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                    return false;
            }
            return true;
        }
#endif

        public static bool IsZero(int len, uint[] x)
        {
            if (x[0] != 0)
                return false;

            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                    return false;
            }
            return true;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool IsZero(int len, ReadOnlySpan<uint> x)
        {
            if (x[0] != 0)
                return false;

            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                    return false;
            }
            return true;
        }
#endif

        public static int LessThan(int len, uint[] x, uint[] y)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[i] - y[i];
                c >>= 32;
            }
            Debug.Assert(c == 0L || c == -1L);
            return (int)c;
        }

        public static int LessThan(int len, uint[] x, int xOff, uint[] y, int yOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[xOff + i] - y[yOff + i];
                c >>= 32;
            }
            Debug.Assert(c == 0L || c == -1L);
            return (int)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int LessThan(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[i] - y[i];
                c >>= 32;
            }
            Debug.Assert(c == 0L || c == -1L);
            return (int)c;
        }
#endif

        public static void Mul(int len, uint[] x, uint[] y, uint[] zz)
        {
            zz[len] = MulWord(len, x[0], y, zz);

            for (int i = 1; i < len; ++i)
            {
                zz[i + len] = MulWordAddTo(len, x[i], y, 0, zz, i);
            }
        }

        public static void Mul(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] zz, int zzOff)
        {
            zz[zzOff + len] = MulWord(len, x[xOff], y, yOff, zz, zzOff);

            for (int i = 1; i < len; ++i)
            {
                zz[zzOff + i + len] = MulWordAddTo(len, x[xOff + i], y, yOff, zz, zzOff + i);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Mul(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
        {
            zz[len] = MulWord(len, x[0], y, zz);

            for (int i = 1; i < len; ++i)
            {
                zz[i + len] = MulWordAddTo(len, x[i], y, zz[i..]);
            }
        }
#endif

        public static void Mul(uint[] x, int xOff, int xLen, uint[] y, int yOff, int yLen, uint[] zz, int zzOff)
        {
            zz[zzOff + yLen] = MulWord(yLen, x[xOff], y, yOff, zz, zzOff);

            for (int i = 1; i < xLen; ++i)
            {
                zz[zzOff + i + yLen] = MulWordAddTo(yLen, x[xOff + i], y, yOff, zz, zzOff + i);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Mul(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
        {
            int xLen = x.Length, yLen = y.Length;
            zz[yLen] = MulWord(yLen, x[0], y, zz);

            for (int i = 1; i < xLen; ++i)
            {
                zz[i + yLen] = MulWordAddTo(yLen, x[i], y, zz[i..]);
            }
        }
#endif

        public static uint MulAddTo(int len, uint[] x, uint[] y, uint[] zz)
        {
            ulong zc = 0;
            for (int i = 0; i < len; ++i)
            {
                zc += MulWordAddTo(len, x[i], y, 0, zz, i) & M;
                zc += zz[i + len] & M;
                zz[i + len] = (uint)zc;
                zc >>= 32;
            }
            return (uint)zc;
        }

        public static uint MulAddTo(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] zz, int zzOff)
        {
            ulong zc = 0;
            for (int i = 0; i < len; ++i)
            {
                zc += MulWordAddTo(len, x[xOff + i], y, yOff, zz, zzOff) & M;
                zc += zz[zzOff + len] & M;
                zz[zzOff + len] = (uint)zc;
                zc >>= 32;
                ++zzOff;
            }
            return (uint)zc;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint MulAddTo(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
        {
            ulong zc = 0;
            for (int i = 0; i < len; ++i)
            {
                zc += MulWordAddTo(len, x[i], y, zz[i..]) & M;
                zc += zz[i + len] & M;
                zz[i + len] = (uint)zc;
                zc >>= 32;
            }
            return (uint)zc;
        }
#endif

        public static uint Mul31BothAdd(int len, uint a, uint[] x, uint b, uint[] y, uint[] z, int zOff)
        {
            ulong c = 0, aVal = a, bVal = b;
            int i = 0;
            do
            {
                c += aVal * x[i] + bVal * y[i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint Mul31BothAdd(int len, uint a, ReadOnlySpan<uint> x, uint b, ReadOnlySpan<uint> y,
            Span<uint> z)
        {
            ulong c = 0, aVal = a, bVal = b;
            int i = 0;
            do
            {
                c += aVal * x[i] + bVal * y[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }
#endif

        public static uint MulWord(int len, uint x, uint[] y, uint[] z)
        {
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint MulWord(int len, uint x, uint[] y, int yOff, uint[] z, int zOff)
        {
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[yOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint MulWord(int len, uint x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }
#endif

        public static uint MulWordAddTo(int len, uint x, uint[] y, int yOff, uint[] z, int zOff)
        {
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[yOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint MulWordAddTo(int len, uint x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }
#endif

        public static uint MulWordDwordAddAt(int len, uint x, ulong y, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 3));
            ulong c = 0, xVal = x;
            c += xVal * (uint)y + z[zPos + 0];
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += xVal * (y >> 32) + z[zPos + 1];
            z[zPos + 1] = (uint)c;
            c >>= 32;
            c += z[zPos + 2];
            z[zPos + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 3);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint MulWordDwordAddAt(int len, uint x, ulong y, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 3));
            ulong c = 0, xVal = x;
            c += xVal * (uint)y + z[zPos + 0];
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += xVal * (y >> 32) + z[zPos + 1];
            z[zPos + 1] = (uint)c;
            c >>= 32;
            c += z[zPos + 2];
            z[zPos + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncAt(len, z, zPos + 3);
        }
#endif

        public static int Negate(int len, uint[] x, uint[] z)
        {
            long c = 0L;
            for (int i = 0; i < len; ++i)
            {
                c -= x[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Negate(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            long c = 0L;
            for (int i = 0; i < len; ++i)
            {
                c -= x[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }
#endif

        public static uint ShiftDownBit(int len, uint[] z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        public static uint ShiftDownBit(int len, uint[] z, int zOff, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftDownBit(int len, Span<uint> z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }
#endif

        public static uint ShiftDownBit(int len, uint[] x, uint c, uint[] z)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        public static uint ShiftDownBit(int len, uint[] x, int xOff, uint c, uint[] z, int zOff)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftDownBit(int len, ReadOnlySpan<uint> x, uint c, Span<uint> z)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }
#endif

        public static uint ShiftDownBits(int len, uint[] z, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint ShiftDownBits(int len, uint[] z, int zOff, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftDownBits(int len, Span<uint> z, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }
#endif

        public static uint ShiftDownBits(int len, uint[] x, int bits, uint c, uint[] z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                z[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint ShiftDownBits(int len, uint[] x, int xOff, int bits, uint c, uint[] z, int zOff)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftDownBits(int len, ReadOnlySpan<uint> x, int bits, uint c, Span<uint> z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                z[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }
#endif

        public static ulong ShiftDownBits64(int len, ulong[] z, int zOff, int bits, ulong c)
        {
            Debug.Assert(bits > 0 && bits < 64);
            int i = len;
            while (--i >= 0)
            {
                ulong next = z[zOff + i];
                z[zOff + i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint ShiftDownWord(int len, uint[] z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = c;
                c = next;
            }
            return c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftDownWord(int len, Span<uint> z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = c;
                c = next;
            }
            return c;
        }
#endif

        public static uint ShiftUpBit(int len, uint[] z, uint c)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBit(len, z.AsSpan(0, len), c);
#else
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = z[i + 0];
                uint next1 = z[i + 1];
                uint next2 = z[i + 2];
                uint next3 = z[i + 3];
                z[i + 0] = (next0 << 1) | (c     >> 31);
                z[i + 1] = (next1 << 1) | (next0 >> 31);
                z[i + 2] = (next2 << 1) | (next1 >> 31);
                z[i + 3] = (next3 << 1) | (next2 >> 31);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = z[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
                ++i;
            }
            return c >> 31;
#endif
        }

        public static uint ShiftUpBit(int len, uint[] z, int zOff, uint c)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBit(len, z.AsSpan(zOff, len), c);
#else
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = z[zOff + i + 0];
                uint next1 = z[zOff + i + 1];
                uint next2 = z[zOff + i + 2];
                uint next3 = z[zOff + i + 3];
                z[zOff + i + 0] = (next0 << 1) | (c     >> 31);
                z[zOff + i + 1] = (next1 << 1) | (next0 >> 31);
                z[zOff + i + 2] = (next2 << 1) | (next1 >> 31);
                z[zOff + i + 3] = (next3 << 1) | (next2 >> 31);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next << 1) | (c >> 31);
                c = next;
                ++i;
            }
            return c >> 31;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftUpBit(int len, Span<uint> z, uint c)
        {
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = z[i + 0];
                uint next1 = z[i + 1];
                uint next2 = z[i + 2];
                uint next3 = z[i + 3];
                z[i + 0] = (next0 << 1) | (c     >> 31);
                z[i + 1] = (next1 << 1) | (next0 >> 31);
                z[i + 2] = (next2 << 1) | (next1 >> 31);
                z[i + 3] = (next3 << 1) | (next2 >> 31);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = z[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
                ++i;
            }
            return c >> 31;
        }
#endif

        public static uint ShiftUpBit(int len, uint[] x, uint c, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBit(len, x.AsSpan(0, len), c, z.AsSpan(0, len));
#else
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = x[i + 0];
                uint next1 = x[i + 1];
                uint next2 = x[i + 2];
                uint next3 = x[i + 3];
                z[i + 0] = (next0 << 1) | (c     >> 31);
                z[i + 1] = (next1 << 1) | (next0 >> 31);
                z[i + 2] = (next2 << 1) | (next1 >> 31);
                z[i + 3] = (next3 << 1) | (next2 >> 31);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = x[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
                ++i;
            }
            return c >> 31;
#endif
        }

        public static uint ShiftUpBit(int len, uint[] x, int xOff, uint c, uint[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBit(len, x.AsSpan(xOff, len), c, z.AsSpan(zOff, len));
#else
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = x[xOff + i + 0];
                uint next1 = x[xOff + i + 1];
                uint next2 = x[xOff + i + 2];
                uint next3 = x[xOff + i + 3];
                z[zOff + i + 0] = (next0 << 1) | (c     >> 31);
                z[zOff + i + 1] = (next1 << 1) | (next0 >> 31);
                z[zOff + i + 2] = (next2 << 1) | (next1 >> 31);
                z[zOff + i + 3] = (next3 << 1) | (next2 >> 31);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next << 1) | (c >> 31);
                c = next;
                ++i;
            }
            return c >> 31;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftUpBit(int len, ReadOnlySpan<uint> x, uint c, Span<uint> z)
        {
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = x[i + 0];
                uint next1 = x[i + 1];
                uint next2 = x[i + 2];
                uint next3 = x[i + 3];
                z[i + 0] = (next0 << 1) | (c     >> 31);
                z[i + 1] = (next1 << 1) | (next0 >> 31);
                z[i + 2] = (next2 << 1) | (next1 >> 31);
                z[i + 3] = (next3 << 1) | (next2 >> 31);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = x[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
                ++i;
            }
            return c >> 31;
        }
#endif

        public static ulong ShiftUpBit64(int len, ulong[] x, ulong c, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBit64(len, x.AsSpan(0, len), c, z.AsSpan(0, len));
#else
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = x[i + 0];
                ulong next1 = x[i + 1];
                ulong next2 = x[i + 2];
                ulong next3 = x[i + 3];
                z[i + 0] = (next0 << 1) | (c     >> 63);
                z[i + 1] = (next1 << 1) | (next0 >> 63);
                z[i + 2] = (next2 << 1) | (next1 >> 63);
                z[i + 3] = (next3 << 1) | (next2 >> 63);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = x[i];
                z[i] = (next << 1) | (c >> 63);
                c = next;
                ++i;
            }
            return c >> 63;
#endif
        }

        public static ulong ShiftUpBit64(int len, ulong[] x, int xOff, ulong c, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBit64(len, x.AsSpan(xOff, len), c, z.AsSpan(zOff, len));
#else
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = x[xOff + i + 0];
                ulong next1 = x[xOff + i + 1];
                ulong next2 = x[xOff + i + 2];
                ulong next3 = x[xOff + i + 3];
                z[zOff + i + 0] = (next0 << 1) | (c     >> 63);
                z[zOff + i + 1] = (next1 << 1) | (next0 >> 63);
                z[zOff + i + 2] = (next2 << 1) | (next1 >> 63);
                z[zOff + i + 3] = (next3 << 1) | (next2 >> 63);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = x[xOff + i];
                z[zOff + i] = (next << 1) | (c >> 63);
                c = next;
                ++i;
            }
            return c >> 63;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ulong ShiftUpBit64(int len, ReadOnlySpan<ulong> x, ulong c, Span<ulong> z)
        {
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = x[i + 0];
                ulong next1 = x[i + 1];
                ulong next2 = x[i + 2];
                ulong next3 = x[i + 3];
                z[i + 0] = (next0 << 1) | (c     >> 63);
                z[i + 1] = (next1 << 1) | (next0 >> 63);
                z[i + 2] = (next2 << 1) | (next1 >> 63);
                z[i + 3] = (next3 << 1) | (next2 >> 63);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = x[i];
                z[i] = (next << 1) | (c >> 63);
                c = next;
                ++i;
            }
            return c >> 63;
        }
#endif

        public static uint ShiftUpBits(int len, uint[] z, int bits, uint c)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits(len, z.AsSpan(0, len), bits, c);
#else
            Debug.Assert(bits > 0 && bits < 32);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = z[i + 0];
                uint next1 = z[i + 1];
                uint next2 = z[i + 2];
                uint next3 = z[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = z[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

        public static uint ShiftUpBits(int len, uint[] z, int zOff, int bits, uint c)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits(len, z.AsSpan(zOff, len), bits, c);
#else
            Debug.Assert(bits > 0 && bits < 32);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = z[zOff + i + 0];
                uint next1 = z[zOff + i + 1];
                uint next2 = z[zOff + i + 2];
                uint next3 = z[zOff + i + 3];
                z[zOff + i + 0] = (next0 << bits) | (c     >> -bits);
                z[zOff + i + 1] = (next1 << bits) | (next0 >> -bits);
                z[zOff + i + 2] = (next2 << bits) | (next1 >> -bits);
                z[zOff + i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftUpBits(int len, Span<uint> z, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = z[i + 0];
                uint next1 = z[i + 1];
                uint next2 = z[i + 2];
                uint next3 = z[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = z[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
        }
#endif

        public static uint ShiftUpBits(int len, uint[] x, int bits, uint c, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits(len, x.AsSpan(0, len), bits, c, z.AsSpan(0, len));
#else
            Debug.Assert(bits > 0 && bits < 32);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = x[i + 0];
                uint next1 = x[i + 1];
                uint next2 = x[i + 2];
                uint next3 = x[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = x[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

        public static uint ShiftUpBits(int len, uint[] x, int xOff, int bits, uint c, uint[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits(len, x.AsSpan(xOff, len), bits, c, z.AsSpan(zOff, len));
#else
            Debug.Assert(bits > 0 && bits < 32);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = x[xOff + i + 0];
                uint next1 = x[xOff + i + 1];
                uint next2 = x[xOff + i + 2];
                uint next3 = x[xOff + i + 3];
                z[zOff + i + 0] = (next0 << bits) | (c     >> -bits);
                z[zOff + i + 1] = (next1 << bits) | (next0 >> -bits);
                z[zOff + i + 2] = (next2 << bits) | (next1 >> -bits);
                z[zOff + i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint ShiftUpBits(int len, ReadOnlySpan<uint> x, int bits, uint c, Span<uint> z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                uint next0 = x[i + 0];
                uint next1 = x[i + 1];
                uint next2 = x[i + 2];
                uint next3 = x[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                uint next = x[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
        }
#endif

        public static ulong ShiftUpBits64(int len, ulong[] z, int bits, ulong c)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits64(len, z.AsSpan(0, len), bits, c);
#else
            Debug.Assert(bits > 0 && bits < 64);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = z[i + 0];
                ulong next1 = z[i + 1];
                ulong next2 = z[i + 2];
                ulong next3 = z[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = z[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

        public static ulong ShiftUpBits64(int len, ulong[] z, int zOff, int bits, ulong c)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits64(len, z.AsSpan(zOff, len), bits, c);
#else
            Debug.Assert(bits > 0 && bits < 64);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = z[zOff + i + 0];
                ulong next1 = z[zOff + i + 1];
                ulong next2 = z[zOff + i + 2];
                ulong next3 = z[zOff + i + 3];
                z[zOff + i + 0] = (next0 << bits) | (c     >> -bits);
                z[zOff + i + 1] = (next1 << bits) | (next0 >> -bits);
                z[zOff + i + 2] = (next2 << bits) | (next1 >> -bits);
                z[zOff + i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = z[zOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ulong ShiftUpBits64(int len, Span<ulong> z, int bits, ulong c)
        {
            Debug.Assert(bits > 0 && bits < 64);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = z[i + 0];
                ulong next1 = z[i + 1];
                ulong next2 = z[i + 2];
                ulong next3 = z[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = z[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
        }
#endif

        public static ulong ShiftUpBits64(int len, ulong[] x, int bits, ulong c, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits64(len, x.AsSpan(0, len), bits, c, z.AsSpan(0, len));
#else
            Debug.Assert(bits > 0 && bits < 64);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = x[i + 0];
                ulong next1 = x[i + 1];
                ulong next2 = x[i + 2];
                ulong next3 = x[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = x[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

        public static ulong ShiftUpBits64(int len, ulong[] x, int xOff, int bits, ulong c, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ShiftUpBits64(len, x.AsSpan(xOff, len), bits, c, z.AsSpan(zOff, len));
#else
            Debug.Assert(bits > 0 && bits < 64);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = x[xOff + i + 0];
                ulong next1 = x[xOff + i + 1];
                ulong next2 = x[xOff + i + 2];
                ulong next3 = x[xOff + i + 3];
                z[zOff + i + 0] = (next0 << bits) | (c     >> -bits);
                z[zOff + i + 1] = (next1 << bits) | (next0 >> -bits);
                z[zOff + i + 2] = (next2 << bits) | (next1 >> -bits);
                z[zOff + i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = x[xOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ulong ShiftUpBits64(int len, ReadOnlySpan<ulong> x, int bits, ulong c, Span<ulong> z)
        {
            Debug.Assert(bits > 0 && bits < 64);
            int i = 0, limit4 = len - 4;
            while (i <= limit4)
            {
                ulong next0 = x[i + 0];
                ulong next1 = x[i + 1];
                ulong next2 = x[i + 2];
                ulong next3 = x[i + 3];
                z[i + 0] = (next0 << bits) | (c     >> -bits);
                z[i + 1] = (next1 << bits) | (next0 >> -bits);
                z[i + 2] = (next2 << bits) | (next1 >> -bits);
                z[i + 3] = (next3 << bits) | (next2 >> -bits);
                c = next3;
                i += 4;
            }
            while (i < len)
            {
                ulong next = x[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
                ++i;
            }
            return c >> -bits;
        }
#endif

        public static void Square(int len, uint[] x, uint[] zz)
        {
            int extLen = len << 1;
            uint c = 0;
            int j = len, k = extLen;
            do
            {
                ulong xVal = (ulong)x[--j];
                ulong p = xVal * xVal;
                zz[--k] = (c << 31) | (uint)(p >> 33);
                zz[--k] = (uint)(p >> 1);
                c = (uint)p;
            }
            while (j > 0);

            ulong d = 0UL;
            int zzPos = 2;

            for (int i = 1; i < len; ++i)
            {
                d += SquareWordAddTo(x, i, zz);
                d += zz[zzPos];
                zz[zzPos++] = (uint)d; d >>= 32;
                d += zz[zzPos];
                zz[zzPos++] = (uint)d; d >>= 32;
            }
            Debug.Assert(0UL == d);

            ShiftUpBit(extLen, zz, x[0] << 31);
        }

        public static void Square(int len, uint[] x, int xOff, uint[] zz, int zzOff)
        {
            int extLen = len << 1;
            uint c = 0;
            int j = len, k = extLen;
            do
            {
                ulong xVal = (ulong)x[xOff + --j];
                ulong p = xVal * xVal;
                zz[zzOff + --k] = (c << 31) | (uint)(p >> 33);
                zz[zzOff + --k] = (uint)(p >> 1);
                c = (uint)p;
            }
            while (j > 0);

            ulong d = 0UL;
            int zzPos = zzOff + 2;

            for (int i = 1; i < len; ++i)
            {
                d += SquareWordAddTo(x, xOff, i, zz, zzOff);
                d += zz[zzPos];
                zz[zzPos++] = (uint)d; d >>= 32;
                d += zz[zzPos];
                zz[zzPos++] = (uint)d; d >>= 32;
            }
            Debug.Assert(0UL == d);

            ShiftUpBit(extLen, zz, zzOff, x[xOff] << 31);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Square(int len, ReadOnlySpan<uint> x, Span<uint> zz)
        {
            int extLen = len << 1;
            uint c = 0;
            int j = len, k = extLen;
            do
            {
                ulong xVal = (ulong)x[--j];
                ulong p = xVal * xVal;
                zz[--k] = (c << 31) | (uint)(p >> 33);
                zz[--k] = (uint)(p >> 1);
                c = (uint)p;
            }
            while (j > 0);

            ulong d = 0UL;
            int zzPos = 2;

            for (int i = 1; i < len; ++i)
            {
                d += SquareWordAddTo(x, i, zz);
                d += zz[zzPos];
                zz[zzPos++] = (uint)d; d >>= 32;
                d += zz[zzPos];
                zz[zzPos++] = (uint)d; d >>= 32;
            }
            Debug.Assert(0UL == d);

            ShiftUpBit(extLen, zz, x[0] << 31);
        }
#endif

        public static uint SquareWordAddTo(uint[] x, int xPos, uint[] z)
        {
            ulong c = 0, xVal = (ulong)x[xPos];
            int i = 0;
            do
            {
                c += xVal * x[i] + z[xPos + i];
                z[xPos + i] = (uint)c;
                c >>= 32;
            }
            while (++i < xPos);
            return (uint)c;
        }

        public static uint SquareWordAddTo(uint[] x, int xOff, int xPos, uint[] z, int zOff)
        {
            ulong c = 0, xVal = (ulong)x[xOff + xPos];
            int i = 0;
            do
            {
                c += xVal * (x[xOff + i] & M) + (z[xPos + zOff] & M);
                z[xPos + zOff] = (uint)c;
                c >>= 32;
                ++zOff;
            }
            while (++i < xPos);
            return (uint)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static uint SquareWordAddTo(ReadOnlySpan<uint> x, int xPos, Span<uint> z)
        {
            ulong c = 0, xVal = x[xPos];
            int i = 0;
            do
            {
                c += xVal * x[i] + z[xPos + i];
                z[xPos + i] = (uint)c;
                c >>= 32;
            }
            while (++i < xPos);
            return (uint)c;
        }
#endif

        public static int Sub(int len, uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[i] - y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int Sub(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[xOff + i] - y[yOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Sub(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[i] - y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }
#endif

        public static int Sub33At(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zPos + 0] - x;
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zPos + 1] - 1;
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zPos + 2);
        }

        public static int Sub33At(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zOff + zPos] - x;
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + zPos + 1] - 1;
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zOff, zPos + 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Sub33At(int len, uint x, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zPos + 0] - x;
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zPos + 1] - 1;
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zPos + 2);
        }
#endif

        public static int Sub33From(int len, uint x, uint[] z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - 1;
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, 2);
        }

        public static int Sub33From(int len, uint x, uint[] z, int zOff)
        {
            long c = (long)z[zOff + 0] - x;
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + 1] - 1;
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zOff, 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int Sub33From(int len, uint x, Span<uint> z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - 1;
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, 2);
        }
#endif

        public static int SubBothFrom(int len, uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[i] - x[i] - y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int SubBothFrom(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[zOff + i] - x[xOff + i] - y[yOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubBothFrom(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[i] - x[i] - y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }
#endif

        public static int SubDWordAt(int len, ulong x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = z[zPos + 0] - (long)(x & M);
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += z[zPos + 1] - (long)(x >> 32);
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zPos + 2);
        }

        public static int SubDWordAt(int len, ulong x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = z[zOff + zPos] - (long)(x & M);
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += z[zOff + zPos + 1] - (long)(x >> 32);
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zOff, zPos + 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubDWordAt(int len, ulong x, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = z[zPos + 0] - (long)(x & M);
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += z[zPos + 1] - (long)(x >> 32);
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zPos + 2);
        }
#endif

        public static int SubDWordFrom(int len, ulong x, uint[] z)
        {
            long c = z[0] - (long)(x & M);
            z[0] = (uint)c;
            c >>= 32;
            c += z[1] - (long)(x >> 32);
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, 2);
        }

        public static int SubDWordFrom(int len, ulong x, uint[] z, int zOff)
        {
            long c = z[zOff + 0] - (long)(x & M);
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += z[zOff + 1] - (long)(x >> 32);
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zOff, 2);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubDWordFrom(int len, ulong x, Span<uint> z)
        {
            long c = z[0] - (long)(x & M);
            z[0] = (uint)c;
            c >>= 32;
            c += z[1] - (long)(x >> 32);
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, 2);
        }
#endif

        public static int SubFrom(int len, uint[] x, uint[] z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[i] - x[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int SubFrom(int len, uint[] x, int xOff, uint[] z, int zOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[zOff + i] - x[xOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubFrom(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[i] - x[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubInt32From(int len, int x, Span<uint> z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;

            int i = 1;
            while (c != 0L && i < len)
            {
                c += z[i];
                z[i++] = (uint)c;
                c >>= 32;
            }

            return (int)c;
        }
#endif

        public static int SubWordAt(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            long c = (long)z[zPos] - x;
            z[zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zPos + 1);
        }

        public static int SubWordAt(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            long c = (long)z[zOff + zPos] - x;
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zOff, zPos + 1);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubWordAt(int len, uint x, Span<uint> z, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            long c = (long)z[zPos] - x;
            z[zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zPos + 1);
        }
#endif

        public static int SubWordFrom(int len, uint x, uint[] z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, 1);
        }

        public static int SubWordFrom(int len, uint x, uint[] z, int zOff)
        {
            long c = (long)z[zOff + 0] - x;
            z[zOff + 0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, zOff, 1);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int SubWordFrom(int len, uint x, Span<uint> z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : DecAt(len, z, 1);
        }
#endif

        public static BigInteger ToBigInteger(int len, uint[] x)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ToBigInteger(len, x.AsSpan());
#else
            byte[] bs = new byte[len << 2];
            int xPos = len, bsPos = 0;
            while (--xPos >= 0)
            {
                Pack.UInt32_To_BE(x[xPos], bs, bsPos);
                bsPos += 4;
            }
            return new BigInteger(1, bs);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static BigInteger ToBigInteger(int len, ReadOnlySpan<uint> x)
        {
            int bsLen = len << 2;
            Span<byte> bs = bsLen <= 512
                ? stackalloc byte[bsLen]
                : new byte[bsLen];

            Pack.UInt32_To_LE(x, bs);

            return new BigInteger(1, bs, bigEndian: false);
        }
#endif

        public static void Xor(int len, uint[] x, uint[] y, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor(len, x.AsSpan(0, len), y.AsSpan(0, len), z.AsSpan(0, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] = x[i] ^ y[i];
            }
#endif
        }

        public static void Xor(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor(len, x.AsSpan(xOff, len), y.AsSpan(yOff, len), z.AsSpan(zOff, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[zOff + i] = x[xOff + i] ^ y[yOff + i];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Xor(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
            int i = 0, limit16 = len - 16;
            while (i <= limit16)
            {
                Nat512.Xor(x[i..], y[i..], z[i..]);
                i += 16;
            }
            while (i < len)
            {
                z[i] = x[i] ^ y[i];
                ++i;
            }
        }
#endif

        public static void Xor64(int len, ulong[] x, ulong y, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor64(len, x.AsSpan(0, len), y, z.AsSpan(0, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] = x[i] ^ y;
            }
#endif
        }

        public static void Xor64(int len, ulong[] x, int xOff, ulong y, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor64(len, x.AsSpan(xOff, len), y, z.AsSpan(zOff, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[zOff + i] = x[xOff + i] ^ y;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Xor64(int len, ReadOnlySpan<ulong> x, ulong y, Span<ulong> z)
        {
            int i = 0;
            if (Vector.IsHardwareAccelerated)
            {
                var vy = new Vector<ulong>(y);

                int limit = len - Vector<ulong>.Count;
                while (i <= limit)
                {
                    var vx = new Vector<ulong>(x[i..]);
                    (vx ^ vy).CopyTo(z[i..]);
                    i += Vector<ulong>.Count;
                }
            }
            else
            {
                int limit = len - 4;
                while (i <= limit)
                {
                    z[i + 0] = x[i + 0] ^ y;
                    z[i + 1] = x[i + 1] ^ y;
                    z[i + 2] = x[i + 2] ^ y;
                    z[i + 3] = x[i + 3] ^ y;
                    i += 4;
                }
            }
            while (i < len)
            {
                z[i] = x[i] ^ y;
                ++i;
            }
        }
#endif

        public static void Xor64(int len, ulong[] x, ulong[] y, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor64(len, x.AsSpan(0, len), y.AsSpan(0, len), z.AsSpan(0, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] = x[i] ^ y[i];
            }
#endif
        }

        public static void Xor64(int len, ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor64(len, x.AsSpan(xOff, len), y.AsSpan(yOff, len), z.AsSpan(zOff, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[zOff + i] = x[xOff + i] ^ y[yOff + i];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Xor64(int len, ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
        {
            int i = 0, limit8 = len - 8;
            while (i <= limit8)
            {
                Nat512.Xor64(x[i..], y[i..], z[i..]);
                i += 8;
            }
            while (i < len)
            {
                z[i] = x[i] ^ y[i];
                ++i;
            }
        }
#endif

        public static void XorTo(int len, uint[] x, uint[] z)
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

        public static void XorTo(int len, uint[] x, int xOff, uint[] z, int zOff)
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
        public static void XorTo(int len, ReadOnlySpan<uint> x, Span<uint> z)
        {
            int i = 0, limit16 = len - 16;
            while (i <= limit16)
            {
                Nat512.XorTo(x[i..], z[i..]);
                i += 16;
            }
            while (i < len)
            {
                z[i] ^= x[i];
                ++i;
            }
        }
#endif

        public static void XorTo64(int len, ulong[] x, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo64(len, x.AsSpan(0, len), z.AsSpan(0, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] ^= x[i];
            }
#endif
        }

        public static void XorTo64(int len, ulong[] x, int xOff, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo64(len, x.AsSpan(xOff, len), z.AsSpan(zOff, len));
#else
            for (int i = 0; i < len; ++i)
            {
                z[zOff + i] ^= x[xOff + i];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void XorTo64(int len, ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            int i = 0, limit8 = len - 8;
            while (i <= limit8)
            {
                Nat512.XorTo64(x[i..], z[i..]);
                i += 8;
            }
            while (i < len)
            {
                z[i] ^= x[i];
                ++i;
            }
        }
#endif

        public static void Zero(int len, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            z.AsSpan(0, len).Fill(0U);
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] = 0U;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Zero(int len, Span<uint> z)
        {
            z[..len].Fill(0U);
        }
#endif

        public static void Zero64(int len, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            z.AsSpan(0, len).Fill(0UL);
#else
            for (int i = 0; i < len; ++i)
            {
                z[i] = 0UL;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Zero64(int len, Span<ulong> z)
        {
            z[..len].Fill(0UL);
        }
#endif
    }
}
