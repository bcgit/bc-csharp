using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Math.Raw
{
    internal static class Nat448
    {
        public static void Copy64(ulong[] x, ulong[] z)
        {
            z[0] = x[0];
            z[1] = x[1];
            z[2] = x[2];
            z[3] = x[3];
            z[4] = x[4];
            z[5] = x[5];
            z[6] = x[6];
        }

        public static void Copy64(ulong[] x, int xOff, ulong[] z, int zOff)
        {
            z[zOff + 0] = x[xOff + 0];
            z[zOff + 1] = x[xOff + 1];
            z[zOff + 2] = x[xOff + 2];
            z[zOff + 3] = x[xOff + 3];
            z[zOff + 4] = x[xOff + 4];
            z[zOff + 5] = x[xOff + 5];
            z[zOff + 6] = x[xOff + 6];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Copy64(ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            z[0] = x[0];
            z[1] = x[1];
            z[2] = x[2];
            z[3] = x[3];
            z[4] = x[4];
            z[5] = x[5];
            z[6] = x[6];
        }
#endif

        public static ulong[] Create64()
        {
            return new ulong[7];
        }

        public static ulong[] CreateExt64()
        {
            return new ulong[14];
        }

        public static bool Eq64(ulong[] x, ulong[] y)
        {
            for (int i = 6; i >= 0; --i)
            {
                if (x[i] != y[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsOne64(ulong[] x)
        {
            if (x[0] != 1UL)
            {
                return false;
            }
            for (int i = 1; i < 7; ++i)
            {
                if (x[i] != 0UL)
                {
                    return false;
                }
            }
            return true;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static bool IsZero64(ReadOnlySpan<ulong> x)
#else
        public static bool IsZero64(ulong[] x)
#endif
        {
            for (int i = 0; i < 7; ++i)
            {
                if (x[i] != 0UL)
                {
                    return false;
                }
            }
            return true;
        }

        public static void Mul(uint[] x, uint[] y, uint[] zz)
        {
            Nat224.Mul(x, y, zz);
            Nat224.Mul(x, 7, y, 7, zz, 14);

            uint c21 = Nat224.AddToEachOther(zz, 7, zz, 14);
            uint c14 = c21 + Nat224.AddTo(zz, 0, zz, 7, 0U);
            c21 += Nat224.AddTo(zz, 21, zz, 14, c14);

            uint[] dx = Nat224.Create(), dy = Nat224.Create();
            bool neg = Nat224.Diff(x, 7, x, 0, dx, 0) != Nat224.Diff(y, 7, y, 0, dy, 0);

            uint[] tt = Nat224.CreateExt();
            Nat224.Mul(dx, dy, tt);

            c21 += neg ? Nat.AddTo(14, tt, 0, zz, 7) : (uint)Nat.SubFrom(14, tt, 0, zz, 7);
            Nat.AddWordAt(28, c21, zz, 21);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Mul(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
        {
            Nat224.Mul(x, y, zz);
            Nat224.Mul(x[7..], y[7..], zz[14..]);

            uint c21 = Nat224.AddToEachOther(zz[7..], zz[14..]);
            uint c14 = c21 + Nat224.AddTo(zz, zz[7..], 0U);
            c21 += Nat224.AddTo(zz[21..], zz[14..], c14);

            Span<uint> dx = stackalloc uint[7];
            Span<uint> dy = stackalloc uint[7];
            bool neg = Nat224.Diff(x[7..], x, dx) != Nat224.Diff(y[7..], y, dy);

            Span<uint> tt = stackalloc uint[14];
            Nat224.Mul(dx, dy, tt);

            c21 += neg ? Nat.AddTo(14, tt, zz[7..]) : (uint)Nat.SubFrom(14, tt, zz[7..]);
            Nat.AddWordAt(28, c21, zz, 21);
        }
#endif

        public static void Square(uint[] x, uint[] zz)
        {
            Nat224.Square(x, zz);
            Nat224.Square(x, 7, zz, 14);

            uint c21 = Nat224.AddToEachOther(zz, 7, zz, 14);
            uint c14 = c21 + Nat224.AddTo(zz, 0, zz, 7, 0U);
            c21 += Nat224.AddTo(zz, 21, zz, 14, c14);

            uint[] dx = Nat224.Create();
            Nat224.Diff(x, 7, x, 0, dx, 0);

            uint[] tt = Nat224.CreateExt();
            Nat224.Square(dx, tt);

            c21 += (uint)Nat.SubFrom(14, tt, 0, zz, 7);
            Nat.AddWordAt(28, c21, zz, 21);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Square(ReadOnlySpan<uint> x, Span<uint> zz)
        {
            Nat224.Square(x, zz);
            Nat224.Square(x[7..], zz[14..]);

            uint c21 = Nat224.AddToEachOther(zz[7..], zz[14..]);
            uint c14 = c21 + Nat224.AddTo(zz, zz[7..], 0U);
            c21 += Nat224.AddTo(zz[21..], zz[14..], c14);

            Span<uint> dx = stackalloc uint[7];
            Nat224.Diff(x[7..], x, dx);

            Span<uint> tt = stackalloc uint[14];
            Nat224.Square(dx, tt);

            c21 += (uint)Nat.SubFrom(14, tt, zz[7..]);
            Nat.AddWordAt(28, c21, zz, 21);
        }
#endif

        public static BigInteger ToBigInteger64(ulong[] x)
        {
            byte[] bs = new byte[56];
            for (int i = 0; i < 7; ++i)
            {
                ulong x_i = x[i];
                if (x_i != 0L)
                {
                    Pack.UInt64_To_BE(x_i, bs, (6 - i) << 3);
                }
            }
            return new BigInteger(1, bs);
        }
    }
}
