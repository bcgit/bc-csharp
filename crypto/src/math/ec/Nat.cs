﻿using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    internal abstract class Nat
    {
        public static uint Add(int len, uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

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

        // TODO Re-write to allow full range for x?
        public static uint AddDWord(int len, ulong x, uint[] z, int zOff)
        {
            Debug.Assert(zOff <= (len - 2));
            ulong c = x;
            c += (ulong)z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(len, z, zOff + 2);
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

        public static uint AddWord(int len, uint x, uint[] z)
        {
            ulong c = (ulong)x + z[0];
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(len, z, 1);
        }

        public static uint AddWordExt(int len, uint x, uint[] zz, int zzOff)
        {
            int extLen = len << 1;
            Debug.Assert(zzOff <= (extLen - 1));
            ulong c = (ulong)x + zz[zzOff];
            zz[zzOff] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(extLen, zz, zzOff + 1);
        }

        public static uint[] Copy(int len, uint[] x)
        {
            uint[] z = new uint[len];
            Array.Copy(x, 0, z, 0, len);
            return z;
        }

        public static uint[] Create(int len)
        {
            return new uint[len];
        }

        public static int Dec(int len, uint[] z, int zOff)
        {
            Debug.Assert(zOff <= len);
            for (int i = zOff; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                {
                    return 0;
                }
            }
            return -1;
        }

        public static bool Eq(int len, uint[] x, uint[] y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                if (x[i] != y[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static uint[] FromBigInteger(int bits, BigInteger x)
        {
            if (x.SignValue < 0 || x.BitLength > bits)
                throw new ArgumentException();

            int len = (bits + 31) >> 5;
            uint[] z = Create(len);
            int i = 0;
            while (x.SignValue != 0)
            {
                z[i++] = (uint)x.IntValue;
                x = x.ShiftRight(32);
            }
            return z;
        }

        public static uint GetBit(uint[] x, int bit)
        {
            if (bit == 0)
            {
                return x[0] & 1;
            }
            int w = bit >> 5;
            if (w < 0 || w >= x.Length)
            {
                return 0;
            }
            int b = bit & 31;
            return (x[w] >> b) & 1;
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

        public static uint Inc(int len, uint[] z, int zOff)
        {
            Debug.Assert(zOff <= len);
            for (int i = zOff; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static bool IsOne(int len, uint[] x)
        {
            if (x[0] != 1)
            {
                return false;
            }
            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsZero(int len, uint[] x)
        {
            if (x[0] != 0)
            {
                return false;
            }
            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static void Mul(int len, uint[] x, uint[] y, uint[] zz)
        {
            zz[len] = (uint)MulWord(len, x[0], y, zz, 0);

            for (int i = 1; i < len; ++i)
            {
                zz[i + len] = (uint)MulWordAdd(len, x[i], y, zz, i);
            }
        }

        public static uint Mul31BothAdd(int len, uint a, uint[] x, uint b, uint[] y, uint[] z, int zOff)
        {
            ulong c = 0, aVal = (ulong)a, bVal = (ulong)b;
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

        public static uint MulWord(int len, uint x, uint[] y, uint[] z, int zOff)
        {
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint MulWordAdd(int len, uint x, uint[] y, uint[] z, int zOff)
        {
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * y[i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint MulWordDwordAdd(int len, uint x, ulong y, uint[] z, int zOff)
        {
            Debug.Assert(zOff <= (len - 3));
            ulong c = 0, xVal = (ulong)x;
            c += xVal * (uint)y + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += xVal * (y >> 32) + z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(len, z, zOff + 3);
        }

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

        public static uint ShiftDownBits(int len, uint[] x, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                x[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint ShiftDownBits(int len, uint[] x, int xOff, int bits, uint c, uint[] z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[xOff + i];
                z[i] = (next >> bits) | (c << -bits);
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

        public static uint ShiftUpBit(int len, uint[] z, uint c)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = z[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static uint ShiftUpBit(int len, uint[] x, uint c, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = x[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static uint ShiftUpBit(int len, uint[] x, int xOff, uint c, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = x[xOff + i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static uint ShiftUpBits(int len, uint[] z, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            for (int i = 0; i < len; ++i)
            {
                uint next = z[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static uint ShiftUpBits(int len, uint[] x, int bits, uint c, uint[] z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            for (int i = 0; i < len; ++i)
            {
                uint next = x[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

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

            for (int i = 1; i < len; ++i)
            {
                c = SquareWordAddExt(len, x, i, zz);
                AddWordExt(len, c, zz, i << 1);
            }

            ShiftUpBit(extLen, zz, x[0] << 31);
        }

        public static uint SquareWordAddExt(int len, uint[] x, int xPos, uint[] zz)
        {
            Debug.Assert(xPos > 0 && xPos < len);
            ulong c = 0, xVal = (ulong)x[xPos];
            int i = 0;
            do
            {
                c += xVal * x[i] + zz[xPos + i];
                zz[xPos + i] = (uint)c;
                c >>= 32;
            }
            while (++i < xPos);
            return (uint)c;
        }

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

        // TODO Re-write to allow full range for x?
        public static int SubDWord(int len, ulong x, uint[] z)
        {
            Debug.Assert(len >= 2);
            long c = -(long)x;
            c += (long)z[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1];
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Dec(len, z, 2);
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

        public static BigInteger ToBigInteger(int len, uint[] x)
        {
            byte[] bs = new byte[len << 2];
            for (int i = 0; i < len; ++i)
            {
                uint x_i = x[i];
                if (x_i != 0)
                {
                    Pack.UInt32_To_BE(x_i, bs, (len - 1 - i) << 2);
                }
            }
            return new BigInteger(1, bs);
        }

        public static void Zero(int len, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                z[i] = 0;
            }
        }
    }
}
