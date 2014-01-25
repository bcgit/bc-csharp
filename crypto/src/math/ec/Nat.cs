using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;

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

        public static uint AddDWord(int len, ulong x, uint[] z, int zOff)
        {
            // assert zOff < (len - 2);
            ulong c = x;
            c += (ulong)z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(len, z, zOff + 2);
        }

        public static uint AddExt(int len, uint[] xx, uint[] yy, uint[] zz)
        {
            int extLen = len << 1;
            ulong c = 0;
            for (int i = 0; i < extLen; ++i)
            {
                c += (ulong)xx[i] + yy[i];
                zz[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint AddToExt(int len, uint[] x, int xOff, uint[] zz, int zzOff)
        {
            // assert zzOff <= len;
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[xOff + i] + zz[zzOff + i];
                zz[zzOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint AddWordExt(int len, uint x, uint[] zz, int zzOff)
        {
            // assert zzOff < ((len << 1) - 1);
            ulong c = (ulong)x + zz[zzOff];
            zz[zzOff] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncExt(len, zz, zzOff + 1);
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

        public static uint[] CreateExt(int len)
        {
            int extLen = len << 1;
            return new uint[extLen];
        }

        public static int Dec(int len, uint[] z, int zOff)
        {
            // assert zOff < len;
            int i = zOff;
            do
            {
                if (--z[i] != uint.MaxValue)
                {
                    return 0;
                }
            }
            while (++i < len);
            return -1;
        }

        public static uint[] FromBigInteger(int len, BigInteger x)
        {
            if (x.SignValue < 0 || x.BitLength > (len << 5))
                throw new ArgumentException();

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
            uint w = (uint)bit >> 5;
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
            return false;
        }

        public static bool GteExt(int len, uint[] xx, uint[] yy)
        {
            int extLen = len << 1;
            for (int i = extLen - 1; i >= 0; --i)
            {
                uint xx_i = xx[i], yy_i = yy[i];
                if (xx_i < yy_i)
                    return false;
                if (xx_i > yy_i)
                    return true;
            }
            return false;
        }

        public static uint Inc(int len, uint[] z, int zOff)
        {
            // assert zOff < len;
            for (int i = zOff; i < len; ++i)
            {
                if (++z[i] != 0)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static uint IncExt(int len, uint[] zz, int zzOff)
        {
            int extLen = len;
            // assert zzOff < extLen;
            for (int i = zzOff; i < extLen; ++i)
            {
                if (++zz[i] != 0)
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

        public static bool IsZeroExt(int len, uint[] xx)
        {
            if (xx[0] != 0)
            {
                return false;
            }
            int extLen = len << 1;
            for (int i = 1; i < extLen; ++i)
            {
                if (xx[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static void Mul(int len, uint[] x, uint[] y, uint[] zz)
        {
            zz[len] = (uint)MulWordExt(len, x[0], y, zz, 0);

            for (int i = 1; i < len; ++i)
            {
                zz[i + len] = (uint)MulWordAddExt(len, x[i], y, 0, zz, i);
            }
        }

        public static uint MulWordAddExt(int len, uint x, uint[] yy, int yyOff, uint[] zz, int zzOff)
        {
            // assert yyOff <= len;
            // assert zzOff <= len;
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * yy[yyOff + i] + zz[zzOff + i];
                zz[zzOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint MulWordDwordAdd(int len, uint x, ulong y, uint[] z, int zOff)
        {
            // assert zOff < (len - 3);
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

        public static uint MulWordExt(int len, uint x, uint[] y, uint[] zz, int zzOff)
        {
            // assert zzOff <= len;
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                zz[zzOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint ShiftDownBit(uint[] x, int xLen, uint c)
        {
            int i = xLen;
            while (--i >= 0)
            {
                uint next = x[i];
                x[i] = (next >> 1) | (c << 31);
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

        public static uint ShiftDownBits(uint[] x, int xLen, int bits, uint c)
        {
            //assert bits > 0 && bits < 32;
            int i = xLen;
            while (--i >= 0)
            {
                uint next = x[i];
                x[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << 32 - bits;
        }

        public static uint ShiftDownWord(uint[] x, int xLen, uint c)
        {
            int i = xLen;
            while (--i >= 0)
            {
                uint next = x[i];
                x[i] = c;
                c = next;
            }
            return c;
        }

        public static uint ShiftUpBit(uint[] x, int xLen, uint c)
        {
            for (int i = 0; i < xLen; ++i)
            {
                uint next = x[i];
                x[i] = (next << 1) | (c >> 31);
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

            ShiftUpBit(zz, extLen, x[0] << 31);
        }

        public static uint SquareWordAddExt(int len, uint[] x, int xPos, uint[] zz)
        {
            // assert xPos > 0 && xPos < len;
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

        public static int SubDWord(int len, ulong x, uint[] z)
        {
            long c = -(long)x;
            c += (long)z[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1];
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Dec(len, z, 2);
        }

        public static int SubExt(int len, uint[] xx, uint[] yy, uint[] zz)
        {
            int extLen = len << 1;
            long c = 0;
            for (int i = 0; i < extLen; ++i)
            {
                c += (long)xx[i] - yy[i];
                zz[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int SubFromExt(int len, uint[] x, int xOff, uint[] zz, int zzOff)
        {
            // assert zzOff <= len;
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)zz[zzOff + i] - x[xOff + i];
                zz[zzOff + i] = (uint)c;
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
