using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal abstract class Nat256
    {
        private const ulong M = 0xFFFFFFFFUL;

        public static uint Add(uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            c += (ulong)x[0] + y[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)x[1] + y[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (ulong)x[2] + y[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (ulong)x[3] + y[3];
            z[3] = (uint)c;
            c >>= 32;
            c += (ulong)x[4] + y[4];
            z[4] = (uint)c;
            c >>= 32;
            c += (ulong)x[5] + y[5];
            z[5] = (uint)c;
            c >>= 32;
            c += (ulong)x[6] + y[6];
            z[6] = (uint)c;
            c >>= 32;
            c += (ulong)x[7] + y[7];
            z[7] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint AddBothTo(uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            c += (ulong)x[0] + y[0] + z[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)x[1] + y[1] + z[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (ulong)x[2] + y[2] + z[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (ulong)x[3] + y[3] + z[3];
            z[3] = (uint)c;
            c >>= 32;
            c += (ulong)x[4] + y[4] + z[4];
            z[4] = (uint)c;
            c >>= 32;
            c += (ulong)x[5] + y[5] + z[5];
            z[5] = (uint)c;
            c >>= 32;
            c += (ulong)x[6] + y[6] + z[6];
            z[6] = (uint)c;
            c >>= 32;
            c += (ulong)x[7] + y[7] + z[7];
            z[7] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        // TODO Re-write to allow full range for x?
        public static uint AddDWord(ulong x, uint[] z, int zOff)
        {
            Debug.Assert(zOff < 6);
            ulong c = x;
            c += (ulong)z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(z, zOff + 2);
        }

        public static uint AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            ulong c = 0;
            for (int i = 0; i < 16; ++i)
            {
                c += (ulong)xx[i] + yy[i];
                zz[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint AddToExt(uint[] x, int xOff, uint[] zz, int zzOff)
        {
            Debug.Assert(zzOff <= 8);
            ulong c = 0;
            c += (ulong)x[xOff + 0] + zz[zzOff + 0];
            zz[zzOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 1] + zz[zzOff + 1];
            zz[zzOff + 1] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 2] + zz[zzOff + 2];
            zz[zzOff + 2] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 3] + zz[zzOff + 3];
            zz[zzOff + 3] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 4] + zz[zzOff + 4];
            zz[zzOff + 4] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 5] + zz[zzOff + 5];
            zz[zzOff + 5] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 6] + zz[zzOff + 6];
            zz[zzOff + 6] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 7] + zz[zzOff + 7];
            zz[zzOff + 7] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint AddWordExt(uint x, uint[] zz, int zzOff)
        {
            Debug.Assert(zzOff < 15);
            ulong c = (ulong)x + zz[zzOff + 0];
            zz[zzOff + 0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : IncExt(zz, zzOff + 1);
        }

        public static uint[] Create()
        {
            return new uint[8];
        }

        public static uint[] CreateExt()
        {
            return new uint[16];
        }

        public static int Dec(uint[] z, int zOff)
        {
            Debug.Assert(zOff < 8);
            int i = zOff;
            do
            {
                if (--z[i] != uint.MaxValue)
                {
                    return 0;
                }
            }
            while (++i < 8);
            return -1;
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            if (x.SignValue < 0 || x.BitLength > 256)
                throw new ArgumentException();

            uint[] z = Create();
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
            if ((bit & 255) != bit)
            {
                return 0;
            }
            int w = bit >> 5;
            int b = bit & 31;
            return (x[w] >> b) & 1;
        }

        public static bool Gte(uint[] x, uint[] y)
        {
            for (int i = 7; i >= 0; --i)
            {
                uint x_i = x[i], y_i = y[i];
                if (x_i < y_i)
                    return false;
                if (x_i > y_i)
                    return true;
            }
            return false;
        }

        public static bool GteExt(uint[] xx, uint[] yy)
        {
            for (int i = 15; i >= 0; --i)
            {
                uint xx_i = xx[i], yy_i = yy[i];
                if (xx_i < yy_i)
                    return false;
                if (xx_i > yy_i)
                    return true;
            }
            return false;
        }

        public static uint Inc(uint[] z, int zOff)
        {
            Debug.Assert(zOff < 8);
            for (int i = zOff; i < 8; ++i)
            {
                if (++z[i] != 0)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static uint IncExt(uint[] zz, int zzOff)
        {
            Debug.Assert(zzOff < 16);
            for (int i = zzOff; i < 16; ++i)
            {
                if (++zz[i] != 0)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static bool IsOne(uint[] x)
        {
            if (x[0] != 1)
            {
                return false;
            }
            for (int i = 1; i < 8; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsZero(uint[] x)
        {
            for (int i = 0; i < 8; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsZeroExt(uint[] xx)
        {
            for (int i = 0; i < 16; ++i)
            {
                if (xx[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static void Mul(uint[] x, uint[] y, uint[] zz)
        {
            ulong y_0 = y[0];
            ulong y_1 = y[1];
            ulong y_2 = y[2];
            ulong y_3 = y[3];
            ulong y_4 = y[4];
            ulong y_5 = y[5];
            ulong y_6 = y[6];
            ulong y_7 = y[7];

            {
                ulong c = 0, x_0 = x[0];
                c += x_0 * y_0;
                zz[0] = (uint)c;
                c >>= 32;
                c += x_0 * y_1;
                zz[1] = (uint)c;
                c >>= 32;
                c += x_0 * y_2;
                zz[2] = (uint)c;
                c >>= 32;
                c += x_0 * y_3;
                zz[3] = (uint)c;
                c >>= 32;
                c += x_0 * y_4;
                zz[4] = (uint)c;
                c >>= 32;
                c += x_0 * y_5;
                zz[5] = (uint)c;
                c >>= 32;
                c += x_0 * y_6;
                zz[6] = (uint)c;
                c >>= 32;
                c += x_0 * y_7;
                zz[7] = (uint)c;
                c >>= 32;
                zz[8] = (uint)c;
            }

            for (int i = 1; i < 8; ++i)
            {
                ulong c = 0, x_i = x[i];
                c += x_i * y_0 + zz[i + 0];
                zz[i + 0] = (uint)c;
                c >>= 32;
                c += x_i * y_1 + zz[i + 1];
                zz[i + 1] = (uint)c;
                c >>= 32;
                c += x_i * y_2 + zz[i + 2];
                zz[i + 2] = (uint)c;
                c >>= 32;
                c += x_i * y_3 + zz[i + 3];
                zz[i + 3] = (uint)c;
                c >>= 32;
                c += x_i * y_4 + zz[i + 4];
                zz[i + 4] = (uint)c;
                c >>= 32;
                c += x_i * y_5 + zz[i + 5];
                zz[i + 5] = (uint)c;
                c >>= 32;
                c += x_i * y_6 + zz[i + 6];
                zz[i + 6] = (uint)c;
                c >>= 32;
                c += x_i * y_7 + zz[i + 7];
                zz[i + 7] = (uint)c;
                c >>= 32;
                zz[i + 8] = (uint)c;
            }
        }

        public static uint MulWordAddExt(uint x, uint[] yy, int yyOff, uint[] zz, int zzOff)
        {
            Debug.Assert(yyOff <= 8);
            Debug.Assert(zzOff <= 8);
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * yy[yyOff + i] + zz[zzOff + i];
                zz[zzOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < 8);
            return (uint)c;
        }

        public static uint MulWordDwordAdd(uint x, ulong y, uint[] z, int zOff)
        {
            Debug.Assert(zOff < 5);
            ulong c = 0, xVal = x;
            c += xVal * y + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += xVal * (y >> 32) + z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += z[zOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Inc(z, zOff + 3);
        }

        public static uint MulWordExt(uint x, uint[] y, uint[] zz, int zzOff)
        {
            Debug.Assert(zzOff <= 8);
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                zz[zzOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < 8);
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

        public static uint ShiftDownBit(uint[] x, uint c, uint[] z)
        {
            int i = 8;
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
            Debug.Assert(bits > 0 && bits < 32);
            int i = xLen;
            while (--i >= 0)
            {
                uint next = x[i];
                x[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
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

        public static uint ShiftUpBit(uint[] x, uint c, uint[] z)
        {
            for (int i = 0; i < 8; ++i)
            {
                uint next = x[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static void Square(uint[] x, uint[] zz)
        {
            ulong x_0 = x[0];
            ulong zz_1;

            {
                uint c = 0;
                int i = 7, j = 16;
                do
                {
                    ulong xVal = x[i--];
                    ulong p = xVal * xVal;
                    zz[--j] = (c << 31) | (uint)(p >> 33);
                    zz[--j] = (uint)(p >> 1);
                    c = (uint)p;
                }
                while (i > 0);

                {
                    ulong p = x_0 * x_0;
                    zz_1 = (ulong)(c << 31) | (p >> 33);
                    zz[0] = (uint)(p >> 1);
                }
            }

            ulong x_1 = x[1];
            ulong zz_2 = zz[2];

            {
                zz_1 += x_1 * x_0;
                zz[1] = (uint)zz_1;
                zz_2 += zz_1 >> 32;
            }

            ulong x_2 = x[2];
            ulong zz_3 = zz[3];
            ulong zz_4 = zz[4];
            {
                zz_2 += x_2 * x_0;
                zz[2] = (uint)zz_2;
                zz_3 += (zz_2 >> 32) + x_2 * x_1;
                zz_4 += zz_3 >> 32;
                zz_3 &= M;
            }

            ulong x_3 = x[3];
            ulong zz_5 = zz[5];
            ulong zz_6 = zz[6];
            {
                zz_3 += x_3 * x_0;
                zz[3] = (uint)zz_3;
                zz_4 += (zz_3 >> 32) + x_3 * x_1;
                zz_5 += (zz_4 >> 32) + x_3 * x_2;
                zz_4 &= M;
                zz_6 += zz_5 >> 32;
                zz_5 &= M;
            }

            ulong x_4 = x[4];
            ulong zz_7 = zz[7];
            ulong zz_8 = zz[8];
            {
                zz_4 += x_4 * x_0;
                zz[4] = (uint)zz_4;
                zz_5 += (zz_4 >> 32) + x_4 * x_1;
                zz_6 += (zz_5 >> 32) + x_4 * x_2;
                zz_5 &= M;
                zz_7 += (zz_6 >> 32) + x_4 * x_3;
                zz_6 &= M;
                zz_8 += zz_7 >> 32;
                zz_7 &= M;
            }

            ulong x_5 = x[5];
            ulong zz_9 = zz[9];
            ulong zz_10 = zz[10];
            {
                zz_5 += x_5 * x_0;
                zz[5] = (uint)zz_5;
                zz_6 += (zz_5 >> 32) + x_5 * x_1;
                zz_7 += (zz_6 >> 32) + x_5 * x_2;
                zz_6 &= M;
                zz_8 += (zz_7 >> 32) + x_5 * x_3;
                zz_7 &= M;
                zz_9 += (zz_8 >> 32) + x_5 * x_4;
                zz_8 &= M;
                zz_10 += zz_9 >> 32;
                zz_9 &= M;
            }

            ulong x_6 = x[6];
            ulong zz_11 = zz[11];
            ulong zz_12 = zz[12];
            {
                zz_6 += x_6 * x_0;
                zz[6] = (uint)zz_6;
                zz_7 += (zz_6 >> 32) + x_6 * x_1;
                zz_8 += (zz_7 >> 32) + x_6 * x_2;
                zz_7 &= M;
                zz_9 += (zz_8 >> 32) + x_6 * x_3;
                zz_8 &= M;
                zz_10 += (zz_9 >> 32) + x_6 * x_4;
                zz_9 &= M;
                zz_11 += (zz_10 >> 32) + x_6 * x_5;
                zz_10 &= M;
                zz_12 += zz_11 >> 32;
                zz_11 &= M;
            }

            ulong x_7 = x[7];
            ulong zz_13 = zz[13];
            ulong zz_14 = zz[14];
            {
                zz_7 += x_7 * x_0;
                zz[7] = (uint)zz_7;
                zz_8 += (zz_7 >> 32) + x_7 * x_1;
                zz_9 += (zz_8 >> 32) + x_7 * x_2;
                zz_10 += (zz_9 >> 32) + x_7 * x_3;
                zz_11 += (zz_10 >> 32) + x_7 * x_4;
                zz_12 += (zz_11 >> 32) + x_7 * x_5;
                zz_13 += (zz_12 >> 32) + x_7 * x_6;
                zz_14 += zz_13 >> 32;
            }

            zz[8] = (uint)zz_8;
            zz[9] = (uint)zz_9;
            zz[10] = (uint)zz_10;
            zz[11] = (uint)zz_11;
            zz[12] = (uint)zz_12;
            zz[13] = (uint)zz_13;
            zz[14] = (uint)zz_14;
            zz[15] += (uint)(zz_14 >> 32);

            ShiftUpBit(zz, 16, (uint)x_0 << 31);
        }

        public static uint SquareWordAddExt(uint[] x, int xPos, uint[] zz)
        {
            Debug.Assert(xPos > 0 && xPos < 8);
            ulong c = 0, xVal = x[xPos];
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

        public static int Sub(uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            c += (long)x[0] - y[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)x[1] - y[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (long)x[2] - y[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (long)x[3] - y[3];
            z[3] = (uint)c;
            c >>= 32;
            c += (long)x[4] - y[4];
            z[4] = (uint)c;
            c >>= 32;
            c += (long)x[5] - y[5];
            z[5] = (uint)c;
            c >>= 32;
            c += (long)x[6] - y[6];
            z[6] = (uint)c;
            c >>= 32;
            c += (long)x[7] - y[7];
            z[7] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static int SubBothFrom(uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            c += (long)z[0] - x[0] - y[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - x[1] - y[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (long)z[2] - x[2] - y[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (long)z[3] - x[3] - y[3];
            z[3] = (uint)c;
            c >>= 32;
            c += (long)z[4] - x[4] - y[4];
            z[4] = (uint)c;
            c >>= 32;
            c += (long)z[5] - x[5] - y[5];
            z[5] = (uint)c;
            c >>= 32;
            c += (long)z[6] - x[6] - y[6];
            z[6] = (uint)c;
            c >>= 32;
            c += (long)z[7] - x[7] - y[7];
            z[7] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        // TODO Re-write to allow full range for x?
        public static int SubDWord(ulong x, uint[] z)
        {
            long c = -(long)x;
            c += (long)z[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1];
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Dec(z, 2);
        }

        public static int SubExt(uint[] xx, uint[] yy, uint[] zz)
        {
            long c = 0;
            for (int i = 0; i < 16; ++i)
            {
                c += (long)xx[i] - yy[i];
                zz[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int SubFromExt(uint[] x, int xOff, uint[] zz, int zzOff)
        {
            Debug.Assert(zzOff <= 8);
            long c = 0;
            c += (long)zz[zzOff + 0] - x[xOff + 0];
            zz[zzOff + 0] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 1] - x[xOff + 1];
            zz[zzOff + 1] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 2] - x[xOff + 2];
            zz[zzOff + 2] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 3] - x[xOff + 3];
            zz[zzOff + 3] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 4] - x[xOff + 4];
            zz[zzOff + 4] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 5] - x[xOff + 5];
            zz[zzOff + 5] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 6] - x[xOff + 6];
            zz[zzOff + 6] = (uint)c;
            c >>= 32;
            c += (long)zz[zzOff + 7] - x[xOff + 7];
            zz[zzOff + 7] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static BigInteger ToBigInteger(uint[] x)
        {
            byte[] bs = new byte[32];
            for (int i = 0; i < 8; ++i)
            {
                uint x_i = x[i];
                if (x_i != 0)
                {
                    Pack.UInt32_To_BE(x_i, bs, (7 - i) << 2);
                }
            }
            return new BigInteger(1, bs);
        }

        public static void Zero(uint[] z)
        {
            z[0] = 0;
            z[1] = 0;
            z[2] = 0;
            z[3] = 0;
            z[4] = 0;
            z[5] = 0;
            z[6] = 0;
            z[7] = 0;
        }
    }
}
