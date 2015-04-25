using System;
using System.Diagnostics;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecT571Field
    {
        private const ulong M59 = ulong.MaxValue >> 5;

        private const ulong RM = 0xEF7BDEF7BDEF7BDEUL;

        public static void Add(ulong[] x, ulong[] y, ulong[] z)
        {
            for (int i = 0; i < 9; ++i)
            {
                z[i] = x[i] ^ y[i]; 
            }
        }

        private static void Add(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            for (int i = 0; i < 9; ++i)
            {
                z[zOff + i] = x[xOff + i] ^ y[yOff + i];
            }
        }

        private static void AddBothTo(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            for (int i = 0; i < 9; ++i)
            {
                z[zOff + i] ^= x[xOff + i] ^ y[yOff + i];
            }
        }

        public static void AddExt(ulong[] xx, ulong[] yy, ulong[] zz)
        {
            for (int i = 0; i < 18; ++i)
            {
                zz[i] = xx[i] ^ yy[i]; 
            }
        }

        public static void AddOne(ulong[] x, ulong[] z)
        {
            z[0] = x[0] ^ 1UL;
            for (int i = 1; i < 9; ++i)
            {
                z[i] = x[i];
            }
        }

        public static ulong[] FromBigInteger(BigInteger x)
        {
            ulong[] z = Nat576.FromBigInteger64(x);
            Reduce5(z, 0);
            return z;
        }

        public static void Multiply(ulong[] x, ulong[] y, ulong[] z)
        {
            ulong[] tt = Nat576.CreateExt64();
            ImplMultiply(x, y, tt);
            Reduce(tt, z);
        }

        public static void MultiplyAddToExt(ulong[] x, ulong[] y, ulong[] zz)
        {
            ulong[] tt = Nat576.CreateExt64();
            ImplMultiply(x, y, tt);
            AddExt(zz, tt, zz);
        }

        public static void Reduce(ulong[] xx, ulong[] z)
        {
            ulong xx09 = xx[9];
            ulong u = xx[17], v = xx09;

            xx09  = v ^ (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
            v = xx[8] ^ (u <<  5) ^ (u <<  7) ^ (u << 10) ^ (u << 15);

            for (int i = 16; i >= 10; --i)
            {
                u = xx[i];
                z[i - 8]  = v ^ (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
                v = xx[i - 9] ^ (u <<  5) ^ (u <<  7) ^ (u << 10) ^ (u << 15);
            }

            u = xx09;
            z[1]  = v ^ (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
            v = xx[0] ^ (u <<  5) ^ (u <<  7) ^ (u << 10) ^ (u << 15);

            ulong x08 = z[8];
            ulong t   = x08 >> 59;
            z[0]      = v ^ t ^ (t << 2) ^ (t << 5) ^ (t << 10);
            z[8]      = x08 & M59;
        }

        public static void Reduce5(ulong[] z, int zOff)
        {
            ulong z8     = z[zOff + 8], t = z8 >> 59;
            z[zOff    ] ^= t ^ (t << 2) ^ (t << 5) ^ (t << 10);
            z[zOff + 8]  = z8 & M59;
        }

        public static void Square(ulong[] x, ulong[] z)
        {
            ulong[] tt = Nat576.CreateExt64();
            ImplSquare(x, tt);
            Reduce(tt, z);
        }

        public static void SquareAddToExt(ulong[] x, ulong[] zz)
        {
            ulong[] tt = Nat576.CreateExt64();
            ImplSquare(x, tt);
            AddExt(zz, tt, zz);
        }

        public static void SquareN(ulong[] x, int n, ulong[] z)
        {
            Debug.Assert(n > 0);

            ulong[] tt = Nat576.CreateExt64();
            ImplSquare(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                ImplSquare(z, tt);
                Reduce(tt, z);
            }
        }

        protected static void ImplMultiply(ulong[] x, ulong[] y, ulong[] zz)
        {
            //for (int i = 0; i < 9; ++i)
            //{
            //    ImplMulwAcc(x, y[i], zz, i);
            //}

            /*
             * Precompute table of all 4-bit products of y
             */
            ulong[] T0 = new ulong[9 << 4];
            Array.Copy(y, 0, T0, 9, 9);
    //        Reduce5(T0, 9);
            int tOff = 0;
            for (int i = 7; i > 0; --i)
            {
                tOff += 18;
                Nat.ShiftUpBit64(9, T0, tOff >> 1, 0UL, T0, tOff);
                Reduce5(T0, tOff);
                Add(T0, 9, T0, tOff, T0, tOff + 9);
            }

            /*
             * Second table with all 4-bit products of B shifted 4 bits
             */
            ulong[] T1 = new ulong[T0.Length];
            Nat.ShiftUpBits64(T0.Length, T0, 0, 4, 0L, T1, 0);

            uint MASK = 0xF;

            /*
             * Lopez-Dahab algorithm
             */

            for (int k = 56; k >= 0; k -= 8)
            {
                for (int j = 1; j < 9; j += 2)
                {
                    uint aVal = (uint)(x[j] >> k);
                    uint u = aVal & MASK;
                    uint v = (aVal >> 4) & MASK;
                    AddBothTo(T0, (int)(9 * u), T1, (int)(9 * v), zz, j - 1);
                }
                Nat.ShiftUpBits64(16, zz, 0, 8, 0L);
            }

            for (int k = 56; k >= 0; k -= 8)
            {
                for (int j = 0; j < 9; j += 2)
                {
                    uint aVal = (uint)(x[j] >> k);
                    uint u = aVal & MASK;
                    uint v = (aVal >> 4) & MASK;
                    AddBothTo(T0, (int)(9 * u), T1, (int)(9 * v), zz, j);
                }
                if (k > 0)
                {
                    Nat.ShiftUpBits64(18, zz, 0, 8, 0L);
                }
            }
        }

        protected static void ImplMulwAcc(ulong[] xs, ulong y, ulong[] z, int zOff)
        {
            ulong[] u = new ulong[32];
    //      u[0] = 0;
            u[1] = y;
            for (int i = 2; i < 32; i += 2)
            {
                u[i    ] = u[i >> 1] << 1;
                u[i + 1] = u[i     ] ^  y;
            }

            ulong l = 0;
            for (int i = 0; i < 9; ++i)
            {
                ulong x = xs[i];

                uint j = (uint)x;

                l ^= u[j & 31];

                ulong g, h = 0;
                int k = 60;
                do
                {
                    j  = (uint)(x >> k);
                    g  = u[j & 31];
                    l ^= (g <<  k);
                    h ^= (g >> -k);
                }
                while ((k -= 5) > 0);

                for (int p = 0; p < 4; ++p)
                {
                    x = (x & RM) >> 1;
                    h ^= x & (ulong)(((long)y << p) >> 63);
                }

                z[zOff + i] ^= l;

                l = h;
            }
            z[zOff + 9] ^= l;
        }

        protected static void ImplSquare(ulong[] x, ulong[] zz)
        {
            for (int i = 0; i < 9; ++i)
            {
                Interleave.Expand64To128(x[i], zz, i << 1);
            }
        }
    }
}
