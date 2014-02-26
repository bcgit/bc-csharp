using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP192R1Field
    {
        // 2^192 - 2^64 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private const uint P5 = 0xFFFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001,
            0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private const uint PExt11 = 0xFFFFFFFF;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat192.Add(x, y, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat192.Sub(z, P, z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat192.AddExt(xx, yy, zz);
            if (c != 0 || (zz[11] == PExt11 && Nat192.GteExt(zz, PExt)))
            {
                Nat192.SubExt(zz, PExt, zz);
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            Array.Copy(x, 0, z, 0, 6);
            uint c = Nat192.Inc(z, 0);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat192.Sub(z, P, z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat192.FromBigInteger(x);
            if (z[5] == P5 && Nat192.Gte(z, P))
            {
                Nat192.Sub(z, P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat192.ShiftDownBit(x, 0, z);
            }
            else
            {
                uint c = Nat192.Add(x, P, z);
                Nat192.ShiftDownBit(z, c, z);
            }
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat192.CreateExt();
            Nat192.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (Nat192.IsZero(x))
            {
                Nat192.Zero(z);
            }
            else
            {
                Nat192.Sub(P, x, z);
            }
        }

        public static void Reduce(uint[] xx, uint[] z)
        {
            long xx06 = xx[6], xx07 = xx[7], xx08 = xx[8];
            long xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];

            long t0 = xx06 + xx10;
            long t1 = xx07 + xx11;

            long cc = 0;
            cc += (long)xx[0] + t0;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[1] + t1;
            z[1] = (uint)cc;
            cc >>= 32;

            t0 += xx08;
            t1 += xx09;

            cc += (long)xx[2] + t0;
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[3] + t1;
            z[3] = (uint)cc;
            cc >>= 32;

            t0 -= xx06;
            t1 -= xx07;

            cc += (long)xx[4] + t0;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[5] + t1;
            z[5] = (uint)cc;
            cc >>= 32;

            int c = (int)cc;
            Debug.Assert(c >= 0);
            while (c > 0)
            {
                c += Nat192.Sub(z, P, z);
            }

            if (z[5] == P5 && Nat192.Gte(z, P))
            {
                Nat192.Sub(z, P, z);
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            uint c = Nat192.AddWord(x, z, 0) + Nat192.AddWord(x, z, 2);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat192.Sub(z, P, z);
            }
        }

        public static void Square(uint[] x, uint[] z)
        {
            uint[] tt = Nat192.CreateExt();
            Nat192.Square(x, tt);
            Reduce(tt, z);
        }

        public static void SquareN(uint[] x, int n, uint[] z)
        {
            Debug.Assert(n > 0);

            uint[] tt = Nat192.CreateExt();
            Nat192.Square(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                Nat192.Square(z, tt);
                Reduce(tt, z);
            }
        }

        public static void Subtract(uint[] x, uint[] y, uint[] z)
        {
            int c = Nat192.Sub(x, y, z);
            if (c != 0)
            {
                Nat192.Add(z, P, z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat192.SubExt(xx, yy, zz);
            if (c != 0)
            {
                Nat192.AddExt(zz, PExt, zz);
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat192.ShiftUpBit(x, 0, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat192.Sub(z, P, z);
            }
        }
    }
}
