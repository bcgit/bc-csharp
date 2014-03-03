using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP224R1Field
    {
        // 2^224 - 2^96 + 1
        internal static readonly uint[] P = new uint[] { 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        internal static readonly uint[] PExt = new uint[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF,
            0xFFFFFFFF, 0x00000000, 0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private const uint P6 = 0xFFFFFFFF;
        private const uint PExt13 = 0xFFFFFFFF;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat224.Add(x, y, z);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.Sub(z, P, z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat224.AddExt(xx, yy, zz);
            if (c != 0 || (zz[13] == PExt13 && Nat224.GteExt(zz, PExt)))
            {
                Nat224.SubExt(zz, PExt, zz);
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            Nat224.Copy(x, z);
            uint c = Nat224.Inc(z, 0);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.Sub(z, P, z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat224.FromBigInteger(x);
            if (z[6] == P6 && Nat224.Gte(z, P))
            {
                Nat224.Sub(z, P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat224.ShiftDownBit(x, 0, z);
            }
            else
            {
                uint c = Nat224.Add(x, P, z);
                Nat224.ShiftDownBit(z, c, z);
            }
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat224.CreateExt();
            Nat224.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (Nat224.IsZero(x))
            {
                Nat224.Zero(z);
            }
            else
            {
                Nat224.Sub(P, x, z);
            }
        }

        public static void Reduce(uint[] xx, uint[] z)
        {
            long xx07 = xx[7], xx08 = xx[8], xx09 = xx[9], xx10 = xx[10];
            long xx11 = xx[11], xx12 = xx[12], xx13 = xx[13];

            long t0 = xx07 + xx11;
            long t1 = xx08 + xx12;
            long t2 = xx09 + xx13;

            long cc = 0;
            cc += (long)xx[0] - t0;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[1] - t1;
            z[1] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[2] - t2;
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[3] + t0 - xx10;
            z[3] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[4] + t1 - xx11;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[5] + t2 - xx12;
            z[5] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[6] + xx10 - xx13;
            z[6] = (uint)cc;
            cc >>= 32;

            int c = (int)cc;
            if (c >= 0)
            {
                Reduce32((uint)c, z);
            }
            else
            {
                while (c < 0)
                {
                    c += (int)Nat224.Add(z, P, z);
                }
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            if ((x != 0 && (Nat224.SubWord(x, z, 0) + Nat224.AddWord(x, z, 3) != 0))
                || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.Sub(z, P, z);
            }
        }

        public static void Square(uint[] x, uint[] z)
        {
            uint[] tt = Nat224.CreateExt();
            Nat224.Square(x, tt);
            Reduce(tt, z);
        }

        public static void SquareN(uint[] x, int n, uint[] z)
        {
            Debug.Assert(n > 0);

            uint[] tt = Nat224.CreateExt();
            Nat224.Square(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                Nat224.Square(z, tt);
                Reduce(tt, z);
            }
        }

        public static void Subtract(uint[] x, uint[] y, uint[] z)
        {
            int c = Nat224.Sub(x, y, z);
            if (c != 0)
            {
                Nat224.Add(z, P, z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat224.SubExt(xx, yy, zz);
            if (c != 0)
            {
                Nat224.AddExt(zz, PExt, zz);
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat224.ShiftUpBit(x, 0, z);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.Sub(z, P, z);
            }
        }
    }
}
