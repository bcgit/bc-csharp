using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP224K1Field
    {
        // 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF };
        private const uint P6 = 0xFFFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x02C23069, 0x00003526, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0xFFFFCADA, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private const uint PExt13 = 0xFFFFFFFF;
        private const ulong PInv = 0x0000000100001A93L; 
        private const uint PInv33 = 0x1A93;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat224.Add(x, y, z);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.AddDWord(PInv, z, 0);
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
            Array.Copy(x, 0, z, 0, 8);
            uint c = Nat224.Inc(z, 0);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.AddDWord(PInv, z, 0);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat224.FromBigInteger(x);
            if (z[6] == P6 && Nat224.Gte(z, P))
            {
                Nat224.AddDWord(PInv, z, 0);
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
            ulong c = Nat224.Mul33Add(PInv33, xx, 7, xx, 0, z, 0);
            c = Nat224.Mul33DWordAdd(PInv33, c, z, 0);

            Debug.Assert(c == 0 || c == 1);

            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat224.AddDWord(PInv, z, 0);
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
                Nat224.SubDWord(PInv, z);
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
                Nat224.AddDWord(PInv, z, 0);
            }
        }
    }
}
