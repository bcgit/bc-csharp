using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP192K1Field
    {
        // 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private const uint P5 = 0xFFFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x013C4FD1, 0x00002392, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0xFFFFDC6E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private const uint PExt11 = 0xFFFFFFFF;
        private const ulong PInv = 0x00000001000011C9L;
        private const uint PInv33 = 0x11C9;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat192.Add(x, y, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat192.AddDWord(PInv, z, 0);
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
                Nat192.AddDWord(PInv, z, 0);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat192.FromBigInteger(x);
            if (z[5] == P5 && Nat192.Gte(z, P))
            {
                Nat192.AddDWord(PInv, z, 0);
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

        public static void Reduce(uint[] tt, uint[] z)
        {
            ulong c = Nat192.Mul33AddExt(PInv33, tt, 6, tt, 0);
            c = Nat192.Mul33DWordAdd(PInv33, c, tt, 0);

            Debug.Assert(c == 0 || c == 1);

            if (c != 0 || (tt[5] == P5 && Nat192.Gte(tt, P)))
            {
                Nat192.AddDWord(PInv, tt, 0);
            }

            Array.Copy(tt, 0, z, 0, 6);
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
                Nat192.SubDWord(PInv, z);
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
                Nat192.AddDWord(PInv, z, 0);
            }
        }
    }
}
