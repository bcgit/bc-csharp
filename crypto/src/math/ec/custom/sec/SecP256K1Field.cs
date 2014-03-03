using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP256K1Field
    {
        // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF };
        internal static readonly uint[] PExt = new uint[]{ 0x000E90A1, 0x000007A2, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF };
        private const uint P7 = 0xFFFFFFFF;
        private const uint PExt15 = 0xFFFFFFFF;
        private const ulong PInv = 0x00000001000003D1UL;
        private const uint PInv33 = 0x3D1;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat256.Add(x, y, z);
            if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.AddDWord(PInv, z, 0);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat256.AddExt(xx, yy, zz);
            if (c != 0 || (zz[15] == PExt15 && Nat256.GteExt(zz, PExt)))
            {
                Nat256.SubExt(zz, PExt, zz);
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            Nat256.Copy(x, z);
            uint c = Nat256.Inc(z, 0);
            if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.AddDWord(PInv, z, 0);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat256.FromBigInteger(x);
            if (z[7] == P7 && Nat256.Gte(z, P))
            {
                Nat256.AddDWord(PInv, z, 0);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat256.ShiftDownBit(x, 0, z);
            }
            else
            {
                uint c = Nat256.Add(x, P, z);
                Nat256.ShiftDownBit(z, c, z);
            }
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat256.CreateExt();
            Nat256.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (Nat256.IsZero(x))
            {
                Nat256.Zero(z);
            }
            else
            {
                Nat256.Sub(P, x, z);
            }
        }

        public static void Reduce(uint[] xx, uint[] z)
        {
            ulong cc = Nat256.Mul33Add(PInv33, xx, 8, xx, 0, z, 0);
            uint c = Nat256.Mul33DWordAdd(PInv33, cc, z, 0);

            Debug.Assert(c == 0 || c == 1);

            if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.AddDWord(PInv, z, 0);
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            if ((x != 0 && Nat256.Mul33WordAdd(PInv33, x, z, 0) != 0)
                || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.AddDWord(PInv, z, 0);
            }
        }

        public static void Square(uint[] x, uint[] z)
        {
            uint[] tt = Nat256.CreateExt();
            Nat256.Square(x, tt);
            Reduce(tt, z);
        }

        public static void SquareN(uint[] x, int n, uint[] z)
        {
            Debug.Assert(n > 0);

            uint[] tt = Nat256.CreateExt();
            Nat256.Square(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                Nat256.Square(z, tt);
                Reduce(tt, z);
            }
        }

        public static void Subtract(uint[] x, uint[] y, uint[] z)
        {
            int c = Nat256.Sub(x, y, z);
            if (c != 0)
            {
                Nat256.SubDWord(PInv, z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat256.SubExt(xx, yy, zz);
            if (c != 0)
            {
                Nat256.AddExt(zz, PExt, zz);
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat256.ShiftUpBit(x, 0, z);
            if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.AddDWord(PInv, z, 0);
            }
        }
    }
}
