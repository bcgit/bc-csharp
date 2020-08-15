using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP224K1Field
    {
        // 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF };
        private static readonly uint[] PExt = new uint[]{ 0x02C23069, 0x00003526, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0xFFFFCADA, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
        };
        private static readonly uint[] PExtInv = new uint[]{ 0xFD3DCF97, 0xFFFFCAD9, 0xFFFFFFFE, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00003525, 0x00000002 };
        private const uint P6 = 0xFFFFFFFF;
        private const uint PExt13 = 0xFFFFFFFF;
        private const uint PInv33 = 0x1A93;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat224.Add(x, y, z);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat.Add33To(7, PInv33, z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat.Add(14, xx, yy, zz);
            if (c != 0 || (zz[13] == PExt13 && Nat.Gte(14, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(14, zz, PExtInv.Length);
                }
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            uint c = Nat.Inc(7, x, z);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat.Add33To(7, PInv33, z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat224.FromBigInteger(x);
            if (z[6] == P6 && Nat224.Gte(z, P))
            {
                Nat224.SubFrom(P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.ShiftDownBit(7, x, 0, z);
            }
            else
            {
                uint c = Nat224.Add(x, P, z);
                Nat.ShiftDownBit(7, z, c);
            }
        }

        public static void Inv(uint[] x, uint[] z)
        {
            /*
             * Raise this element to the exponent 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 5
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 191 1s } { 1 0s } { 19 1s } "0010101101011"
             *
             * Therefore we need an addition chain containing 1, 2, 19, 191 (the lengths of the repunits)
             * We use: [1], [2], 4, 5, 9, 10, [19], 38, 76, 152, 190 [191]
             */

            if (0 != IsZero(x))
                throw new ArgumentException("cannot be 0", "x");

            uint[] x1 = x;
            uint[] x2 = Nat224.Create();
            Square(x1, x2);
            Multiply(x2, x1, x2);
            uint[] x4 = Nat224.Create();
            SquareN(x2, 2, x4);
            Multiply(x4, x2, x4);
            uint[] x5 = Nat224.Create();
            Square(x4, x5);
            Multiply(x5, x1, x5);
            uint[] x9 = x5;
            SquareN(x5, 4, x9);
            Multiply(x9, x4, x9);
            uint[] x10 = x4;
            Square(x9, x10);
            Multiply(x10, x1, x10);
            uint[] x19 = x10;
            SquareN(x10, 9, x19);
            Multiply(x19, x9, x19);
            uint[] x38 = x9;
            SquareN(x19, 19, x38);
            Multiply(x38, x19, x38);
            uint[] x76 = Nat224.Create();
            SquareN(x38, 38, x76);
            Multiply(x76, x38, x76);
            uint[] x152 = Nat224.Create();
            SquareN(x76, 76, x152);
            Multiply(x152, x76, x152);
            uint[] x190 = x76;
            SquareN(x152, 38, x190);
            Multiply(x190, x38, x190);
            uint[] x191 = x38;
            Square(x190, x191);
            Multiply(x191, x1, x191);

            uint[] t = x191;
            SquareN(t, 20, t);
            Multiply(t, x19, t);
            SquareN(t, 3, t);
            Multiply(t, x1, t);
            SquareN(t, 2, t);
            Multiply(t, x1, t);
            SquareN(t, 3, t);
            Multiply(t, x2, t);
            SquareN(t, 2, t);
            Multiply(t, x1, t);
            SquareN(t, 3, t);
            Multiply(t, x2, z);
        }

        public static int IsZero(uint[] x)
        {
            uint d = 0;
            for (int i = 0; i < 7; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return ((int)d - 1) >> 31;
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat224.CreateExt();
            Nat224.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void MultiplyAddToExt(uint[] x, uint[] y, uint[] zz)
        {
            uint c = Nat224.MulAddTo(x, y, zz);
            if (c != 0 || (zz[13] == PExt13 && Nat.Gte(14, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(14, zz, PExtInv.Length);
                }
            }
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (0 != IsZero(x))
            {
                Nat224.Sub(P, P, z);
            }
            else
            {
                Nat224.Sub(P, x, z);
            }
        }

        public static void Random(SecureRandom r, uint[] z)
        {
            byte[] bb = new byte[7 * 4];
            do
            {
                r.NextBytes(bb);
                Pack.LE_To_UInt32(bb, 0, z, 0, 7);
            }
            while (0 == Nat.LessThan(7, z, P));
        }

        public static void RandomMult(SecureRandom r, uint[] z)
        {
            do
            {
                Random(r, z);
            }
            while (0 != IsZero(z));
        }

        public static void Reduce(uint[] xx, uint[] z)
        {
            ulong cc = Nat224.Mul33Add(PInv33, xx, 7, xx, 0, z, 0);
            uint c = Nat224.Mul33DWordAdd(PInv33, cc, z, 0);

            Debug.Assert(c == 0 || c == 1);

            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat.Add33To(7, PInv33, z);
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            if ((x != 0 && Nat224.Mul33WordAdd(PInv33, x, z, 0) != 0)
                || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat.Add33To(7, PInv33, z);
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
                Nat.Sub33From(7, PInv33, z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.Sub(14, xx, yy, zz);
            if (c != 0)
            {
                if (Nat.SubFrom(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.DecAt(14, zz, PExtInv.Length);
                }
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat.ShiftUpBit(7, x, 0, z);
            if (c != 0 || (z[6] == P6 && Nat224.Gte(z, P)))
            {
                Nat.Add33To(7, PInv33, z);
            }
        }
    }
}
