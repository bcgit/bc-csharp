using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP192K1Field
    {
        // 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF };
        private static readonly uint[] PExt = new uint[]{ 0x013C4FD1, 0x00002392, 0x00000001, 0x00000000, 0x00000000,
            0x00000000, 0xFFFFDC6E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private static readonly uint[] PExtInv = new uint[]{ 0xFEC3B02F, 0xFFFFDC6D, 0xFFFFFFFE, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0x00002391, 0x00000002 };
        private const uint P5 = 0xFFFFFFFF;
        private const uint PExt11 = 0xFFFFFFFF;
        private const uint PInv33 = 0x11C9;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat192.Add(x, y, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat.Add33To(6, PInv33, z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat.Add(12, xx, yy, zz);
            if (c != 0 || (zz[11] == PExt11 && Nat.Gte(12, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(12, zz, PExtInv.Length);
                }
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            uint c = Nat.Inc(6, x, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat.Add33To(6, PInv33, z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat192.FromBigInteger(x);
            if (z[5] == P5 && Nat192.Gte(z, P))
            {
                Nat192.SubFrom(P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.ShiftDownBit(6, x, 0, z);
            }
            else
            {
                uint c = Nat192.Add(x, P, z);
                Nat.ShiftDownBit(6, z, c);
            }
        }

        public static void Inv(uint[] x, uint[] z)
        {
            /*
             * Raise this element to the exponent 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 3
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 159 1s } { 1 0s } { 19 1s } { 1 0s } { 3 1s } "000110101"
             *
             * Therefore we need an addition chain containing 1, 2, 3, 19, 159 (the lengths of the repunits)
             * We use: [1], [2], [3], 6, 12, 18, [19], 38, 76, 152, 158, [159]
             */

            if (0 != IsZero(x))
                throw new ArgumentException("cannot be 0", "x");

            uint[] x1 = x;
            uint[] x2 = Nat192.Create();
            Square(x1, x2);
            Multiply(x2, x1, x2);
            uint[] x3 = Nat192.Create();
            Square(x2, x3);
            Multiply(x3, x1, x3);
            uint[] x6 = Nat192.Create();
            SquareN(x3, 3, x6);
            Multiply(x6, x3, x6);
            uint[] x12 = Nat192.Create();
            SquareN(x6, 6, x12);
            Multiply(x12, x6, x12);
            uint[] x18 = x12;
            SquareN(x12, 6, x18);
            Multiply(x18, x6, x18);
            uint[] x19 = x18;
            Square(x18, x19);
            Multiply(x19, x1, x19);
            uint[] x38 = Nat192.Create();
            SquareN(x19, 19, x38);
            Multiply(x38, x19, x38);
            uint[] x76 = Nat192.Create();
            SquareN(x38, 38, x76);
            Multiply(x76, x38, x76);
            uint[] x152 = x38;
            SquareN(x76, 76, x152);
            Multiply(x152, x76, x152);
            uint[] x158 = x76;
            SquareN(x152, 6, x158);
            Multiply(x158, x6, x158);
            uint[] x159 = x6;
            Square(x158, x159);
            Multiply(x159, x1, x159);

            uint[] t = x159;
            SquareN(t, 20, t);
            Multiply(t, x19, t);
            SquareN(t, 4, t);
            Multiply(t, x3, t);
            SquareN(t, 5, t);
            Multiply(t, x2, t);
            SquareN(t, 2, t);
            Multiply(t, x1, t);
            SquareN(t, 2, t);

            // NOTE that x1 and z could be the same array
            Multiply(x1, t, z);
        }

        public static int IsZero(uint[] x)
        {
            uint d = 0;
            for (int i = 0; i < 6; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return ((int)d - 1) >> 31;
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat192.CreateExt();
            Nat192.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void MultiplyAddToExt(uint[] x, uint[] y, uint[] zz)
        {
            uint c = Nat192.MulAddTo(x, y, zz);
            if (c != 0 || (zz[11] == PExt11 && Nat.Gte(12, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(12, zz, PExtInv.Length);
                }
            }
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (0 != IsZero(x))
            {
                Nat192.Sub(P, P, z);
            }
            else
            {
                Nat192.Sub(P, x, z);
            }
        }

        public static void Random(SecureRandom r, uint[] z)
        {
            byte[] bb = new byte[6 * 4];
            do
            {
                r.NextBytes(bb);
                Pack.LE_To_UInt32(bb, 0, z, 0, 6);
            }
            while (0 == Nat.LessThan(6, z, P));
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
            ulong cc = Nat192.Mul33Add(PInv33, xx, 6, xx, 0, z, 0);
            uint c = Nat192.Mul33DWordAdd(PInv33, cc, z, 0);

            Debug.Assert(c == 0 || c == 1);

            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat.Add33To(6, PInv33, z);
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            if ((x != 0 && Nat192.Mul33WordAdd(PInv33, x, z, 0) != 0)
                || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat.Add33To(6, PInv33, z);
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
                Nat.Sub33From(6, PInv33, z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.Sub(12, xx, yy, zz);
            if (c != 0)
            {
                if (Nat.SubFrom(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.DecAt(12, zz, PExtInv.Length);
                }
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat.ShiftUpBit(6, x, 0, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                Nat.Add33To(6, PInv33, z);
            }
        }
    }
}
