using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP160R2Field
    {
        // 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private static readonly uint[] PExt = new uint[]{ 0x1B44BBA9, 0x0000A71A, 0x00000001, 0x00000000, 0x00000000,
            0xFFFF58E6, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private static readonly uint[] PExtInv = new uint[]{ 0xE4BB4457, 0xFFFF58E5, 0xFFFFFFFE, 0xFFFFFFFF,
            0xFFFFFFFF, 0x0000A719, 0x00000002 };
        private const uint P4 = 0xFFFFFFFF;
        private const uint PExt9 = 0xFFFFFFFF;
        private const uint PInv33 = 0x538D;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat160.Add(x, y, z);
            if (c != 0 || (z[4] == P4 && Nat160.Gte(z, P)))
            {
                Nat.Add33To(5, PInv33, z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat.Add(10, xx, yy, zz);
            if (c != 0 || (zz[9] == PExt9 && Nat.Gte(10, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(10, zz, PExtInv.Length);
                }
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            uint c = Nat.Inc(5, x, z);
            if (c != 0 || (z[4] == P4 && Nat160.Gte(z, P)))
            {
                Nat.Add33To(5, PInv33, z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat160.FromBigInteger(x);
            if (z[4] == P4 && Nat160.Gte(z, P))
            {
                Nat160.SubFrom(P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.ShiftDownBit(5, x, 0, z);
            }
            else
            {
                uint c = Nat160.Add(x, P, z);
                Nat.ShiftDownBit(5, z, c);
            }
        }

        public static void Inv(uint[] x, uint[] z)
        {
            /*
             * Raise this element to the exponent 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 3
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 127 1s } { 1 0s } { 17 1s } "010110001110001"
             *
             * Therefore we need an addition chain containing 1, 2, 3, 17, 127 (the lengths of the repunits)
             * We use: 1, 2, 3, 6, 12, 15, [17], 34, 68, 102, 119, 125, [127]
             */

            if (0 != IsZero(x))
                throw new ArgumentException("cannot be 0", "x");

            uint[] x1 = x;
            uint[] x2 = Nat160.Create();
            Square(x1, x2);
            Multiply(x2, x1, x2);
            uint[] x3 = Nat160.Create();
            Square(x2, x3);
            Multiply(x3, x1, x3);
            uint[] x6 = Nat160.Create();
            SquareN(x3, 3, x6);
            Multiply(x6, x3, x6);
            uint[] x12 = Nat160.Create();
            SquareN(x6, 6, x12);
            Multiply(x12, x6, x12);
            uint[] x15 = x12;
            SquareN(x12, 3, x15);
            Multiply(x15, x3, x15);
            uint[] x17 = x15;
            SquareN(x15, 2, x17);
            Multiply(x17, x2, x17);
            uint[] x34 = Nat160.Create();
            SquareN(x17, 17, x34);
            Multiply(x34, x17, x34);
            uint[] x68 = Nat160.Create();
            SquareN(x34, 34, x68);
            Multiply(x68, x34, x68);
            uint[] x102 = x68;
            SquareN(x68, 34, x102);
            Multiply(x102, x34, x102);
            uint[] x119 = x34;
            SquareN(x102, 17, x119);
            Multiply(x119, x17, x119);
            uint[] x125 = x102;
            SquareN(x119, 6, x125);
            Multiply(x125, x6, x125);
            uint[] x127 = x6;
            SquareN(x125, 2, x127);
            Multiply(x127, x2, x127);

            uint[] t = x127;
            SquareN(t, 18, t);
            Multiply(t, x17, t);
            SquareN(t, 2, t);
            Multiply(t, x1, t);
            SquareN(t, 3, t);
            Multiply(t, x2, t);
            SquareN(t, 6, t);
            Multiply(t, x3, t);
            SquareN(t, 4, t);

            // NOTE that x1 and z could be the same array
            Multiply(x1, t, z);
        }

        public static int IsZero(uint[] x)
        {
            uint d = 0;
            for (int i = 0; i < 5; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return ((int)d - 1) >> 31;
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat160.CreateExt();
            Nat160.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void MultiplyAddToExt(uint[] x, uint[] y, uint[] zz)
        {
            uint c = Nat160.MulAddTo(x, y, zz);
            if (c != 0 || (zz[9] == PExt9 && Nat.Gte(10, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(10, zz, PExtInv.Length);
                }
            }
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (0 != IsZero(x))
            {
                Nat160.Sub(P, P, z);
            }
            else
            {
                Nat160.Sub(P, x, z);
            }
        }

        public static void Random(SecureRandom r, uint[] z)
        {
            byte[] bb = new byte[5 * 4];
            do
            {
                r.NextBytes(bb);
                Pack.LE_To_UInt32(bb, 0, z, 0, 5);
            }
            while (0 == Nat.LessThan(5, z, P));
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
            ulong cc = Nat160.Mul33Add(PInv33, xx, 5, xx, 0, z, 0);
            uint c = Nat160.Mul33DWordAdd(PInv33, cc, z, 0);

            Debug.Assert(c == 0 || c == 1);

            if (c != 0 || (z[4] == P4 && Nat160.Gte(z, P)))
            {
                Nat.Add33To(5, PInv33, z);
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            if ((x != 0 && Nat160.Mul33WordAdd(PInv33, x, z, 0) != 0)
                || (z[4] == P4 && Nat160.Gte(z, P)))
            {
                Nat.Add33To(5, PInv33, z);
            }
        }

        public static void Square(uint[] x, uint[] z)
        {
            uint[] tt = Nat160.CreateExt();
            Nat160.Square(x, tt);
            Reduce(tt, z);
        }

        public static void SquareN(uint[] x, int n, uint[] z)
        {
            Debug.Assert(n > 0);

            uint[] tt = Nat160.CreateExt();
            Nat160.Square(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                Nat160.Square(z, tt);
                Reduce(tt, z);
            }
        }

        public static void Subtract(uint[] x, uint[] y, uint[] z)
        {
            int c = Nat160.Sub(x, y, z);
            if (c != 0)
            {
                Nat.Sub33From(5, PInv33, z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.Sub(10, xx, yy, zz);
            if (c != 0)
            {
                if (Nat.SubFrom(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.DecAt(10, zz, PExtInv.Length);
                }
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat.ShiftUpBit(5, x, 0, z);
            if (c != 0 || (z[4] == P4 && Nat160.Gte(z, P)))
            {
                Nat.Add33To(5, PInv33, z);
            }
        }
    }
}
