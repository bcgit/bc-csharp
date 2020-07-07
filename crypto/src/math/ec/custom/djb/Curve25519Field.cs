using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.Djb
{
    internal class Curve25519Field
    {
        // 2^255 - 19
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF };
        private const uint P7 = 0x7FFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x00000169, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0x3FFFFFFF };
        private const uint PInv = 0x13;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            Nat256.Add(x, y, z);
            if (Nat256.Gte(z, P))
            {
                SubPFrom(z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            Nat.Add(16, xx, yy, zz);
            if (Nat.Gte(16, zz, PExt))
            {
                SubPExtFrom(zz);
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            Nat.Inc(8, x, z);
            if (Nat256.Gte(z, P))
            {
                SubPFrom(z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat256.FromBigInteger(x);
            while (Nat256.Gte(z, P))
            {
                Nat256.SubFrom(P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.ShiftDownBit(8, x, 0, z);
            }
            else
            {
                Nat256.Add(x, P, z);
                Nat.ShiftDownBit(8, z, 0);
            }
        }

        public static void Inv(uint[] x, uint[] z)
        {
            /*
             * Raise this element to the exponent 2^255 - 21
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 250 1s } { 1 0s } { 1 1s } { 1 0s } { 2 1s }
             *
             * Therefore we need an addition chain containing 1, 2, 250 (the lengths of the repunits)
             * We use: [1], [2], 3, 5, 10, 15, 25, 50, 75, 125, [250]
             */

            if (0 != IsZero(x))
                throw new ArgumentException("cannot be 0", "x");

            uint[] x1 = x;
            uint[] x2 = Nat256.Create();
            Square(x1, x2);
            Multiply(x2, x1, x2);
            uint[] x3 = Nat256.Create();
            Square(x2, x3);
            Multiply(x3, x1, x3);
            uint[] x5 = x3;
            SquareN(x3, 2, x5);
            Multiply(x5, x2, x5);
            uint[] x10 = Nat256.Create();
            SquareN(x5, 5, x10);
            Multiply(x10, x5, x10);
            uint[] x15 = Nat256.Create();
            SquareN(x10, 5, x15);
            Multiply(x15, x5, x15);
            uint[] x25 = x5;
            SquareN(x15, 10, x25);
            Multiply(x25, x10, x25);
            uint[] x50 = x10;
            SquareN(x25, 25, x50);
            Multiply(x50, x25, x50);
            uint[] x75 = x15;
            SquareN(x50, 25, x75);
            Multiply(x75, x25, x75);
            uint[] x125 = x25;
            SquareN(x75, 50, x125);
            Multiply(x125, x50, x125);
            uint[] x250 = x50;
            SquareN(x125, 125, x250);
            Multiply(x250, x125, x250);

            uint[] t = x250;
            SquareN(t, 2, t);
            Multiply(t, x1, t);
            SquareN(t, 3, t);
            Multiply(t, x2, z);
        }

        public static int IsZero(uint[] x)
        {
            uint d = 0;
            for (int i = 0; i < 8; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return ((int)d - 1) >> 31;
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat256.CreateExt();
            Nat256.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void MultiplyAddToExt(uint[] x, uint[] y, uint[] zz)
        {
            Nat256.MulAddTo(x, y, zz);
            if (Nat.Gte(16, zz, PExt))
            {
                SubPExtFrom(zz);
            }
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (0 != IsZero(x))
            {
                Nat256.Sub(P, P, z);
            }
            else
            {
                Nat256.Sub(P, x, z);
            }
        }

        public static void Random(SecureRandom r, uint[] z)
        {
            byte[] bb = new byte[8 * 4];
            do
            {
                r.NextBytes(bb);
                Pack.LE_To_UInt32(bb, 0, z, 0, 8);
                z[7] &= P7;
            }
            while (0 == Nat.LessThan(8, z, P));
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
            Debug.Assert(xx[15] >> 30 == 0);

            uint xx07 = xx[7];
            Nat.ShiftUpBit(8, xx, 8, xx07, z, 0);
            uint c = Nat256.MulByWordAddTo(PInv, xx, z) << 1;
            uint z7 = z[7];
            c += (z7 >> 31) - (xx07 >> 31);
            z7 &= P7;
            z7 += Nat.AddWordTo(7, c * PInv, z);
            z[7] = z7;
            if (z7 >= P7 && Nat256.Gte(z, P))
            {
                SubPFrom(z);
            }
        }

        public static void Reduce27(uint x, uint[] z)
        {
            Debug.Assert(x >> 26 == 0);

            uint z7 = z[7];
            uint c = (x << 1 | z7 >> 31);
            z7 &= P7;
            z7 += Nat.AddWordTo(7, c * PInv, z);
            z[7] = z7;
            if (z7 >= P7 && Nat256.Gte(z, P))
            {
                SubPFrom(z);
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
                AddPTo(z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.Sub(16, xx, yy, zz);
            if (c != 0)
            {
                AddPExtTo(zz);
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            Nat.ShiftUpBit(8, x, 0, z);
            if (Nat256.Gte(z, P))
            {
                SubPFrom(z);
            }
        }

        private static uint AddPTo(uint[] z)
        {
            long c = (long)z[0] - PInv;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.DecAt(7, z, 1);
            }
            c += (long)z[7] + (P7 + 1);
            z[7] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        private static uint AddPExtTo(uint[] zz)
        {
            long c = (long)zz[0] + PExt[0];
            zz[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.IncAt(8, zz, 1);
            }
            c += (long)zz[8] - PInv;
            zz[8] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.DecAt(15, zz, 9);
            }
            c += (long)zz[15] + (PExt[15] + 1);
            zz[15] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        private static int SubPFrom(uint[] z)
        {
            long c = (long)z[0] + PInv;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.IncAt(7, z, 1);
            }
            c += (long)z[7] - (P7 + 1);
            z[7] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        private static int SubPExtFrom(uint[] zz)
        {
            long c = (long)zz[0] - PExt[0];
            zz[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.DecAt(8, zz, 1);
            }
            c += (long)zz[8] + PInv;
            zz[8] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.IncAt(15, zz, 9);
            }
            c += (long)zz[15] - (PExt[15] + 1);
            zz[15] = (uint)c;
            c >>= 32;
            return (int)c;
        }
    }
}
