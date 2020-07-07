using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP384R1Field
    {
        // 2^384 - 2^128 - 2^96 + 2^32 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE,
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private static readonly uint[] PExt = new uint[]{ 0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000,
            0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0x00000001,
            0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF };
        private static readonly uint[] PExtInv = new uint[]{ 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD,
            0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001,
            0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000002 };
        private const uint P11 = 0xFFFFFFFF;
        private const uint PExt23 = 0xFFFFFFFF;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat.Add(12, x, y, z);
            if (c != 0 || (z[11] == P11 && Nat.Gte(12, z, P)))
            {
                AddPInvTo(z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat.Add(24, xx, yy, zz);
            if (c != 0 || (zz[23] == PExt23 && Nat.Gte(24, zz, PExt)))
            {
                if (Nat.AddTo(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.IncAt(24, zz, PExtInv.Length);
                }
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            uint c = Nat.Inc(12, x, z);
            if (c != 0 || (z[11] == P11 && Nat.Gte(12, z, P)))
            {
                AddPInvTo(z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat.FromBigInteger(384, x);
            if (z[11] == P11 && Nat.Gte(12, z, P))
            {
                Nat.SubFrom(12, P, z);
            }
            return z;
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.ShiftDownBit(12, x, 0, z);
            }
            else
            {
                uint c = Nat.Add(12, x, P, z);
                Nat.ShiftDownBit(12, z, c);
            }
        }

        public static void Inv(uint[] x, uint[] z)
        {
            /*
             * Raise this element to the exponent 2^384 - 2^128 - 2^96 + 2^32 - 3
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 255 1s } { 1 0s } { 32 1s } { 64 0s } { 30 1s } { 1 0s } { 1 1s }
             *
             * Therefore we need an addition chain containing 1, 30, 32, 255 (the lengths of the repunits)
             * We use: [1], 2, 3, 6, 12, 24, [30], [32], 62, 124, 248, 254, [255]
             */

            if (0 != IsZero(x))
                throw new ArgumentException("cannot be 0", "x");

            uint[] x1 = x;
            uint[] x2 = Nat.Create(12);
            Square(x1, x2);
            Multiply(x2, x1, x2);
            uint[] x3 = Nat.Create(12);
            Square(x2, x3);
            Multiply(x3, x1, x3);
            uint[] x6 = Nat.Create(12);
            SquareN(x3, 3, x6);
            Multiply(x6, x3, x6);
            uint[] x12 = x3;
            SquareN(x6, 6, x12);
            Multiply(x12, x6, x12);
            uint[] x24 = Nat.Create(12);
            SquareN(x12, 12, x24);
            Multiply(x24, x12, x24);
            uint[] x30 = x12;
            SquareN(x24, 6, x30);
            Multiply(x30, x6, x30);
            uint[] x32 = x24;
            SquareN(x30, 2, x32);
            Multiply(x32, x2, x32);
            uint[] x62 = x2;
            SquareN(x32, 30, x62);
            Multiply(x62, x30, x62);
            uint[] x124 = Nat.Create(12);
            SquareN(x62, 62, x124);
            Multiply(x124, x62, x124);
            uint[] x248 = x62;
            SquareN(x124, 124, x248);
            Multiply(x248, x124, x248);
            uint[] x254 = x124;
            SquareN(x248, 6, x254);
            Multiply(x254, x6, x254);
            uint[] x255 = x6;
            Square(x254, x255);
            Multiply(x255, x1, x255);

            uint[] t = x255;
            SquareN(t, 33, t);
            Multiply(t, x32, t);
            SquareN(t, 94, t);
            Multiply(t, x30, t);
            SquareN(t, 2, t);

            // NOTE that x1 and z could be the same array
            Multiply(x1, t, z);
        }

        public static int IsZero(uint[] x)
        {
            uint d = 0;
            for (int i = 0; i < 12; ++i)
            {
                d |= x[i];
            }
            d = (d >> 1) | (d & 1);
            return ((int)d - 1) >> 31;
        }

        public static void Multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat.Create(24);
            Nat384.Mul(x, y, tt);
            Reduce(tt, z);
        }

        public static void Negate(uint[] x, uint[] z)
        {
            if (0 != IsZero(x))
            {
                Nat.Sub(12, P, P, z);
            }
            else
            {
                Nat.Sub(12, P, x, z);
            }
        }

        public static void Random(SecureRandom r, uint[] z)
        {
            byte[] bb = new byte[12 * 4];
            do
            {
                r.NextBytes(bb);
                Pack.LE_To_UInt32(bb, 0, z, 0, 12);
            }
            while (0 == Nat.LessThan(12, z, P));
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
            long xx16 = xx[16], xx17 = xx[17], xx18 = xx[18], xx19 = xx[19];
            long xx20 = xx[20], xx21 = xx[21], xx22 = xx[22], xx23 = xx[23];

            const long n = 1;

            long t0 = (long)xx[12] + xx20 - n;
            long t1 = (long)xx[13] + xx22;
            long t2 = (long)xx[14] + xx22 + xx23;
            long t3 = (long)xx[15] + xx23;
            long t4 = xx17 + xx21;
            long t5 = xx21 - xx23;
            long t6 = xx22 - xx23;
            long t7 = t0 + t5;

            long cc = 0;
            cc += (long)xx[0] + t7;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[1] + xx23 - t0 + t1;
            z[1] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[2] - xx21 - t1 + t2;
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[3] - t2 + t3 + t7;
            z[3] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[4] + xx16 + xx21 + t1 - t3 + t7;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[5] - xx16 + t1 + t2 + t4;
            z[5] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[6] + xx18 - xx17 + t2 + t3;
            z[6] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[7] + xx16 + xx19 - xx18 + t3;
            z[7] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[8] + xx16 + xx17 + xx20 - xx19;
            z[8] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[9] + xx18 - xx20 + t4;
            z[9] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[10] + xx18 + xx19 - t5 + t6;
            z[10] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[11] + xx19 + xx20 - t6;
            z[11] = (uint)cc;
            cc >>= 32;
            cc += n;

            Debug.Assert(cc >= 0);

            Reduce32((uint)cc, z);
        }

        public static void Reduce32(uint x, uint[] z)
        {
            long cc = 0;

            if (x != 0)
            {
                long xx12 = x;

                cc += (long)z[0] + xx12;
                z[0] = (uint)cc;
                cc >>= 32;
                cc += (long)z[1] - xx12;
                z[1] = (uint)cc;
                cc >>= 32;
                if (cc != 0)
                {
                    cc += (long)z[2];
                    z[2] = (uint)cc;
                    cc >>= 32;
                }
                cc += (long)z[3] + xx12;
                z[3] = (uint)cc;
                cc >>= 32;
                cc += (long)z[4] + xx12;
                z[4] = (uint)cc;
                cc >>= 32;

                Debug.Assert(cc == 0 || cc == 1);
            }

            if ((cc != 0 && Nat.IncAt(12, z, 5) != 0)
                || (z[11] == P11 && Nat.Gte(12, z, P)))
            {
                AddPInvTo(z);
            }
        }

        public static void Square(uint[] x, uint[] z)
        {
            uint[] tt = Nat.Create(24);
            Nat384.Square(x, tt);
            Reduce(tt, z);
        }

        public static void SquareN(uint[] x, int n, uint[] z)
        {
            Debug.Assert(n > 0);

            uint[] tt = Nat.Create(24);
            Nat384.Square(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                Nat384.Square(z, tt);
                Reduce(tt, z);
            }
        }

        public static void Subtract(uint[] x, uint[] y, uint[] z)
        {
            int c = Nat.Sub(12, x, y, z);
            if (c != 0)
            {
                SubPInvFrom(z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.Sub(24, xx, yy, zz);
            if (c != 0)
            {
                if (Nat.SubFrom(PExtInv.Length, PExtInv, zz) != 0)
                {
                    Nat.DecAt(24, zz, PExtInv.Length);
                }
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat.ShiftUpBit(12, x, 0, z);
            if (c != 0 || (z[11] == P11 && Nat.Gte(12, z, P)))
            {
                AddPInvTo(z);
            }
        }

        private static void AddPInvTo(uint[] z)
        {
            long c = (long)z[0] + 1;
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - 1;
            z[1] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c += (long)z[2];
                z[2] = (uint)c;
                c >>= 32;
            }
            c += (long)z[3] + 1;
            z[3] = (uint)c;
            c >>= 32;
            c += (long)z[4] + 1;
            z[4] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                Nat.IncAt(12, z, 5);
            }
        }

        private static void SubPInvFrom(uint[] z)
        {
            long c = (long)z[0] - 1;
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] + 1;
            z[1] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c += (long)z[2];
                z[2] = (uint)c;
                c >>= 32;
            }
            c += (long)z[3] - 1;
            z[3] = (uint)c;
            c >>= 32;
            c += (long)z[4] - 1;
            z[4] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                Nat.DecAt(12, z, 5);
            }
        }
    }
}
