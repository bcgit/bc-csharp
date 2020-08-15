using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP192R1Field
    {
        // 2^192 - 2^64 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF };
        private static readonly uint[] PExt = new uint[]{ 0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001,
            0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        private static readonly uint[] PExtInv = new uint[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF,
            0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000002 };
        private const uint P5 = 0xFFFFFFFF;
        private const uint PExt11 = 0xFFFFFFFF;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat192.Add(x, y, z);
            if (c != 0 || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                AddPInvTo(z);
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
                AddPInvTo(z);
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
             * Raise this element to the exponent 2^192 - 2^64 - 1
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 127 1s } { 1 0s } { 62 1s } { 1 0s } { 1 1s }
             *
             * Therefore we need an addition chain containing 1, 62, 127 (the lengths of the repunits)
             * We use: [1], 2, 3, 6, 12, 24, 30, 32, [62], 65, [127]
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
            uint[] x24 = Nat192.Create();
            SquareN(x12, 12, x24);
            Multiply(x24, x12, x24);
            uint[] x30 = x12;
            SquareN(x24, 6, x30);
            Multiply(x30, x6, x30);
            uint[] x32 = x6;
            SquareN(x30, 2, x32);
            Multiply(x32, x2, x32);
            uint[] x62 = x2;
            SquareN(x32, 30, x62);
            Multiply(x62, x30, x62);
            uint[] x65 = x24;
            SquareN(x62, 3, x65);
            Multiply(x65, x3, x65);
            uint[] x127 = x3;
            SquareN(x65, 62, x127);
            Multiply(x127, x62, x127);

            uint[] t = x127;
            SquareN(t, 63, t);
            Multiply(t, x62, t);
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
            ulong xx06 = xx[6], xx07 = xx[7], xx08 = xx[8];
            ulong xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];

            ulong t0 = xx06 + xx10;
            ulong t1 = xx07 + xx11;

            ulong cc = 0;
            cc += (ulong)xx[0] + t0;
            uint z0 = (uint)cc;
            cc >>= 32;
            cc += (ulong)xx[1] + t1;
            z[1] = (uint)cc;
            cc >>= 32;

            t0 += xx08;
            t1 += xx09;

            cc += (ulong)xx[2] + t0;
            ulong z2 = (uint)cc;
            cc >>= 32;
            cc += (ulong)xx[3] + t1;
            z[3] = (uint)cc;
            cc >>= 32;

            t0 -= xx06;
            t1 -= xx07;

            cc += (ulong)xx[4] + t0;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (ulong)xx[5] + t1;
            z[5] = (uint)cc;
            cc >>= 32;

            z2 += cc;

            cc += z0;
            z[0] = (uint)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += z[1];
                z[1] = (uint)cc;
                z2 += cc >> 32;
            }
            z[2] = (uint)z2;
            cc  = z2 >> 32;

            Debug.Assert(cc == 0 || cc == 1);

            if ((cc != 0 && Nat.IncAt(6, z, 3) != 0)
                || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                AddPInvTo(z);
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            ulong cc = 0;

            if (x != 0)
            {
                cc += (ulong)z[0] + x;
                z[0] = (uint)cc;
                cc >>= 32;
                if (cc != 0)
                {
                    cc += (ulong)z[1];
                    z[1] = (uint)cc;
                    cc >>= 32;
                }
                cc += (ulong)z[2] + x;
                z[2] = (uint)cc;
                cc >>= 32;

                Debug.Assert(cc == 0 || cc == 1);
            }

            if ((cc != 0 && Nat.IncAt(6, z, 3) != 0)
                || (z[5] == P5 && Nat192.Gte(z, P)))
            {
                AddPInvTo(z);
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
                SubPInvFrom(z);
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
                AddPInvTo(z);
            }
        }

        private static void AddPInvTo(uint[] z)
        {
            long c = (long)z[0] + 1;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c += (long)z[1];
                z[1] = (uint)c;
                c >>= 32;
            }
            c += (long)z[2] + 1;
            z[2] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                Nat.IncAt(6, z, 3);
            }
        }

        private static void SubPInvFrom(uint[] z)
        {
            long c = (long)z[0] - 1;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c += (long)z[1];
                z[1] = (uint)c;
                c >>= 32;
            }
            c += (long)z[2] - 1;
            z[2] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                Nat.DecAt(6, z, 3);
            }
        }
    }
}
