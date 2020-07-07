using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Math.EC.Custom.GM
{
    internal class SM2P256V1Field
    {
        // 2^256 - 2^224 - 2^96 + 2^64 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE };
        private static readonly uint[] PExt = new uint[]{ 00000001, 0x00000000, 0xFFFFFFFE, 0x00000001, 0x00000001,
            0xFFFFFFFE, 0x00000000, 0x00000002, 0xFFFFFFFE, 0xFFFFFFFD, 0x00000003, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0x00000000, 0xFFFFFFFE };
        private const uint P7 = 0xFFFFFFFE;
        private const uint PExt15 = 0xFFFFFFFE;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat256.Add(x, y, z);
            if (c != 0 || (z[7] >= P7 && Nat256.Gte(z, P)))
            {
                AddPInvTo(z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat.Add(16, xx, yy, zz);
            if (c != 0 || (zz[15] >= PExt15 && Nat.Gte(16, zz, PExt)))
            {
                Nat.SubFrom(16, PExt, zz);
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            uint c = Nat.Inc(8, x, z);
            if (c != 0 || (z[7] >= P7 && Nat256.Gte(z, P)))
            {
                AddPInvTo(z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat256.FromBigInteger(x);
            if (z[7] >= P7 && Nat256.Gte(z, P))
            {
                Nat256.SubFrom(P, z);
            }
            return z;
        }

        public static void Inv(uint[] x, uint[] z)
        {
            /*
             * Raise this element to the exponent 2^256 - 2^224 - 2^96 + 2^64 - 3
             *
             * Breaking up the exponent's binary representation into "repunits", we get:
             * { 31 1s } { 1 0s } { 128 1s } { 32 0s } { 62 1s } { 1 0s } { 1 1s }
             *
             * We use an addition chain for the beginning: [1], 2, [4], 6, 12, 24, 30, [31] 
             */

            if (0 != IsZero(x))
                throw new ArgumentException("cannot be 0", "x");

            uint[] x1 = x;
            uint[] x2 = Nat256.Create();
            Square(x1, x2);
            Multiply(x2, x1, x2);
            uint[] x4 = Nat256.Create();
            SquareN(x2, 2, x4);
            Multiply(x4, x2, x4);
            uint[] x6 = Nat256.Create();
            SquareN(x4, 2, x6);
            Multiply(x6, x2, x6);
            uint[] x12 = x2;
            SquareN(x6, 6, x12);
            Multiply(x12, x6, x12);
            uint[] x24 = Nat256.Create();
            SquareN(x12, 12, x24);
            Multiply(x24, x12, x24);
            uint[] x30 = x12;
            SquareN(x24, 6, x30);
            Multiply(x30, x6, x30);
            uint[] x31 = x6;
            Square(x30, x31);
            Multiply(x31, x1, x31);

            uint[] t = x24;
            SquareN(x31, 32, t);
            Multiply(t, x31, t);
            SquareN(t, 31, t);
            Multiply(t, x31, t);
            SquareN(t, 31, t);
            Multiply(t, x31, t);
            SquareN(t, 31, t);
            Multiply(t, x31, t);
            SquareN(t, 4, t);
            Multiply(t, x4, t);
            SquareN(t, 63, t);
            Multiply(t, x31, t);
            SquareN(t, 31, t);
            Multiply(t, x31, t);
            SquareN(t, 2, t);

            // NOTE that x1 and z could be the same array
            Multiply(x1, t, z);
        }

        public static void Half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.ShiftDownBit(8, x, 0, z);
            }
            else
            {
                uint c = Nat256.Add(x, P, z);
                Nat.ShiftDownBit(8, z, c);
            }
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
            uint c = Nat256.MulAddTo(x, y, zz);
            if (c != 0 || (zz[15] >= PExt15 && Nat.Gte(16, zz, PExt)))
            {
                Nat.SubFrom(16, PExt, zz);
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
            long xx08 = xx[8], xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];
            long xx12 = xx[12], xx13 = xx[13], xx14 = xx[14], xx15 = xx[15];

            long t0 = xx08 + xx09;
            long t1 = xx10 + xx11;
            long t2 = xx12 + xx15;
            long t3 = xx13 + xx14;
            long t4 = t3 + (xx15 << 1);

            long ts = t0 + t3;
            long tt = t1 + t2 + ts;

            long cc = 0;
            cc += (long)xx[0] + tt + xx13 + xx14 + xx15;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[1] + tt - xx08 + xx14 + xx15;
            z[1] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[2] - ts;
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[3] + tt - xx09 - xx10 + xx13;
            z[3] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[4] + tt - t1 - xx08 + xx14;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[5] + t4 + xx10;
            z[5] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[6] + xx11 + xx14 + xx15;
            z[6] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[7] + tt + t4 + xx12;
            z[7] = (uint)cc;
            cc >>= 32;

            Debug.Assert(cc >= 0);

            Reduce32((uint)cc, z);
        }

        public static void Reduce32(uint x, uint[] z)
        {
            long cc = 0;

            if (x != 0)
            {
                long xx08 = x;

                cc += (long)z[0] + xx08;
                z[0] = (uint)cc;
                cc >>= 32;
                if (cc != 0)
                {
                    cc += (long)z[1];
                    z[1] = (uint)cc;
                    cc >>= 32;
                }
                cc += (long)z[2] - xx08;
                z[2] = (uint)cc;
                cc >>= 32;
                cc += (long)z[3] + xx08;
                z[3] = (uint)cc;
                cc >>= 32;
                if (cc != 0)
                {
                    cc += (long)z[4];
                    z[4] = (uint)cc;
                    cc >>= 32;
                    cc += (long)z[5];
                    z[5] = (uint)cc;
                    cc >>= 32;
                    cc += (long)z[6];
                    z[6] = (uint)cc;
                    cc >>= 32;
                }
                cc += (long)z[7] + xx08;
                z[7] = (uint)cc;
                cc >>= 32;

                Debug.Assert(cc == 0 || cc == 1);
            }

            if (cc != 0 || (z[7] >= P7 && Nat256.Gte(z, P)))
            {
                AddPInvTo(z);
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
                SubPInvFrom(z);
            }
        }

        public static void SubtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.Sub(16, xx, yy, zz);
            if (c != 0)
            {
                Nat.AddTo(16, PExt, zz);
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            uint c = Nat.ShiftUpBit(8, x, 0, z);
            if (c != 0 || (z[7] >= P7 && Nat256.Gte(z, P)))
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
            c += (long)z[2] - 1;
            z[2] = (uint)c;
            c >>= 32;
            c += (long)z[3] + 1;
            z[3] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c += (long)z[4];
                z[4] = (uint)c;
                c >>= 32;
                c += (long)z[5];
                z[5] = (uint)c;
                c >>= 32;
                c += (long)z[6];
                z[6] = (uint)c;
                c >>= 32;
            }
            c += (long)z[7] + 1;
            z[7] = (uint)c;
            //c >>= 32;
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
            c += (long)z[2] + 1;
            z[2] = (uint)c;
            c >>= 32;
            c += (long)z[3] - 1;
            z[3] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c += (long)z[4];
                z[4] = (uint)c;
                c >>= 32;
                c += (long)z[5];
                z[5] = (uint)c;
                c >>= 32;
                c += (long)z[6];
                z[6] = (uint)c;
                c >>= 32;
            }
            c += (long)z[7] - 1;
            z[7] = (uint)c;
            //c >>= 32;
        }
    }
}
