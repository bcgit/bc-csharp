using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP256R1Field
    {
        // 2^256 - 2^224 + 2^192 + 2^96 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0xFFFFFFFF };
        private const uint P7 = 0xFFFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0x00000001, 0xFFFFFFFE,
            0x00000002, 0xFFFFFFFE };

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            uint c = Nat256.Add(x, y, z);
            if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.Sub(z, P, z);
            }
        }

        public static void AddExt(uint[] xx, uint[] yy, uint[] zz)
        {
            uint c = Nat256.AddExt(xx, yy, zz);
            if (c != 0 || Nat256.GteExt(zz, PExt))
            {
                Nat256.SubExt(zz, PExt, zz);
            }
        }

        public static void AddOne(uint[] x, uint[] z)
        {
            Array.Copy(x, 0, z, 0, 8);
            uint c = Nat256.Inc(z, 0);
            if (c != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.Sub(z, P, z);
            }
        }

        public static uint[] FromBigInteger(BigInteger x)
        {
            uint[] z = Nat256.FromBigInteger(x);
            if (z[7] == P7 && Nat256.Gte(z, P))
            {
                Nat256.Sub(z, P, z);
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

        public static void Reduce(uint[] tt, uint[] z)
        {
            long t08 = tt[8], t09 = tt[9], t10 = tt[10], t11 = tt[11];
            long t12 = tt[12], t13 = tt[13], t14 = tt[14], t15 = tt[15];

            long cc = 0;
            cc += (long)tt[0] + t08 + t09 - t11 - t12 - t13 - t14;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[1] + t09 + t10 - t12 - t13 - t14 - t15;
            z[1] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[2] + t10 + t11 - t13 - t14 - t15;
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[3] + ((t11 + t12) << 1) + t13 - t15 - t08 - t09;
            z[3] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[4] + ((t12 + t13) << 1) + t14 - t09 - t10;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[5] + ((t13 + t14) << 1) + t15 - t10 - t11;
            z[5] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[6] + ((t14 + t15) << 1) + t14 + t13 - t08 - t09;
            z[6] = (uint)cc;
            cc >>= 32;
            cc += (long)tt[7] + (t15 << 1) + t15 + t08 - t10 - t11 - t12 - t13;
            z[7] = (uint)cc;
            cc >>= 32;

            int c = (int)cc;
            if (c > 0)
            {
                do
                {
                    c += Nat256.Sub(z, P, z);
                }
                while (c != 0);

                if (z[7] == P7 && Nat256.Gte(z, P))
                {
                    Nat256.Sub(z, P, z);
                }
            }
            else if (c < 0)
            {
                do
                {
                    c += (int)Nat256.Add(z, P, z);
                }
                while (c != 0);
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
                Nat256.Add(z, P, z);
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
                Nat256.Sub(z, P, z);
            }
        }
    }
}
