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

        public static void Reduce(uint[] xx, uint[] z)
        {
            long xx08 = xx[8], xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];
            long xx12 = xx[12], xx13 = xx[13], xx14 = xx[14], xx15 = xx[15];

            long t0 = xx08 + xx09;
            long t1 = xx09 + xx10;
            long t2 = xx10 + xx11;
            long t3 = xx11 + xx12;
            long t4 = xx12 + xx13;
            long t5 = xx13 + xx14;
            long t6 = xx14 + xx15;

            long cc = 0;
            cc += (long)xx[0] + t0 - t3 - t5;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[1] + t1 - t4 - t6;
            z[1] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[2] + t2 - t5 - xx15;
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[3] + (t3 << 1) + xx13 - xx15 - t0;
            z[3] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[4] + (t4 << 1) + xx14 - t1;
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[5] + (t5 << 1) + xx15 - t2;
            z[5] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[6] + (t6 << 1) + t5 - t0;
            z[6] = (uint)cc;
            cc >>= 32;
            cc += (long)xx[7] + (xx15 << 1) + xx15 + xx08 - t2 - t4;
            z[7] = (uint)cc;
            cc >>= 32;

            int c = (int)cc;
            if (c < 0)
            {
                do
                {
                    c += (int)Nat256.Add(z, P, z);
                }
                while (c < 0);
            }
            else
            {
                while (c > 0)
                {
                    c += Nat256.Sub(z, P, z);
                }

                if (z[7] == P7 && Nat256.Gte(z, P))
                {
                    Nat256.Sub(z, P, z);
                }
            }
        }

        public static void Reduce32(uint x, uint[] z)
        {
            long xx08 = x;

            long cc = 0;
            cc += (long)z[0] + xx08;
            z[0] = (uint)cc;
            cc >>= 32;
            cc += (long)z[1];
            z[1] = (uint)cc;
            cc >>= 32;
            cc += (long)z[2];
            z[2] = (uint)cc;
            cc >>= 32;
            cc += (long)z[3] - xx08;
            z[3] = (uint)cc;
            cc >>= 32;
            cc += (long)z[4];
            z[4] = (uint)cc;
            cc >>= 32;
            cc += (long)z[5];
            z[5] = (uint)cc;
            cc >>= 32;
            cc += (long)z[6] - xx08;
            z[6] = (uint)cc;
            cc >>= 32;
            cc += (long)z[7] + xx08;
            z[7] = (uint)cc;
            cc >>= 32;

            if (cc != 0 || (z[7] == P7 && Nat256.Gte(z, P)))
            {
                Nat256.Sub(z, P, z);
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
