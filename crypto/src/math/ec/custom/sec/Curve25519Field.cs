using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class Curve25519Field
    {
        // 2^255 - 2^4 - 2^1 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0x7FFFFFFF };
        private const int P7 = 0x7FFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x00000169, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0x3FFFFFFF };
        private const uint PInv = 0x13;

        public static void Add(uint[] x, uint[] y, uint[] z)
        {
            Nat256.Add(x, y, z);
            if (Nat256.Gte(z, P))
            {
                AddPInvTo(z);
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
                AddPInvTo(z);
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
            Debug.Assert(xx[15] >> 30 == 0);

            uint xx07 = xx[7];
            Nat.ShiftUpBit(8, xx, 8, xx07, z, 0);
            uint c = Nat256.MulByWordAddTo(PInv, xx, z) << 1;
            uint z07 = z[7];
            z[7] = z07 & P7;
            c += (z07 >> 31) - (xx07 >> 31);
            Nat.AddWordTo(8, c * PInv, z);
            if (Nat256.Gte(z, P))
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
    //        assert n > 0;

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
                AddPExtTo(zz);
            }
        }

        public static void Twice(uint[] x, uint[] z)
        {
            Nat.ShiftUpBit(8, x, 0, z);
            if (Nat256.Gte(z, P))
            {
                AddPInvTo(z);
            }
        }

        private static void AddPExtTo(uint[] zz)
        {
            ulong c = (ulong)zz[0] + PExt[0];
            zz[0] = (uint)c;
            c >>= 32;

            int i = 1 - (int)c;
            i = (i << 3) - i;

            while (++i < 16)
            {
                c += (ulong)zz[i] + PExt[i];
                zz[i] = (uint)c;
                c >>= 32;
            }
        }

        private static void SubPExtFrom(uint[] zz)
        {
            long c = (long)zz[0] - PExt[0];
            zz[0] = (uint)c;
            c >>= 32;

            int i = 1 + (int)c;
            i = (i << 3) - i;

            while (++i < 16)
            {
                c += (long)zz[i] - PExt[i];
                zz[i] = (uint)c;
                c >>= 32;
            }
        }

        private static void AddPInvTo(uint[] z)
        {
            ulong c = (ulong)z[0] + PInv;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                Nat.IncAt(7, z, 1);
            }
            z[7] &= P7;
        }

        private static void SubPInvFrom(uint[] z)
        {
            long c = (long)z[0] - PInv;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                Nat.DecAt(7, z, 1);
            }
            z[7] &= P7;
        }
    }
}
