using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    internal abstract class Mod
    {
        public static void Invert(uint[] p, uint[] x, uint[] z)
        {
            int len = p.Length;
            if (Nat.IsOne(len, x))
            {
                Array.Copy(x, 0, z, 0, len);
                return;
            }

            uint[] u = Nat.Copy(len, x);
            uint[] a = Nat.Create(len);
            a[0] = 1;

            if ((u[0] & 1) == 0)
            {
                InversionStep(p, u, len, a);
            }
            if (Nat.IsOne(len, u))
            {
                Array.Copy(a, 0, z, 0, len);
                return;
            }

            uint[] v = Nat.Copy(len, p);
            uint[] b = Nat.Create(len);

            int uvLen = len;

            for (;;)
            {
                while (u[uvLen - 1] == 0 && v[uvLen - 1] == 0)
                {
                    --uvLen;
                }

                if (Nat.Gte(len, u, v))
                {
                    Subtract(p, a, b, a);
                    Nat.Sub(len, u, v, u);
                    if ((u[0] & 1) == 0)
                    {
                        InversionStep(p, u, uvLen, a);
                    }
                    if (Nat.IsOne(len, u))
                    {
                        Array.Copy(a, 0, z, 0, len);
                        return;
                    }
                }
                else
                {
                    Subtract(p, b, a, b);
                    Nat.Sub(len, v, u, v);
                    if ((v[0] & 1) == 0)
                    {
                        InversionStep(p, v, uvLen, b);
                    }
                    if (Nat.IsOne(len, v))
                    {
                        Array.Copy(b, 0, z, 0, len);
                        return;
                    }
                }
            }
        }

        public static void Subtract(uint[] p, uint[] x, uint[] y, uint[] z)
        {
            int len = p.Length;
            int c = Nat.Sub(len, x, y, z);
            if (c != 0)
            {
                Nat.Add(len, z, p, z);
            }
        }

        private static void InversionStep(uint[] p, uint[] u, int uLen, uint[] x)
        {
            int len = p.Length;
            int count = 0;
            while (u[0] == 0)
            {
                Nat.ShiftDownWord(u, uLen, 0);
                count += 32;
            }

            {
                int zeroes = GetTrailingZeroes(u[0]);
                if (zeroes > 0)
                {
                    Nat.ShiftDownBits(u, uLen, zeroes, 0);
                    count += zeroes;
                }
            }

            for (int i = 0; i < count; ++i)
            {
                uint c = (x[0] & 1) == 0 ? 0 : Nat.Add(len, x, p, x);
                Nat.ShiftDownBit(x, len, c);
            }
        }

        private static int GetTrailingZeroes(uint x)
        {
    //        assert x != 0;

            int count = 0;
            while ((x & 1) == 0)
            {
                x >>= 1;
                ++count;
            }
            return count;
        }
    }
}
