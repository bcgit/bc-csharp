using System;

namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal static class Rounding
    {
        internal static void Power2RoundAll(int[] c0, int[] c1)
        {
            const int d = MLDsaEngine.D, n = MLDsaEngine.N;
            const int u = (1 << (d - 1)) - 1, v = -1 << d;

            for (int i = 0; i < n; ++i)
            {
                int a = c0[i];

                int t = a + u;
                int r1 = a - (t & v);

                c0[i] = t >> d;
                c1[i] = r1;
            }
        }

        internal static void DecomposeAll(int[] c0, int[] c1, int gamma2)
        {
            const int n = MLDsaEngine.N, q = MLDsaEngine.Q;

            if (gamma2 == (q - 1) / 32)
            {
                for (int i = 0; i < n; ++i)
                {
                    int a = c1[i];
                    int a1 = (a + 127) >> 7;
                    a1 = (a1 * 1025 + (1 << 21)) >> 22;
                    a1 &= 15;
                    int a0 = a - a1 * 2 * gamma2;
                    a0 -= (((q - 1) / 2 - a0) >> 31) & q;
                    c0[i] = a0;
                    c1[i] = a1;
                }
            }
            else if (gamma2 == (q - 1) / 88)
            {
                for (int i = 0; i < n; ++i)
                {
                    int a = c1[i];
                    int a1 = (a + 127) >> 7;
                    a1 = (a1 * 11275 + (1 << 23)) >> 24;
                    a1 ^= ((43 - a1) >> 31) & a1;
                    int a0 = a - a1 * 2 * gamma2;
                    a0 -= (((q - 1) / 2 - a0) >> 31) & q;
                    c0[i] = a0;
                    c1[i] = a1;
                }
            }
            else
            {
                throw new ArgumentException("Wrong Gamma2!");
            }
        }

        internal static int MakeHint(int a0, int a1, MLDsaEngine engine)
        {
            const int q = MLDsaEngine.Q;
            int g2 = engine.Gamma2;

            //if (a0 <= g2 || a0 > q - g2 || (a0 == q - g2 && a1 == 0))
            //    return 0;
            //return 1;

            int t = q - g2 - a0;
            int u = t | a1;
            return (((g2 - a0) & ~t & (u | -u)) >> 31) & 1;
        }

        internal static int UseHint(int a, int hint, int gamma2)
        {
            const int q = MLDsaEngine.Q;

            if (gamma2 == (q - 1) / 32)
            {
                int a1 = (a + 127) >> 7;
                a1 = (a1 * 1025 + (1 << 21)) >> 22;
                a1 &= 15;

                if (hint == 0)
                    return a1;

                int a0 = a - a1 * 2 * gamma2;
                a0 -= (((q - 1) / 2 - a0) >> 31) & q;

                if (a0 > 0)
                {
                    return (a1 + 1) & 15;
                }
                else
                {
                    return (a1 - 1) & 15;
                }
            }
            else if (gamma2 == (q - 1) / 88)
            {
                int a1 = (a + 127) >> 7;
                a1 = (a1 * 11275 + (1 << 23)) >> 24;
                a1 ^= ((43 - a1) >> 31) & a1;

                if (hint == 0)
                    return a1;

                int a0 = a - a1 * 2 * gamma2;
                a0 -= (((q - 1) / 2 - a0) >> 31) & q;

                if (a0 > 0)
                {
                    return (a1 == 43) ? 0 : a1 + 1;
                }
                else
                {
                    return (a1 == 0) ? 43 : a1 - 1;
                }
            }
            else
            {
                throw new ArgumentException("Wrong Gamma2!");
            }
        }
    }
}
