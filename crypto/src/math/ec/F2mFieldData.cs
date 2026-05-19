using System;

using Org.BouncyCastle.Math.BinPoly;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC
{
    internal class F2mFieldData
    {
        internal static F2mFieldData From(int m, int k1, int k2, int k3)
        {
            return k2 == 0 ? From(m, new int[]{ k1 })
                           : From(m, new int[]{ k1, k2, k3 });
        }

        internal static F2mFieldData From(int m, int[] ks)
        {
            var mul = ks.Length == 1 ? BinPolys.Mul.Trinomial(m, ks[0])
                                     : BinPolys.Mul.Pentanomial(m, ks[0], ks[1], ks[2]);
            var inv = BinPolys.Inv.ItohTsujii(mul);
            return new F2mFieldData(m, ks, mul, inv);
        }

        internal readonly int m;
        internal readonly int[] ks;
        internal readonly IBinPolyMul mul;
        internal readonly IBinPolyInv inv;

        internal F2mFieldData(int m, int[] ks, IBinPolyMul mul, IBinPolyInv inv)
        {
            this.m = m;
            this.ks = ks;
            this.mul = mul;
            this.inv = inv;
        }

        internal int K1 => ks[0];

        internal int K2 => ks.Length >= 2 ? ks[1] : 0;

        internal int K3 => ks.Length >= 3 ? ks[2] : 0;

        internal static bool Equals(F2mFieldData a, F2mFieldData b)
        {
            if (a == b)
                return true;

            return a.m == b.m && Arrays.AreEqual(a.ks, b.ks);
        }

        internal static int GetHashCode(F2mFieldData x) => x.m ^ Arrays.GetHashCode(x.ks);
    }
}
