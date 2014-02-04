using System;

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    public class FixedPointUtilities
    {
        public static FixedPointPreCompInfo GetFixedPointPreCompInfo(PreCompInfo preCompInfo)
        {
            if ((preCompInfo != null) && (preCompInfo is FixedPointPreCompInfo))
            {
                return (FixedPointPreCompInfo)preCompInfo;
            }

            return new FixedPointPreCompInfo();
        }

        public static FixedPointPreCompInfo Precompute(ECPoint p, int width)
        {
            ECCurve c = p.Curve;

            int n = 1 << width;
            FixedPointPreCompInfo info = GetFixedPointPreCompInfo(c.GetPreCompInfo(p));
            ECPoint[] lookupTable = info.PreComp;

            if (lookupTable == null || lookupTable.Length != n)
            {
                BigInteger order = c.Order;
                if (order == null)
                    throw new InvalidOperationException("fixed-point precomputation needs the curve order");

                int bits = order.BitLength;
                int d = (bits + width - 1) / width;

                ECPoint[] pow2Table = new ECPoint[width];
                pow2Table[0] = p;
                for (int i = 1; i < width; ++i)
                {
                    pow2Table[i] = pow2Table[i - 1].TimesPow2(d);
                }
    
                c.NormalizeAll(pow2Table);
    
                lookupTable = new ECPoint[n];
                lookupTable[0] = c.Infinity;

                for (int bit = width - 1; bit >= 0; --bit)
                {
                    ECPoint pow2 = pow2Table[bit];

                    int step = 1 << bit;
                    for (int i = step; i < n; i += (step << 1))
                    {
                        lookupTable[i] = lookupTable[i - step].Add(pow2);
                    }
                }

                c.NormalizeAll(lookupTable);

                info.PreComp = lookupTable;

                c.SetPreCompInfo(p, info);
            }

            return info;
        }
    }
}
