using System;

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    public class FixedPointCombMultiplier
        : AbstractECMultiplier
    {
        protected override ECPoint MultiplyPositive(ECPoint p, BigInteger k)
        {
            int width = 4;

            FixedPointPreCompInfo info = FixedPointUtilities.Precompute(p, width);
            ECPoint[] lookupTable = info.PreComp;

            ECCurve c = p.Curve;
            int d = (c.Order.BitLength + width - 1) / width;

            ECPoint R = c.Infinity;

            for (int i = d - 1; i >= 0; --i)
            {
                int index = 0;
                for (int j = width - 1; j >= 0; --j)
                {
                    index <<= 1;
                    if (k.TestBit(j * d + i))
                    {
                        index |= 1;
                    }
                }

                R = R.TwicePlus(lookupTable[index]);
            }

            return R;
        }
    }
}
