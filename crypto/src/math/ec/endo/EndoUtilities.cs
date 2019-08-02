using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public abstract class EndoUtilities
    {
        public static BigInteger[] DecomposeScalar(ScalarSplitParameters p, BigInteger k)
        {
            int bits = p.Bits;
            BigInteger b1 = CalculateB(k, p.G1, bits);
            BigInteger b2 = CalculateB(k, p.G2, bits);

            BigInteger a = k.Subtract((b1.Multiply(p.V1A)).Add(b2.Multiply(p.V2A)));
            BigInteger b = (b1.Multiply(p.V1B)).Add(b2.Multiply(p.V2B)).Negate();

            return new BigInteger[]{ a, b };
        }

        private static BigInteger CalculateB(BigInteger k, BigInteger g, int t)
        {
            bool negative = (g.SignValue < 0);
            BigInteger b = k.Multiply(g.Abs());
            bool extra = b.TestBit(t - 1);
            b = b.ShiftRight(t);
            if (extra)
            {
                b = b.Add(BigInteger.One);
            }
            return negative ? b.Negate() : b;
        }
    }
}
