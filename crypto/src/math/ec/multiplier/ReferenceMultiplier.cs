namespace Org.BouncyCastle.Math.EC.Multiplier
{
    public class ReferenceMultiplier
        : AbstractECMultiplier
    {
        /**
         * Simple shift-and-add multiplication. Serves as reference implementation
         * to verify (possibly faster) implementations in
         * {@link org.bouncycastle.math.ec.ECPoint ECPoint}.
         * 
         * @param p The point to multiply.
         * @param k The factor by which to multiply.
         * @return The result of the point multiplication <code>k * p</code>.
         */
        protected override ECPoint MultiplyPositive(ECPoint p, BigInteger k)
        {
            ECPoint q = p.Curve.Infinity;
            int t = k.BitLength;
            if (t > 0)
            {
                if (k.TestBit(0))
                {
                    q = p;
                }
                for (int i = 1; i < t; i++)
                {
                    p = p.Twice();
                    if (k.TestBit(i))
                    {
                        q = q.Add(p);
                    }
                }
            }
            return q;
        }
    }
}
