namespace Org.BouncyCastle.Math.EC.Multiplier
{
    public abstract class AbstractECMultiplier
        : ECMultiplier
    {
        public virtual ECPoint Multiply(ECPoint p, BigInteger k)
        {
            int sign = k.SignValue;
            if (sign == 0 || p.IsInfinity)
                return p.Curve.Infinity;

            ECPoint positive = MultiplyPositive(p, k.Abs());
            return sign > 0 ? positive : positive.Negate();
        }

        protected abstract ECPoint MultiplyPositive(ECPoint p, BigInteger k);
    }
}
