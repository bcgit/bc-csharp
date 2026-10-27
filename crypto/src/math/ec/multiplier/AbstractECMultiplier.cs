namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /// <summary>Base class for elliptic curve multipliers: handles the trivial cases and negative scalars.</summary>
    public abstract class AbstractECMultiplier
        : ECMultiplier
    {
        /// <inheritdoc/>
        public virtual ECPoint Multiply(ECPoint p, BigInteger k)
        {
            int sign = k.SignValue;
            if (sign == 0 || p.IsInfinity)
                return p.Curve.Infinity;

            ECPoint positive = MultiplyPositive(p, k.Abs());
            ECPoint result = sign > 0 ? positive : positive.Negate();

            /*
             * Although the various multipliers ought not to produce invalid output under normal
             * circumstances, a final check here is advised to guard against fault attacks.
             */
            return CheckResult(result);
        }

        /// <summary>Multiply a point by a positive scalar.</summary>
        /// <param name="p">The point.</param>
        /// <param name="k">The scalar, which is positive.</param>
        /// <returns>The product.</returns>
        protected abstract ECPoint MultiplyPositive(ECPoint p, BigInteger k);

        /// <summary>Check and normalize the result of a multiplication.</summary>
        /// <param name="p">The result.</param>
        /// <returns>The checked result.</returns>
        protected virtual ECPoint CheckResult(ECPoint p)
        {
            return ECAlgorithms.ImplCheckResult(p);
        }
    }
}
