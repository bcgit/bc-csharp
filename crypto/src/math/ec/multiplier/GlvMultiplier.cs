using System;

using Org.BouncyCastle.Math.EC.Endo;

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /// <summary>A multiplier using the GLV method for curves with an efficiently computable endomorphism.</summary>
    public class GlvMultiplier
        :   AbstractECMultiplier
    {
        /// <summary>The curve.</summary>
        protected readonly ECCurve curve;
        /// <summary>The glv endomorphism.</summary>
        protected readonly GlvEndomorphism glvEndomorphism;

        /// <summary>Create a new <see cref="GlvMultiplier"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="glvEndomorphism">The glv endomorphism.</param>
        public GlvMultiplier(ECCurve curve, GlvEndomorphism glvEndomorphism)
        {
            if (curve == null || curve.Order == null)
                throw new ArgumentException("Need curve with known group order", "curve");

            this.curve = curve;
            this.glvEndomorphism = glvEndomorphism;
        }

        /// <inheritdoc/>
        protected override ECPoint MultiplyPositive(ECPoint p, BigInteger k)
        {
            if (!curve.Equals(p.Curve))
                throw new InvalidOperationException();

            BigInteger n = p.Curve.Order;
            BigInteger[] ab = glvEndomorphism.DecomposeScalar(k.Mod(n));
            BigInteger a = ab[0], b = ab[1];

            if (glvEndomorphism.HasEfficientPointMap)
            {
                return ECAlgorithms.ImplShamirsTrickWNaf(glvEndomorphism, p, a, b);
            }

            ECPoint q = EndoUtilities.MapPoint(glvEndomorphism, p);

            return ECAlgorithms.ImplShamirsTrickWNaf(p, a, q, b);
        }
    }
}
