using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public class GlvTypeAEndomorphism
        :   GlvEndomorphism
    {
        protected readonly GlvTypeAParameters m_parameters;
        protected readonly ECPointMap m_pointMap;

        /// <summary>Create a new <see cref="GlvTypeAEndomorphism"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="parameters">The parameters.</param>
        public GlvTypeAEndomorphism(ECCurve curve, GlvTypeAParameters parameters)
        {
            /*
             * NOTE: 'curve' MUST only be used to create a suitable ECFieldElement. Due to the way
             * ECCurve configuration works, 'curve' will not be the actual instance of ECCurve that the
             * endomorphism is being used with.
             */

            this.m_parameters = parameters;
            this.m_pointMap = new ScaleYNegateXPointMap(curve.FromBigInteger(parameters.I));
        }

        /// <inheritdoc/>
        public virtual BigInteger[] DecomposeScalar(BigInteger k)
        {
            return EndoUtilities.DecomposeScalar(m_parameters.SplitParams, k);
        }

        /// <inheritdoc/>
        public virtual ECPointMap PointMap
        {
            get { return m_pointMap; }
        }

        /// <inheritdoc/>
        public virtual bool HasEfficientPointMap
        {
            get { return true; }
        }
    }
}
