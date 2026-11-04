using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>Holder that creates the <see cref="X9ECParameters"/> of a named curve on first use.</summary>
    public abstract class X9ECParametersHolder
    {
        private ECCurve m_curve;
        private X9ECParameters m_parameters;

        /// <summary>Gets the curve.</summary>
        public ECCurve Curve => Objects.EnsureSingletonInitialized(ref m_curve, this, self => self.CreateCurve());

        /// <summary>Gets the parameters.</summary>
        public X9ECParameters Parameters =>
            Objects.EnsureSingletonInitialized(ref m_parameters, this, self => self.CreateParameters());

        /// <summary>Create the curve.</summary>
        /// <returns>The curve.</returns>
        protected virtual ECCurve CreateCurve() => Parameters.Curve;

        /// <summary>Create the parameters.</summary>
        /// <returns>The parameters.</returns>
        protected abstract X9ECParameters CreateParameters();
    }
}
