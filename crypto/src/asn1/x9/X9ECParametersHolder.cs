using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X9
{
	public abstract class X9ECParametersHolder
	{
        private ECCurve m_curve;
        private X9ECParameters m_parameters;

        public ECCurve Curve => Objects.EnsureSingletonInitialized(ref m_curve, this, self => self.CreateCurve());

        public X9ECParameters Parameters =>
            Objects.EnsureSingletonInitialized(ref m_parameters, this, self => self.CreateParameters());

        protected virtual ECCurve CreateCurve() => Parameters.Curve;

        protected abstract X9ECParameters CreateParameters();
	}
}
