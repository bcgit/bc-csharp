using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECPrivateKeyParameters
        : ECKeyParameters
    {
        private readonly BigInteger m_d;

        public ECPrivateKeyParameters(BigInteger d, ECDomainParameters parameters)
            : this("EC", d, parameters)
        {
        }

        public ECPrivateKeyParameters(string algorithm, BigInteger d, ECDomainParameters parameters)
            : base(algorithm, true, parameters)
        {
            m_d = Parameters.ValidatePrivateScalar(d);
        }

        public ECPrivateKeyParameters(string algorithm, BigInteger d, DerObjectIdentifier publicKeyParamSet)
            : base(algorithm, true, publicKeyParamSet)
        {
            m_d = Parameters.ValidatePrivateScalar(d);
        }

        public BigInteger D => m_d;

        public override bool Equals(object obj) => obj is ECPrivateKeyParameters other && Equals(other);

        // TODO[api] Should be override
        protected bool Equals(ECPrivateKeyParameters other) => m_d.Equals(other.m_d) && base.Equals(other);

        public override int GetHashCode() => m_d.GetHashCode() ^ base.GetHashCode();
    }
}
