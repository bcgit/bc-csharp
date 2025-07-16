using System;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECPublicKeyParameters
        : ECKeyParameters
    {
        private readonly ECPoint m_q;

        public ECPublicKeyParameters(ECPoint q, ECDomainParameters parameters)
            : this("EC", q, parameters)
        {
        }

        public ECPublicKeyParameters(string algorithm, ECPoint q, ECDomainParameters parameters)
            : base(algorithm, false, parameters)
        {
            m_q = ECDomainParameters.ValidatePublicPoint(Parameters.Curve, q);
        }

        public ECPublicKeyParameters(string algorithm, ECPoint q, DerObjectIdentifier publicKeyParamSet)
            : base(algorithm, false, publicKeyParamSet)
        {
            m_q = ECDomainParameters.ValidatePublicPoint(Parameters.Curve, q);
        }

        public ECPoint Q => m_q;

        public override bool Equals(object obj) => obj is ECPublicKeyParameters other && Equals(other);

        // TODO[api] Should be override
        protected bool Equals(ECPublicKeyParameters other) => m_q.Equals(other.m_q) && base.Equals(other);

        public override int GetHashCode() => m_q.GetHashCode() ^ base.GetHashCode();
    }
}
