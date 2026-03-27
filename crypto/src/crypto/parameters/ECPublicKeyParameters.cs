using System;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Elliptic curve public key parameters.</summary>
    public class ECPublicKeyParameters
        : ECKeyParameters
    {
        private readonly ECPoint m_q;

        /// <summary>Initializes a new instance of <see cref="ECPublicKeyParameters"/>.</summary>
        /// <param name="q">The public point Q.</param>
        /// <param name="parameters">The EC domain parameters.</param>
        public ECPublicKeyParameters(ECPoint q, ECDomainParameters parameters)
            : this("EC", q, parameters)
        {
        }

        /// <summary>Initializes a new instance of <see cref="ECPublicKeyParameters"/>.</summary>
        /// <param name="algorithm">The algorithm name.</param>
        /// <param name="q">The public point Q.</param>
        /// <param name="parameters">The EC domain parameters.</param>
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

        /// <summary>Gets the public point Q.</summary>
        public ECPoint Q => m_q;

        public override bool Equals(object obj) => obj is ECPublicKeyParameters other && Equals(other);

        // TODO[api] Should be override
        protected bool Equals(ECPublicKeyParameters other) => m_q.Equals(other.m_q) && base.Equals(other);

        public override int GetHashCode() => m_q.GetHashCode() ^ base.GetHashCode();
    }
}
