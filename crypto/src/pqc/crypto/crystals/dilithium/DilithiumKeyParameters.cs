using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    [Obsolete("Use ML-DSA instead")]
    public abstract class DilithiumKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly DilithiumParameters m_parameters;

        internal DilithiumKeyParameters(bool isPrivate, DilithiumParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        public DilithiumParameters Parameters => m_parameters;
    }
}
