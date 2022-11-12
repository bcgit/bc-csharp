using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public abstract class SikeKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SikeParameters m_parameters;

        internal SikeKeyParameters(bool isPrivate, SikeParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        public SikeParameters Parameters => m_parameters;
    }
}
