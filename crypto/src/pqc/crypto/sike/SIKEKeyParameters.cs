using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public abstract class SikeKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SikeParameters m_parameters;

        public SikeKeyParameters(bool isPrivate, SikeParameters param)
            : base(isPrivate)
        {
            this.m_parameters = param;
        }

        public SikeParameters Parameters => m_parameters;
    }
}
