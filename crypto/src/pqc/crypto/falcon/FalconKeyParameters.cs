using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public abstract class FalconKeyParameters 
        : AsymmetricKeyParameter
    {
        private readonly FalconParameters m_parameters;

        internal FalconKeyParameters(bool isPrivate, FalconParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public FalconParameters Parameters => m_parameters;
    }
}
