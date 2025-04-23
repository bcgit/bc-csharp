using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public abstract class SlhDsaKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SlhDsaParameters m_parameters;

        internal SlhDsaKeyParameters(bool isPrivate, SlhDsaParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public SlhDsaParameters Parameters => m_parameters;
    }
}
