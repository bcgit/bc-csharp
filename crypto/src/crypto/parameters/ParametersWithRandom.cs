using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithRandom
		: ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
		private readonly SecureRandom m_random;

        public ParametersWithRandom(ICipherParameters parameters)
            : this(parameters, CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        public ParametersWithRandom(ICipherParameters parameters, SecureRandom random)
        {
			m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            m_random = random ?? throw new ArgumentNullException(nameof(random));
        }

        public ICipherParameters Parameters => m_parameters;

        public SecureRandom Random => m_random;
    }
}
