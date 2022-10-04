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
            : this(parameters, new SecureRandom())
        {
        }

        public ParametersWithRandom(ICipherParameters parameters, SecureRandom random)
        {
			if (parameters == null)
				throw new ArgumentNullException(nameof(parameters));
			if (random == null)
				throw new ArgumentNullException(nameof(random));

			m_parameters = parameters;
			m_random = random;
		}

        public ICipherParameters Parameters => m_parameters;

        public SecureRandom Random => m_random;
    }
}
