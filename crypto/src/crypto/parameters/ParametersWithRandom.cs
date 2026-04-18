using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include a source of randomness (SecureRandom).
    /// </summary>
    public class ParametersWithRandom
		: ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
		private readonly SecureRandom m_random;

        /// <summary>
        /// Constructor using the default secure random from <see cref="CryptoServicesRegistrar"/>.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        public ParametersWithRandom(ICipherParameters parameters)
            : this(parameters, CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="random">The source of randomness.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or <paramref name="random"/> is
        /// null.</exception>
        public ParametersWithRandom(ICipherParameters parameters, SecureRandom random)
        {
			m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            m_random = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>
        /// Return the base parameters associated with this randomness.
        /// </summary>
        /// <returns>The parameters wrapped by this source of randomness.</returns>
        public ICipherParameters Parameters => m_parameters;

        /// <summary>
        /// Return the source of randomness.
        /// </summary>
        /// <returns>The source of randomness.</returns>
        public SecureRandom Random => m_random;
    }
}
