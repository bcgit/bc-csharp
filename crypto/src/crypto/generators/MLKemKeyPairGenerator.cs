using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>
    /// Key-pair generator for ML-KEM (FIPS 203). Driven by an <see cref="MLKemKeyGenerationParameters"/>
    /// init payload; produces an <see cref="AsymmetricCipherKeyPair"/> bound to the chosen parameter set.
    /// </summary>
    public class MLKemKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private MLKemParameters m_parameters;

        /// <summary>
        /// Initialise with an <see cref="MLKemKeyGenerationParameters"/> instance; the <see cref="SecureRandom"/>
        /// and parameter set are taken from it.
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="MLKemKeyGenerationParameters"/>.</exception>
        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((MLKemKeyGenerationParameters)parameters).Parameters;
        }

        /// <summary>
        /// Generate a fresh ML-KEM key pair. The private key is returned with
        /// <see cref="MLKemPrivateKeyParameters.Format.SeedAndEncoding"/> so the resulting key carries both
        /// the 64-byte seed and the expanded encoding.
        /// </summary>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            m_parameters.ParameterSet.Engine.GenerateKemKeyPair(m_random, out byte[] seed, out byte[] encoding);

            var privateKey = new MLKemPrivateKeyParameters(m_parameters, seed, encoding,
                preferredFormat: MLKemPrivateKeyParameters.Format.SeedAndEncoding);

            return new AsymmetricCipherKeyPair(privateKey.GetPublicKey(), privateKey);
        }
    }
}
