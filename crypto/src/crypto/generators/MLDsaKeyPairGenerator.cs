using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>
    /// Key-pair generator for ML-DSA (FIPS 204). Driven by an <see cref="MLDsaKeyGenerationParameters"/>
    /// init payload; produces an <see cref="AsymmetricCipherKeyPair"/> bound to the chosen parameter set.
    /// </summary>
    public sealed class MLDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private MLDsaParameters m_parameters;

        /// <summary>
        /// Initialise with an <see cref="MLDsaKeyGenerationParameters"/> instance; the <see cref="SecureRandom"/>
        /// and parameter set are taken from it.
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="MLDsaKeyGenerationParameters"/>.</exception>
        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((MLDsaKeyGenerationParameters)parameters).Parameters;
        }

        /// <summary>
        /// Generate a fresh ML-DSA key pair. The private key is returned with
        /// <see cref="MLDsaPrivateKeyParameters.Format.SeedAndEncoding"/> so the resulting key carries both
        /// the 32-byte seed and the expanded encoding.
        /// </summary>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var engine = m_parameters.ParameterSet.GetEngine(m_random);

            byte[] rho, k, tr, s1, s2, t0, encT1, seed;
            engine.GenerateKeyPair(out rho, out k, out tr, out s1, out s2, out t0, out encT1, out seed);

            var format = MLDsaPrivateKeyParameters.Format.SeedAndEncoding;

            return new AsymmetricCipherKeyPair(
                new MLDsaPublicKeyParameters(m_parameters, rho, encT1),
                new MLDsaPrivateKeyParameters(m_parameters, rho, k, tr, s1, s2, t0, encT1, seed, format));
        }
    }
}
