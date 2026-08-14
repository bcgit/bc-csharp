using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>
    /// Key-pair generator for Composite ML-DSA. Driven by a
    /// <see cref="CompositeMLDsaKeyGenerationParameters"/> init payload; generates both component key pairs
    /// to the sizes the chosen combination requires.
    /// </summary>
    public sealed class CompositeMLDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private static readonly BigInteger PublicExponent = BigInteger.ValueOf(0x10001);

        private const int RsaCertainty = 100;

        private SecureRandom m_random;
        private CompositeMLDsaParameters m_parameters;

        /// <summary>
        /// Initialise with a <see cref="CompositeMLDsaKeyGenerationParameters"/> instance; the
        /// <see cref="SecureRandom"/> and combination are taken from it.
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not a
        /// <see cref="CompositeMLDsaKeyGenerationParameters"/>.</exception>
        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((CompositeMLDsaKeyGenerationParameters)parameters).Parameters;
        }

        /// <summary>Generate a fresh composite key pair.</summary>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            if (m_parameters == null)
                throw new InvalidOperationException("CompositeMLDsaKeyPairGenerator not initialised");

            var random = CryptoServicesRegistrar.GetSecureRandom(m_random);

            var mlDsaKeyPairGenerator = new MLDsaKeyPairGenerator();
            mlDsaKeyPairGenerator.Init(
                new MLDsaKeyGenerationParameters(random, m_parameters.MLDsaParameters));
            var mlDsaKeyPair = mlDsaKeyPairGenerator.GenerateKeyPair();

            var traditionalKeyPair = GenerateTraditionalKeyPair(random);

            var publicKey = new CompositeMLDsaPublicKeyParameters(m_parameters,
                (MLDsaPublicKeyParameters)mlDsaKeyPair.Public, traditionalKeyPair.Public);
            var privateKey = new CompositeMLDsaPrivateKeyParameters(m_parameters,
                (MLDsaPrivateKeyParameters)mlDsaKeyPair.Private, traditionalKeyPair.Private);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        private AsymmetricCipherKeyPair GenerateTraditionalKeyPair(SecureRandom random)
        {
            switch (m_parameters.KeyType)
            {
            case CompositeMLDsaParameters.TraditionalKeyType.Ed25519:
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(random));
                return generator.GenerateKeyPair();
            }
            case CompositeMLDsaParameters.TraditionalKeyType.Ed448:
            {
                var generator = new Ed448KeyPairGenerator();
                generator.Init(new Ed448KeyGenerationParameters(random));
                return generator.GenerateKeyPair();
            }
            case CompositeMLDsaParameters.TraditionalKeyType.ECDsa:
            {
                var generator = new ECKeyPairGenerator();
                generator.Init(new ECKeyGenerationParameters(m_parameters.CurveOid, random));
                return generator.GenerateKeyPair();
            }
            case CompositeMLDsaParameters.TraditionalKeyType.Rsa:
            {
                var generator = new RsaKeyPairGenerator();
                generator.Init(new RsaKeyGenerationParameters(PublicExponent, random, m_parameters.RsaKeySize,
                    RsaCertainty));
                return generator.GenerateKeyPair();
            }
            default:
                throw new InvalidOperationException();
            }
        }
    }
}
