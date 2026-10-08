using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>
    /// Key-pair generator for one Composite ML-DSA combination, fixed at construction. Only the
    /// <see cref="SecureRandom"/> from the supplied <see cref="KeyGenerationParameters"/> is used; both component
    /// key pairs are generated to the sizes the combination requires.
    /// </summary>
    public sealed class CompositeMLDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private static readonly BigInteger PublicExponent = BigInteger.ValueOf(0x10001);

        private const int RsaCertainty = 100;

        private readonly CompositeMLDsaParameters m_parameters;

        private SecureRandom m_random;

        /// <summary>Construct a generator for the given combination.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        public CompositeMLDsaKeyPairGenerator(CompositeMLDsaParameters parameters)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>
        /// Capture the <see cref="SecureRandom"/> both component generators will draw from. The strength is
        /// ignored, since the combination fixes every key size.
        /// </summary>
        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
        }

        /// <summary>Generate a fresh composite key pair.</summary>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            if (m_random == null)
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
