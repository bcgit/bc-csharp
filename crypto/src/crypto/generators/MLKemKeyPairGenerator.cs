using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    public class MLKemKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private MLKemParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((MLKemKeyGenerationParameters)parameters).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            m_parameters.ParameterSet.Engine.GenerateKemKeyPair(m_random, out byte[] seed, out byte[] encoding);

            var privateKey = new MLKemPrivateKeyParameters(m_parameters, seed, encoding,
                preferredFormat: MLKemPrivateKeyParameters.Format.SeedAndEncoding);

            return new AsymmetricCipherKeyPair(privateKey.GetPublicKey(), privateKey);
        }
    }
}
