using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class MLDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private MLDsaParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((MLDsaKeyGenerationParameters)parameters).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var engine = m_parameters.ParameterSet.GetEngine(m_random);

            byte[] rho, k, tr, s1, s2, t0, encT1, seed;
            engine.GenerateKeyPair(legacy: false, out rho, out k, out tr, out s1, out s2, out t0, out encT1, out seed);

            return new AsymmetricCipherKeyPair(
                new MLDsaPublicKeyParameters(m_parameters, rho, encT1),
                new MLDsaPrivateKeyParameters(m_parameters, rho, k, tr, s1, s2, t0, encT1, seed));
        }
    }
}
