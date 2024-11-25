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
            var engine = m_parameters.ParameterSet.GetEngine(m_random);

            engine.GenerateKemKeyPair(out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk, out byte[] nonce,
                out byte[] seed);

            MLKemPublicKeyParameters pubKey = new MLKemPublicKeyParameters(m_parameters, t, rho);
            MLKemPrivateKeyParameters privKey = new MLKemPrivateKeyParameters(m_parameters, s, hpk, nonce, t, rho, seed);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        internal AsymmetricCipherKeyPair InternalGenerateKeyPair(byte[] d, byte[] z)
        {
            var engine = m_parameters.ParameterSet.GetEngine(random: null);

            engine.GenerateKemKeyPairInternal(d, z, out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk,
                out byte[] nonce, out byte[] seed);

            MLKemPublicKeyParameters pubKey = new MLKemPublicKeyParameters(m_parameters, t, rho);
            MLKemPrivateKeyParameters privKey = new MLKemPrivateKeyParameters(m_parameters, s, hpk, nonce, t, rho, seed);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
    }
}
