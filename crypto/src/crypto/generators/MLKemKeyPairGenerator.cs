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

            return CreateKeyPair(m_parameters, t, rho, s, hpk, nonce, seed);
        }

        internal AsymmetricCipherKeyPair InternalGenerateKeyPair(byte[] d, byte[] z)
        {
            var engine = m_parameters.ParameterSet.GetEngine(random: null);

            engine.GenerateKemKeyPairInternal(d, z, out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk,
                out byte[] nonce, out byte[] seed);

            return CreateKeyPair(m_parameters, t, rho, s, hpk, nonce, seed);
        }

        private static AsymmetricCipherKeyPair CreateKeyPair(MLKemParameters parameters, byte[] t, byte[] rho, byte[] s,
            byte[] hpk, byte[] nonce, byte[] seed)
        {
            var format = MLKemPrivateKeyParameters.Format.SeedAndEncoding;

            return new AsymmetricCipherKeyPair(
                publicParameter: new MLKemPublicKeyParameters(parameters, t, rho),
                privateParameter: new MLKemPrivateKeyParameters(parameters, s, hpk, nonce, t, rho, seed, format));
        }
    }
}
