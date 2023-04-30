using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public class FrodoKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private FrodoParameters m_parameters;
        private SecureRandom m_random;

        public void Init(KeyGenerationParameters param)
        {
            FrodoKeyGenerationParameters frodoParams = (FrodoKeyGenerationParameters)param;

            m_parameters = frodoParams.Parameters;
            m_random = frodoParams.Random;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
#pragma warning disable CS0618 // Type or member is obsolete
            FrodoEngine engine = m_parameters.Engine;
#pragma warning restore CS0618 // Type or member is obsolete
            byte[] sk = new byte[engine.PrivateKeySize];
            byte[] pk = new byte[engine.PublicKeySize];
            engine.kem_keypair(pk, sk, m_random);

            return new AsymmetricCipherKeyPair(
                new FrodoPublicKeyParameters(m_parameters, pk),
                new FrodoPrivateKeyParameters(m_parameters, sk));
        }
    }
}
