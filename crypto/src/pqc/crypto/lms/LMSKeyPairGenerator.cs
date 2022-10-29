using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private LmsKeyGenerationParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            m_parameters = (LmsKeyGenerationParameters)parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            SecureRandom source = m_parameters.Random;

            byte[] I = new byte[16];
            source.NextBytes(I);

            byte[] rootSecret = new byte[32];
            source.NextBytes(rootSecret);

            LmsPrivateKeyParameters privKey = Lms.GenerateKeys(m_parameters.LmsParameters.LMSigParameters,
                m_parameters.LmsParameters.LMOtsParameters, 0, I, rootSecret);

            return new AsymmetricCipherKeyPair(privKey.GetPublicKey(), privKey);
        }
    }
}
