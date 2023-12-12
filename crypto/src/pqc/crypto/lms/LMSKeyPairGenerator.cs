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
            var random = m_parameters.Random;
            byte[] I = SecureRandom.GetNextBytes(random, 16);

            var lmsParameters = m_parameters.LmsParameters;
            var sigParameters = lmsParameters.LMSigParameters;
            var otsParameters = lmsParameters.LMOtsParameters;
            byte[] rootSecret = SecureRandom.GetNextBytes(random, sigParameters.M);

            LmsPrivateKeyParameters privKey = Lms.GenerateKeys(sigParameters, otsParameters, 0, I, rootSecret);

            return new AsymmetricCipherKeyPair(privKey.GetPublicKey(), privKey);
        }
    }
}
