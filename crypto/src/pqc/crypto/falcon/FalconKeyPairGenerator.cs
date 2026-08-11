using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private FalconKeyGenerationParameters m_parameters;
        private SecureRandom m_random;
        private FalconNist m_nist;
        //private int m_pkSize;

        public void Init(KeyGenerationParameters param)
        {
            m_parameters = (FalconKeyGenerationParameters)param;
            m_random = param.Random;

            var falconParameters = m_parameters.Parameters;
            m_nist = new FalconNist(m_random, falconParameters.LogN, falconParameters.NonceLength);

            //int n = 1 << falconParameters.LogN;
            //int sk_coeff_size = 8;
            //if (n == 1024)
            //{
            //    sk_coeff_size = 5;
            //}
            //else if (n == 256 || n == 512)
            //{
            //    sk_coeff_size = 6;
            //}
            //else if (n == 64 || n == 128)
            //{
            //    sk_coeff_size = 7;
            //}

            //m_pkSize = 1 + (14 * n / 8);
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            m_nist.crypto_sign_keypair(out byte[] pk, out byte[] f, out byte[] g, out byte[] F);
            var falconParameters = m_parameters.Parameters;
            FalconPrivateKeyParameters privk = new FalconPrivateKeyParameters(falconParameters, f, g, F, pk);
            FalconPublicKeyParameters pubk = new FalconPublicKeyParameters(falconParameters, pk);
            return new AsymmetricCipherKeyPair(pubk, privk);
        }
    }
}
