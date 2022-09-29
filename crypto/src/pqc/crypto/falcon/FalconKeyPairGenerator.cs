using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private FalconKeyGenerationParameters parameters;
        private SecureRandom random;
        private FalconNIST nist;
        private uint logn;
        private uint noncelen;

        private int pk_size;

        public void Init(KeyGenerationParameters param)
        {
            this.parameters = (FalconKeyGenerationParameters)param;
            this.random = param.Random;
            this.logn = ((FalconKeyGenerationParameters)param).Parameters.LogN;
            this.noncelen = ((FalconKeyGenerationParameters)param).Parameters.NonceLength;
            this.nist = new FalconNIST(random, logn, noncelen);
            int n = 1 << (int)this.logn;
            int sk_coeff_size = 8;
            if (n == 1024)
            {
                sk_coeff_size = 5;
            }
            else if (n == 256 || n == 512)
            {
                sk_coeff_size = 6;
            }
            else if (n == 64 || n == 128)
            {
                sk_coeff_size = 7;
            }

            this.pk_size = 1 + (14 * n / 8);
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            byte[] pk, sk, f, g, F;
            nist.crypto_sign_keypair(out pk, out f, out g, out F);
            FalconParameters p = ((FalconKeyGenerationParameters)this.parameters).Parameters;
            FalconPrivateKeyParameters privk = new FalconPrivateKeyParameters(p, f, g, F, pk);
            FalconPublicKeyParameters pubk = new FalconPublicKeyParameters(p, pk);
            return new AsymmetricCipherKeyPair(pubk, privk);
        }
    }
}
