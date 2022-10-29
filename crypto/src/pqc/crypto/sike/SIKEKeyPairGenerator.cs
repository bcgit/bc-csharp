using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    public sealed class SikeKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SikeKeyGenerationParameters sikeParams;

        private SecureRandom random;

        private void Initialize(KeyGenerationParameters param)
        {
            this.sikeParams = (SikeKeyGenerationParameters) param;
            this.random = param.Random;
        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            SikeEngine engine = sikeParams.Parameters.Engine;
            byte[] sk = new byte[engine.GetPrivateKeySize()];
            byte[] pk = new byte[engine.GetPublicKeySize()];

            engine.crypto_kem_keypair(pk, sk, random);

            SikePublicKeyParameters pubKey = new SikePublicKeyParameters(sikeParams.Parameters, pk);
            SikePrivateKeyParameters privKey = new SikePrivateKeyParameters(sikeParams.Parameters, sk);
            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        public void Init(KeyGenerationParameters param)
        {
            this.Initialize(param);
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenKeyPair();
        }
    }
}
