using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    public sealed class CmceKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private CmceKeyGenerationParameters m_cmceParams;

        private SecureRandom random;

        private void Initialize(
            KeyGenerationParameters param)
        {
            this.m_cmceParams = (CmceKeyGenerationParameters) param;
            this.random = param.Random;
        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            CmceEngine engine = m_cmceParams.Parameters.Engine;
            byte[] sk = new byte[engine.PrivateKeySize];
            byte[] pk = new byte[engine.PublicKeySize];
            engine.kem_keypair(pk, sk, random);

            CmcePublicKeyParameters pubKey = new CmcePublicKeyParameters(m_cmceParams.Parameters, pk);
            CmcePrivateKeyParameters privKey = new CmcePrivateKeyParameters(m_cmceParams.Parameters, sk);
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
