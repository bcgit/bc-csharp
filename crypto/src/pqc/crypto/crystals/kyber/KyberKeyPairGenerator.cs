using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public class KyberKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private KyberParameters KyberParams;
        
        private SecureRandom random;

        private void Initialize(
            KeyGenerationParameters param)
        {
            this.KyberParams = ((KyberKeyGenerationParameters)param).Parameters;;
            this.random = param.Random; 
        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            KyberEngine engine = KyberParams.Engine;
            engine.Init(random);
            byte[] s, hpk, nonce, t, rho;
            engine.GenerateKemKeyPair(out t, out rho, out s, out hpk, out nonce);

            KyberPublicKeyParameters pubKey = new KyberPublicKeyParameters(KyberParams, t, rho);
            KyberPrivateKeyParameters privKey = new KyberPrivateKeyParameters(KyberParams, s, hpk, nonce, t, rho);
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