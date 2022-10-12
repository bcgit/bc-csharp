
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public class SaberKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private SABEREngine engine;

        private SaberKeyParameters key;

        public SaberKemExtractor(SaberKeyParameters privParams)
        {
            this.key = privParams;
            InitCipher(key.GetParameters());
        }

        private void InitCipher(SaberParameters param)
        {
            engine = param.GetEngine();
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[engine.GetSessionKeySize()];
            engine.crypto_kem_dec(session_key, encapsulation, ((SaberPrivateKeyParameters) key).GetPrivateKey());
            return session_key;
        }

        public int EncapsulationLength => engine.GetCipherTextSize();
    }
}