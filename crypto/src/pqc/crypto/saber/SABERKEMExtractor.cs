using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly SaberKeyParameters key;

        private SaberEngine engine;

        public SaberKemExtractor(SaberKeyParameters privParams)
        {
            this.key = privParams;
            InitCipher(key.Parameters);
        }

        private void InitCipher(SaberParameters param)
        {
            engine = param.Engine;
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
