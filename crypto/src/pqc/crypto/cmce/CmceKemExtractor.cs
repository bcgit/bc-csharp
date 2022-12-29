using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    public sealed class CmceKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private ICmceEngine engine;

        private CmceKeyParameters key;

        public CmceKemExtractor(CmcePrivateKeyParameters privParams)
        {
            this.key = privParams;
            InitCipher(key.Parameters);
        }

        private void InitCipher(CmceParameters param)
        {
            engine = param.Engine;
            CmcePrivateKeyParameters privateParams = (CmcePrivateKeyParameters)key;
            if (privateParams.privateKey.Length < engine.PrivateKeySize)
            {
                key = new CmcePrivateKeyParameters(privateParams.Parameters,
                    engine.DecompressPrivateKey(privateParams.privateKey));
            }
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            return ExtractSecret(encapsulation, engine.DefaultSessionKeySize);
        }

        private byte[] ExtractSecret(byte[] encapsulation, int sessionKeySizeInBits)
        {
            byte[] session_key = new byte[sessionKeySizeInBits / 8];
            engine.KemDec(session_key, encapsulation, ((CmcePrivateKeyParameters)key).privateKey);
            return session_key;
        }

        public int EncapsulationLength => engine.CipherTextSize;
    }
}
