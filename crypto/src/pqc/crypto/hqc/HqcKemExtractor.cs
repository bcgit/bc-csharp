using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKemExtractor : IEncapsulatedSecretExtractor
    {
        private HqcEngine engine;

        private HqcKeyParameters key;

        public HqcKemExtractor(HqcPrivateKeyParameters privParams)
        {
            this.key = privParams;
            InitCipher(key.Parameters);
        }

        private void InitCipher(HqcParameters param)
        {
            engine = param.Engine;
        }

        
        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[engine.GetSessionKeySize()];
            HqcPrivateKeyParameters secretKey = (HqcPrivateKeyParameters)key;
            byte[] sk = secretKey.PrivateKey;

            engine.Decaps(session_key, encapsulation, sk);

            return session_key;
        }

        public int EncapsulationLength => key.Parameters.NBytes + key.Parameters.N1n2Bytes + 64;
 
    }
}
