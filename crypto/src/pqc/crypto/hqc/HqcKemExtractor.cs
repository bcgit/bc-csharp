using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly HqcPrivateKeyParameters m_privateKey;

        private HqcEngine m_engine;

        public HqcKemExtractor(HqcPrivateKeyParameters privParams)
        {
            m_privateKey = privParams;
            InitCipher(m_privateKey.Parameters);
        }

        private void InitCipher(HqcParameters param)
        {
            m_engine = param.Engine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[m_engine.GetSessionKeySize()];
            m_engine.Decaps(ss: session_key, ct: encapsulation, sk: m_privateKey.PrivateKey);
            return session_key;
        }

        public int EncapsulationLength => Parameters.NBytes + Parameters.N1n2Bytes + 16;

        private HqcParameters Parameters => m_privateKey.Parameters;
    }
}
