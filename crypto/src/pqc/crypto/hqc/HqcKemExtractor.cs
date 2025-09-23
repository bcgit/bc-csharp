using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly HqcPrivateKeyParameters m_privateKey;
        private readonly HqcEngine m_engine;

        public HqcKemExtractor(HqcPrivateKeyParameters privParams)
        {
            m_privateKey = privParams;
            m_engine = privParams.Parameters.Engine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[64];
            m_engine.Decaps(ss: session_key, ct: encapsulation, sk: m_privateKey.InternalPrivateKey);
            return session_key;
        }

        public int EncapsulationLength => Parameters.NBytes + Parameters.N1n2Bytes + 16;

        private HqcParameters Parameters => m_privateKey.Parameters;
    }
}
