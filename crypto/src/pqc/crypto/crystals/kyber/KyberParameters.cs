using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberParameters
        : IKemParameters
    {
        public static KyberParameters kyber512 = new KyberParameters("kyber512", 2, 128, false);
        public static KyberParameters kyber768 = new KyberParameters("kyber768", 3, 192, false);
        public static KyberParameters kyber1024 = new KyberParameters("kyber1024", 4, 256, false);

        private string m_name;
        private int m_sessionKeySize;
        private KyberEngine m_engine;

        private KyberParameters(string name, int k, int sessionKeySize, bool usingAes)
        {
            m_name = name;
            this.m_sessionKeySize = sessionKeySize;
            m_engine = new KyberEngine(k, usingAes);
        }

        public string Name => m_name;

        public int K => m_engine.K;

        public int SessionKeySize => m_sessionKeySize;

        internal KyberEngine Engine => m_engine;
    }
}
