using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberParameters
        : ICipherParameters
    {
        public static KyberParameters kyber512 = new KyberParameters("kyber512", 2);
        public static KyberParameters kyber768 = new KyberParameters("kyber768", 3);
        public static KyberParameters kyber1024 = new KyberParameters("kyber1024", 4);

        private string m_name;
        private KyberEngine m_engine;

        public KyberParameters(string name, int k)
        {
            m_name = name;
            m_engine = new KyberEngine(k);
        }

        public string Name => m_name;

        public int K => m_engine.K;

        public int DefaultKeySize => 64 * m_engine.K;

        internal KyberEngine Engine => m_engine;
    }
}
