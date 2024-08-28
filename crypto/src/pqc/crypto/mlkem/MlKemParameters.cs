namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemParameters
        : IKemParameters
    {
        public static readonly MLKemParameters ML_KEM_512 = new MLKemParameters("ML-KEM-512", 2, 256);
        public static readonly MLKemParameters ML_KEM_768 = new MLKemParameters("ML-KEM-768", 3, 256);
        public static readonly MLKemParameters ML_KEM_1024 = new MLKemParameters("ML-KEM-1024", 4, 256);

        private readonly string m_name;
        private readonly int m_sessionKeySize;
        private readonly MLKemEngine m_engine;

        private MLKemParameters(string name, int k, int sessionKeySize)
        {
            m_name = name;
            this.m_sessionKeySize = sessionKeySize;
            m_engine = new MLKemEngine(k);
        }

        public string Name => m_name;

        public int K => m_engine.K;

        public int SessionKeySize => m_sessionKeySize;

        internal MLKemEngine Engine => m_engine;
    }
}
