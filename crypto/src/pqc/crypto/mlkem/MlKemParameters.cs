namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemParameters
        : IKemParameters
    {
        public static readonly MLKemParameters ML_KEM_512 = new MLKemParameters("ML-KEM-512", 2);
        public static readonly MLKemParameters ML_KEM_768 = new MLKemParameters("ML-KEM-768", 3);
        public static readonly MLKemParameters ML_KEM_1024 = new MLKemParameters("ML-KEM-1024", 4);

        private readonly string m_name;
        private readonly int m_k;

        private MLKemParameters(string name, int k)
        {
            m_name = name;
            m_k = k;
        }

        public string Name => m_name;

        public int K => m_k;

        public int SessionKeySize => 256;

        internal MLKemEngine GetEngine() => new MLKemEngine(m_k);
    }
}
