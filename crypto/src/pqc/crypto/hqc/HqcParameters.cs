using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcParameters
        : ICipherParameters
    {
        // TODO[api] Rename parameters instances and remove most properties

        // 128 bits security
        public static readonly HqcParameters hqc128 = new HqcParameters("HQC-128", 17669, 46, 384, 16, 31, 15, 66, 75, 75, 4,
            new[]{ 89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1 });

        // 192 bits security
        public static readonly HqcParameters hqc192 = new HqcParameters("HQC-192", 35851, 56, 640, 24, 33, 16, 100, 114, 114, 5,
            new[]{ 45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1 });

        // 256 bits security
        public static readonly HqcParameters hqc256 = new HqcParameters("HQC-256", 57637, 90, 640, 32, 59, 29, 131, 149, 149, 5,
            new[]{ 49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1 });

        internal const int PARAM_M = 8;
        internal const int GF_MUL_ORDER = 255;

        private readonly string m_name;
        private readonly int m_n;
        private readonly int m_n1;
        private readonly int m_n2;
        private readonly int m_k;
        private readonly int m_delta;
        private readonly int m_w;
        private readonly int m_wr;
        private readonly int m_we;

        private readonly HqcEngine m_engine;

        private HqcParameters(string name, int n, int n1, int n2, int k, int g, int delta, int w, int wr, int we, int fft, int[] generatorPoly)
        {
            m_name = name;
            m_n = n;
            m_n1 = n1;
            m_n2 = n2;
            m_k = k;
            m_delta = delta;
            m_w = w;
            m_wr = wr;
            m_we = we;

            m_engine = new HqcEngine(n, n1, n2, k, g, delta, w, wr, we, fft, generatorPoly);
        }

        public int EncapsulationLength => m_engine.CipherTextBytes;

        internal HqcEngine Engine => m_engine;

        public string Name => m_name;

        public int SecretLength => HqcEngine.SharedSecretBytes;

        public int N => m_n;
        public int K => m_k;
        public int Delta => m_delta;
        public int W => m_w;
        public int Wr => m_wr;
        public  int We => m_we;
        public int N1 => m_n1;
        public int N2 => m_n2;
        public int Sha512Bytes => 512 / 8;
        public int NBytes => (m_n + 7) / 8;
        // TODO[api] Rename to N1N2Bytes
        public int N1n2Bytes => (m_n1 * m_n2 + 7) / 8;
        public int SaltSizeBytes => 16;
    }
}
