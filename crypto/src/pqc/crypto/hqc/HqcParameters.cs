using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcParameters
        : ICipherParameters
    {
        // TODO[api] Rename parameters instances and remove most properties

        // 128 bits security
        public static readonly HqcParameters hqc128 = new HqcParameters("HQC-128", 17669, 46, 384, 16, 31, 15, 66, 75, 4, 243079, 2241, 2321,
            new[]{ 89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1 });

        // 192 bits security
        public static readonly HqcParameters hqc192 = new HqcParameters("HQC-192", 35851, 56, 640, 24, 33, 16, 100, 114, 5, 119800, 4514, 4602,
            new[]{ 45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1 });

        // 256 bits security
        public static readonly HqcParameters hqc256 = new HqcParameters("HQC-256", 57637, 90, 640, 32, 59, 29, 131, 149, 5, 74517, 7237, 7333,
            new[]{ 49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1 });

        internal const int PARAM_M = 8;
        internal const int GF_MUL_ORDER = 255;

        private readonly string m_name;
        private readonly int m_n;
        private readonly int m_n1;
        private readonly int m_n2;

        private readonly int m_publicKeyBytes;
        private readonly int m_secretKeyBytes;

        private readonly HqcEngine m_engine;

        private HqcParameters(string name, int n, int n1, int n2, int k, int g, int delta, int w, int wr, int fft,
            int nMu, int pkSize, int skSize, int[] generatorPoly)
        {
            m_name = name;
            m_n = n;
            m_n1 = n1;
            m_n2 = n2;
            m_publicKeyBytes = pkSize;
            m_secretKeyBytes = skSize;
            m_engine = new HqcEngine(n, n1, n2, k, g, delta, w, wr, fft, nMu, pkSize, generatorPoly);
        }

        internal int Sha512Bytes => 512 / 8;

        internal int SaltSizeBytes => 16;

        internal int NBytes => (m_n + 7) / 8;

        internal int N1N2Bytes => (m_n1 * m_n2 + 7) / 8;

        internal HqcEngine Engine => m_engine;

        public int EncapsulationLength => m_engine.CipherTextBytes;

        public int SessionKeySize => 32 * 8;

        public string Name => m_name;

        public int PublicKeyBytes => m_publicKeyBytes;

        public int SecretKeyBytes => m_secretKeyBytes;

        public int SecretLength => HqcEngine.SharedSecretBytes;

        public override string ToString() => Name;
    }
}
