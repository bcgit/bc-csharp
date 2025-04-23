using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcParameters
        : ICipherParameters
    {
        // 128 bits security
        public static HqcParameters hqc128 = new HqcParameters("hqc128", 17669, 46, 384, 16, 31, 15, 66, 75, 75, 16767881, 4, new[] { 89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1 }, 128);

        // 192 bits security
        public static HqcParameters hqc192 = new HqcParameters("hqc192", 35851, 56, 640, 24, 33, 16, 100, 114, 114, 16742417, 5, new[] { 45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1 }, 192);

        // 256 bits security
        public static HqcParameters hqc256 = new HqcParameters("hqc256", 57637, 90, 640, 32, 59, 29, 131, 149, 149, 16772367, 5, new[] { 49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1 }, 256);

        private string name;
        private int n;
        private int n1;
        private int n2;
        private int k;
        private int g;
        private int delta;
        private int w;
        private int wr;
        private int we;
        private int utilRejectionThreshold;
        private int fft;

        private int[] generatorPoly;
        private int defaultKeySize;

        internal const int PARAM_M = 8;
        internal const int GF_MUL_ORDER = 255;

        private HqcEngine hqcEngine;

        private HqcParameters(string name, int n, int n1, int n2, int k, int g, int delta, int w, int wr, int we, int utilRejectionThreshold, int fft, int[] generatorPoly, int defaultKeySize)
        {
            this.name = name;
            this.n = n;
            this.n1 = n1;
            this.n2 = n2;
            this.k = k;
            this.delta = delta;
            this.w = w;
            this.wr = wr;
            this.we = we;
            this.generatorPoly = generatorPoly;
            this.g = g;
            this.utilRejectionThreshold = utilRejectionThreshold;
            this.fft = fft;
            this.defaultKeySize = defaultKeySize;
            hqcEngine = new HqcEngine(n, n1, n2, k, g, delta, w, wr, we, utilRejectionThreshold, fft, generatorPoly);
        }

        public int N => n;
        public int K => k;
        public int Delta => delta;
        public int W => w;
        public int Wr => wr;
        public  int We => we;
        public int N1 => n1;
        public int N2 => n2;
        public int Sha512Bytes => 512 / 8;
        public int NBytes => (n + 7) / 8;
        // TODO[api] Rename to N1N2Bytes
        public int N1n2Bytes => (n1 * n2 + 7) / 8;
        public int DefaultKeySize => defaultKeySize;
        public int SaltSizeBytes => 16;
        internal HqcEngine Engine => hqcEngine;
    }
}
