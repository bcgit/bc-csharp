using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /// <summary>HQC code-based KEM parameter sets (HQC-128, HQC-192, HQC-256).</summary>
    /// <remarks>
    /// Parameter sets of the HQC specification of 2026-10-12 (Tables 6, 8 and 9): n, n1, n2, k, delta, the weights
    /// omega and omega_r (= omega_e), the FFT exponent, the Barrett multiplier for n, the size of ekKEM and the
    /// Reed-Solomon generator polynomial over GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X + 1).
    /// </remarks>
    public sealed class HqcParameters
        : ICipherParameters
    {
        // TODO[api] Rename parameters instances and remove most properties

        /// <summary>HQC parameter set targeting 128-bit security.</summary>
        public static readonly HqcParameters hqc128 = new HqcParameters("HQC-128", 17669, 46, 384, 16, 15, 67, 76, 4,
            243079, 2241, new[]{
                74, 81, 224, 114, 221, 115, 110, 88, 91, 151, 139, 151, 84, 184, 21, 242, 97, 199, 87, 113, 104, 184,
                197, 111, 89, 81, 156, 71, 128, 217, 1 });

        /// <summary>HQC parameter set targeting 192-bit security.</summary>
        public static readonly HqcParameters hqc192 = new HqcParameters("HQC-192", 35851, 56, 640, 24, 16, 101, 114, 5,
            119800, 4514, new[]{
                56, 180, 145, 30, 131, 105, 28, 60, 107, 33, 206, 184, 155, 249, 153, 231, 112, 11, 231, 1, 144, 201,
                71, 62, 8, 150, 142, 246, 33, 214, 26, 150, 1 });

        /// <summary>HQC parameter set targeting 256-bit security.</summary>
        public static readonly HqcParameters hqc256 = new HqcParameters("HQC-256", 57637, 90, 640, 32, 29, 132, 150, 5,
            74517, 7237, new[]{
                35, 203, 35, 52, 165, 121, 125, 73, 136, 42, 235, 82, 232, 122, 67, 98, 51, 188, 230, 82, 164, 117,
                103, 184, 209, 218, 244, 181, 122, 10, 25, 138, 216, 182, 225, 145, 100, 244, 5, 142, 213, 238, 15,
                150, 59, 28, 244, 222, 252, 85, 125, 59, 52, 215, 180, 34, 173, 208, 1 });

        internal const int PARAM_M = 8;
        internal const int GF_MUL_ORDER = 255;

        private readonly string m_name;
        private readonly int m_n;
        private readonly int m_n1;
        private readonly int m_n2;

        private readonly int m_publicKeyBytes;

        private readonly HqcEngine m_engine;

        private HqcParameters(string name, int n, int n1, int n2, int k, int delta, int w, int wr, int fft,
            int nMu, int pkSize, int[] generatorPoly)
        {
            m_name = name;
            m_n = n;
            m_n1 = n1;
            m_n2 = n2;
            m_publicKeyBytes = pkSize;
            m_engine = new HqcEngine(n, n1, n2, k, delta, w, wr, fft, nMu, pkSize, generatorPoly);
        }

        internal int Sha512Bytes => 512 / 8;

        internal int SaltSizeBytes => 16;

        internal int NBytes => (m_n + 7) / 8;

        internal int N1N2Bytes => (m_n1 * m_n2 + 7) / 8;

        internal HqcEngine Engine => m_engine;

        /// <summary>The length, in bytes, of an HQC ciphertext (encapsulation).</summary>
        public int EncapsulationLength => m_engine.CipherTextBytes;

        /// <summary>The session (shared) key size, in bits.</summary>
        public int SessionKeySize => 32 * 8;

        /// <summary>The name of this parameter set.</summary>
        public string Name => m_name;

        /// <summary>The length, in bytes, of an HQC public key.</summary>
        public int PublicKeyBytes => m_publicKeyBytes;

        /// <summary>The length, in bytes, of an HQC private key.</summary>
        /// <remarks>
        /// The decapsulation key encoding is the 32-byte seedKEM from which the whole key pair is derived, which is
        /// the only dkKEM format of the HQC specification of 2026-10-12.
        /// </remarks>
        public int SecretKeyBytes => HqcEngine.SeedBytes;

        /// <summary>The length, in bytes, of the shared secret.</summary>
        public int SecretLength => HqcEngine.SharedSecretBytes;

        /// <inheritdoc/>
        public override string ToString() => Name;
    }
}
