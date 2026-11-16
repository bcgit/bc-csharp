using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    /// <summary>Extracts the shared secret from an encapsulation, for SABER.</summary>
    public sealed class SaberKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly SaberKeyParameters key;

        private SaberEngine engine;

        /// <summary>Create a new <see cref="SaberKemExtractor"/>.</summary>
        /// <param name="privParams">The priv params.</param>
        public SaberKemExtractor(SaberKeyParameters privParams)
        {
            this.key = privParams;
            InitCipher(key.Parameters);
        }

        private void InitCipher(SaberParameters param)
        {
            engine = param.Engine;
        }

        /// <inheritdoc/>
        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[engine.GetSessionKeySize()];
            engine.crypto_kem_dec(session_key, encapsulation, ((SaberPrivateKeyParameters) key).GetPrivateKey());
            return session_key;
        }

        /// <inheritdoc/>
        public int EncapsulationLength => engine.GetCipherTextSize();
    }
}
