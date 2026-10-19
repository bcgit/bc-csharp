using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>Extracts the shared secret from an encapsulation, for Streamlined NTRU Prime.</summary>
    public class SNtruPrimeKemExtractor : IEncapsulatedSecretExtractor
    {
        private NtruPrimeEngine _primeEngine;
        private readonly SNtruPrimeKeyParameters _primeKey;

        /// <summary>Create a new <see cref="SNtruPrimeKemExtractor"/>.</summary>
        /// <param name="privParams">The priv params.</param>
        public SNtruPrimeKemExtractor(SNtruPrimeKeyParameters privParams)
        {
            this._primeKey = privParams;
            InitCipher(_primeKey.Parameters);
        }

        private void InitCipher(SNtruPrimeParameters param)
        {
            _primeEngine = param.PrimeEngine;
        }

        /// <inheritdoc/>
        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[_primeEngine.SessionKeySize];
            _primeEngine.kem_dec(session_key, encapsulation, ((SNtruPrimePrivateKeyParameters)_primeKey).privKey);
            return session_key;
        }

        /// <inheritdoc/>
        public int EncapsulationLength => _primeEngine.CipherTextSize;
    }
}
