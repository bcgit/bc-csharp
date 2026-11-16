using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    /// <summary>Extracts the shared secret from an encapsulation, for NTRU LPRime.</summary>
    public class NtruLPRimeKemExtractor : IEncapsulatedSecretExtractor
    {
        private NtruPrimeEngine _primeEngine;
        private readonly NtruLPRimeKeyParameters _primeKey;

        /// <summary>Create a new <see cref="NtruLPRimeKemExtractor"/>.</summary>
        /// <param name="privParams">The priv params.</param>
        public NtruLPRimeKemExtractor(NtruLPRimeKeyParameters privParams)
        {
            this._primeKey = privParams;
            InitCipher(_primeKey.Parameters);
        }

        private void InitCipher(NtruLPRimeParameters param)
        {
            _primeEngine = param.PrimeEngine;
        }

        /// <inheritdoc/>
        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[_primeEngine.SessionKeySize];
            _primeEngine.kem_dec(session_key, encapsulation, ((NtruLPRimePrivateKeyParameters)_primeKey).privKey);
            return session_key;
        }

        /// <inheritdoc/>
        public int EncapsulationLength => _primeEngine.CipherTextSize;
    }
}
