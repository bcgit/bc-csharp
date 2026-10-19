using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    // TODO[api] FrodoKemExtractor
    public class FrodoKEMExtractor
            : IEncapsulatedSecretExtractor
    {
        private readonly FrodoKeyParameters m_key;
        private readonly FrodoEngine m_engine;

        /// <summary>Create a new <see cref="FrodoKEMExtractor"/>.</summary>
        /// <param name="privParams">The priv params.</param>
        public FrodoKEMExtractor(FrodoKeyParameters privParams)
        {
            m_key = privParams;
#pragma warning disable CS0618 // Type or member is obsolete
            m_engine = privParams.Parameters.Engine;
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <inheritdoc/>
        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[m_engine.SessionKeySize];
            m_engine.kem_dec(session_key, encapsulation, ((FrodoPrivateKeyParameters)m_key).privateKey);
            return session_key;
        }

        /// <inheritdoc/>
        public int EncapsulationLength => m_engine.CipherTextSize;
    }
}
