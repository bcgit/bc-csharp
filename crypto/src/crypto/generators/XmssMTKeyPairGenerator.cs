using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>Key pair generator for XMSS^MT keys (RFC 8391).</summary>
    public sealed class XmssMTKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private XmssMTParameters m_parameters;
        private SecureRandom m_random;

        /// <summary>
        /// Initialise with an <see cref="XmssMTKeyGenerationParameters"/> instance; the <see cref="SecureRandom"/> and
        /// parameter set are taken from it.
        /// </summary>
        /// <exception cref="System.InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="XmssMTKeyGenerationParameters"/>.</exception>
        public void Init(KeyGenerationParameters parameters)
        {
            XmssMTKeyGenerationParameters xmssMTParameters = (XmssMTKeyGenerationParameters)parameters;

            m_random = xmssMTParameters.Random;
            m_parameters = xmssMTParameters.Parameters;
        }

        /// <summary>Generate a new XMSS^MT private key / public key pair.</summary>
        public AsymmetricCipherKeyPair GenerateKeyPair() => XmssEngine.GenerateMTKeyPair(m_parameters, m_random);
    }
}
