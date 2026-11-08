using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>Key pair generator for XMSS keys (RFC 8391).</summary>
    public sealed class XmssKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private XmssParameters m_parameters;
        private SecureRandom m_random;

        /// <summary>
        /// Initialise with an <see cref="XmssKeyGenerationParameters"/> instance; the <see cref="SecureRandom"/> and
        /// parameter set are taken from it.
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="XmssKeyGenerationParameters"/>.</exception>
        public void Init(KeyGenerationParameters parameters)
        {
            XmssKeyGenerationParameters xmssParameters = (XmssKeyGenerationParameters)parameters;

            m_random = xmssParameters.Random;
            m_parameters = xmssParameters.Parameters;
        }

        /// <summary>Generate a new XMSS private key / public key pair.</summary>
        public AsymmetricCipherKeyPair GenerateKeyPair() => XmssEngine.GenerateKeyPair(m_parameters, m_random);
    }
}
