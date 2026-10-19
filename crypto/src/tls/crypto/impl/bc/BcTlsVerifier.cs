using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Base class for TLS signature verifiers using the Bouncy Castle implementation.</summary>
    public abstract class BcTlsVerifier
        : TlsVerifier
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly AsymmetricKeyParameter m_publicKey;

        /// <summary>Create a new <see cref="BcTlsVerifier"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="publicKey">The public key.</param>
        protected BcTlsVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter publicKey)
        {
            if (crypto == null)
                throw new ArgumentNullException(nameof(crypto));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("must be public", nameof(publicKey));

            m_crypto = crypto;
            m_publicKey = publicKey;
        }

        /// <inheritdoc/>
        public virtual TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned) => null;

        /// <inheritdoc/>
        public virtual bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash) =>
            throw new NotSupportedException();
    }
}
