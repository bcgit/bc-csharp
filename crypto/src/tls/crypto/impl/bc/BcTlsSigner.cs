using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Base class for TLS signers using the Bouncy Castle implementation.</summary>
    public abstract class BcTlsSigner
        : TlsSigner
    {
        /// <summary>The crypto.</summary>
        protected readonly BcTlsCrypto m_crypto;
        /// <summary>The private key.</summary>
        protected readonly AsymmetricKeyParameter m_privateKey;

        /// <summary>Create a new <see cref="BcTlsSigner"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="privateKey">The private key.</param>
        protected BcTlsSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)
        {
            if (crypto == null)
                throw new ArgumentNullException(nameof(crypto));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            if (!privateKey.IsPrivate)
                throw new ArgumentException("must be private", nameof(privateKey));

            m_crypto = crypto;
            m_privateKey = privateKey;
        }

        /// <inheritdoc/>
        public virtual byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) =>
            throw new NotSupportedException();

        /// <inheritdoc/>
        public virtual TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm) => null;
    }
}
