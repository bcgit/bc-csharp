using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>An Ed25519 signer for TLS, using the Bouncy Castle implementation.</summary>
    public class BcTlsEd25519Signer
        : BcTlsSigner
    {
        /// <summary>Create a new <see cref="BcTlsEd25519Signer"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="privateKey">The private key.</param>
        public BcTlsEd25519Signer(BcTlsCrypto crypto, Ed25519PrivateKeyParameters privateKey)
            : base(crypto, privateKey)
        {
        }

        /// <inheritdoc/>
        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.ed25519)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            Ed25519Signer signer = new Ed25519Signer();
            signer.Init(true, m_privateKey);

            return new BcTlsStreamSigner(signer);
        }
    }
}
