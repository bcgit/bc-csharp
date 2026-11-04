using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>An SLH-DSA signer for TLS, using the Bouncy Castle implementation.</summary>
    public class BcTlsSlhDsaSigner
        : BcTlsSigner
    {
        /// <summary>Create an SLH-DSA signer for a signature scheme.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="signatureScheme">The signature scheme.</param>
        /// <returns>The signer.</returns>
        public static BcTlsSlhDsaSigner Create(BcTlsCrypto crypto, SlhDsaPrivateKeyParameters privateKey, int signatureScheme)
        {
            if (signatureScheme != PqcUtilities.GetSlhDsaSignatureScheme(privateKey.Parameters))
                return null;

            return new BcTlsSlhDsaSigner(crypto, privateKey, signatureScheme);
        }

        private readonly int m_signatureScheme;

        private BcTlsSlhDsaSigner(BcTlsCrypto crypto, SlhDsaPrivateKeyParameters privateKey, int signatureScheme)
            : base(crypto, privateKey)
        {
            if (!SignatureScheme.IsSlhDsa(signatureScheme))
                throw new ArgumentException($"{SignatureScheme.GetText(signatureScheme)} is not SLH-DSA",
                    nameof(signatureScheme));

            m_signatureScheme = signatureScheme;
        }

        /// <inheritdoc/>
        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            var slhDsaAlgOid = PqcUtilities.GetSlhDsaObjectidentifier(m_signatureScheme);

            /*
             * draft-reddy-tls-slhdsa-01 2. [..], the context parameter [..] MUST be set to the empty string.
             */
            var signer = SignerUtilities.InitSigner(slhDsaAlgOid, forSigning: true, m_privateKey, m_crypto.SecureRandom);

            return new BcTlsStreamSigner(signer);
        }
    }
}
