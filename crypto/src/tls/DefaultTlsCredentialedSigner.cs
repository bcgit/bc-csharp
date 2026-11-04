using System;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Container class for generating signatures that carries the signature type, parameters, public key
    /// certificate and public key's associated signer object.</summary>
    public class DefaultTlsCredentialedSigner
        : TlsCredentialedSigner
    {
        /// <summary>The crypto params.</summary>
        protected readonly TlsCryptoParameters m_cryptoParams;
        /// <summary>The certificate.</summary>
        protected readonly Certificate m_certificate;
        /// <summary>The signature and hash algorithm.</summary>
        protected readonly SignatureAndHashAlgorithm m_signatureAndHashAlgorithm;
        /// <summary>The signer.</summary>
        protected readonly TlsSigner m_signer;

        /// <summary>Create a new <see cref="DefaultTlsCredentialedSigner"/>.</summary>
        /// <param name="cryptoParams">The crypto params.</param>
        /// <param name="signer">The signer.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="signatureAndHashAlgorithm">The signature and hash algorithm.</param>
        public DefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, TlsSigner signer,
            Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");
            if (certificate.IsEmpty)
                throw new ArgumentException("cannot be empty", "certificate");
            if (signer == null)
                throw new ArgumentNullException("signer");

            this.m_cryptoParams = cryptoParams;
            this.m_certificate = certificate;
            this.m_signatureAndHashAlgorithm = signatureAndHashAlgorithm;
            this.m_signer = signer;
        }

        /// <summary>Gets the certificate chain.</summary>
        public virtual Certificate Certificate
        {
            get { return m_certificate; }
        }

        /// <inheritdoc/>
        public virtual byte[] GenerateRawSignature(byte[] hash)
        {
            return m_signer.GenerateRawSignature(GetEffectiveAlgorithm(), hash);
        }

        /// <summary>Gets the signature and hash algorithm used for signing, if any.</summary>
        public virtual SignatureAndHashAlgorithm SignatureAndHashAlgorithm
        {
            get { return m_signatureAndHashAlgorithm; }
        }

        /// <inheritdoc/>
        public virtual TlsStreamSigner GetStreamSigner()
        {
            return m_signer.GetStreamSigner(GetEffectiveAlgorithm());
        }

        /// <summary>Return the effective algorithm.</summary>
        protected virtual SignatureAndHashAlgorithm GetEffectiveAlgorithm()
        {
            SignatureAndHashAlgorithm algorithm = null;
            if (TlsImplUtilities.IsTlsV12(m_cryptoParams))
            {
                algorithm = SignatureAndHashAlgorithm;
                if (algorithm == null)
                    throw new InvalidOperationException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
            }
            return algorithm;
        }
    }
}
