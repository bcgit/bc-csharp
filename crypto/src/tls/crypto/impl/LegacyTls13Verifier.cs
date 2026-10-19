using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    public sealed class LegacyTls13Verifier
        : TlsVerifier
    {
        private readonly int m_signatureScheme;
        private readonly Tls13Verifier m_tls13Verifier;

        /// <summary>Create a new <see cref="LegacyTls13Verifier"/>.</summary>
        /// <param name="signatureScheme">The signature scheme.</param>
        /// <param name="tls13Verifier">The tls 13 verifier.</param>
        public LegacyTls13Verifier(int signatureScheme, Tls13Verifier tls13Verifier)
        {
            if (!TlsUtilities.IsValidUint16(signatureScheme))
                throw new ArgumentException("Expected SignatureScheme (uint16)", nameof(signatureScheme));

            m_signatureScheme = signatureScheme;
            m_tls13Verifier = tls13Verifier ?? throw new ArgumentNullException(nameof(tls13Verifier));
        }

        /// <inheritdoc/>
        public TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            return new TlsStreamVerifierImpl(m_tls13Verifier, digitallySigned.Signature);
        }

        /// <inheritdoc/>
        public bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash) =>
            throw new NotSupportedException();

        private class TlsStreamVerifierImpl
            : TlsStreamVerifier
        {
            private readonly Tls13Verifier m_tls13Verifier;
            private readonly byte[] m_signature;

            internal TlsStreamVerifierImpl(Tls13Verifier tls13Verifier, byte[] signature)
            {
                m_tls13Verifier = tls13Verifier;
                m_signature = signature;
            }

            public Stream Stream => m_tls13Verifier.Stream;

            public bool IsVerified() => m_tls13Verifier.VerifySignature(m_signature);
        }
    }
}
