using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A TLS 1.3 CertificateVerify message.</summary>
    public sealed class CertificateVerify
    {
        private readonly int m_algorithm;
        private readonly byte[] m_signature;

        /// <summary>Create a new <see cref="CertificateVerify"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="signature">The signature.</param>
        public CertificateVerify(int algorithm, byte[] signature)
        {
            if (!TlsUtilities.IsValidUint16(algorithm))
                throw new ArgumentException("Expected SignatureScheme (uint16)", nameof(algorithm));
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));

            m_algorithm = algorithm;
            m_signature = signature;
        }

        /// <returns>a <see cref="SignatureScheme"/> value.</returns>
        public int Algorithm => m_algorithm;

        /// <summary>Gets the signature.</summary>
        public byte[] Signature => m_signature;

        /// <summary>Encode this <see cref="CertificateVerify"/> to a <see cref="Stream"/>.</summary>
        /// <param name="output">the <see cref="Stream"/> to encode to.</param>
        /// <exception cref="IOException"/>
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint16(m_algorithm, output);
            TlsUtilities.WriteOpaque16(m_signature, output);
        }

        /// <summary>Parse a <see cref="CertificateVerify"/> from a <see cref="Stream"/>.</summary>
        /// <param name="context">the <see cref="TlsContext"/> of the current connection.</param>
        /// <param name="input">the <see cref="Stream"/> to parse from.</param>
        /// <returns>a <see cref="CertificateVerify"/> object.</returns>
        /// <exception cref="IOException"/>
        public static CertificateVerify Parse(TlsContext context, Stream input)
        {
            if (!TlsUtilities.IsTlsV13(context))
                throw new InvalidOperationException();

            int algorithm = TlsUtilities.ReadUint16(input);
            byte[] signature = TlsUtilities.ReadOpaque16(input);
            return new CertificateVerify(algorithm, signature);
        }
    }
}
