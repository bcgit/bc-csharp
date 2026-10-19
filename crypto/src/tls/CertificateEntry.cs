using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>An entry of a TLS 1.3 certificate message: a certificate together with its extensions.</summary>
    public sealed class CertificateEntry
    {
        private readonly TlsCertificate m_certificate;
        private readonly IDictionary<int, byte[]> m_extensions;

        /// <summary>Create a new <see cref="CertificateEntry"/>.</summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="extensions">The extensions.</param>
        public CertificateEntry(TlsCertificate certificate, IDictionary<int, byte[]> extensions)
        {
            m_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            m_extensions = extensions;
        }

        /// <summary>Gets the certificate.</summary>
        public TlsCertificate Certificate => m_certificate;

        /// <summary>Gets the extensions.</summary>
        public IDictionary<int, byte[]> Extensions => m_extensions;
    }
}
