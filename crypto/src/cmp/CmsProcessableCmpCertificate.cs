using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>Carrier class for a <see cref="CmpCertificate"/> over CMS.</summary>
    public sealed class CmsProcessableCmpCertificate
        : CmsTypedData
    {
        private readonly CmpCertificate m_cmpCertificate;

        /// <summary>Wrap an X.509 certificate.</summary>
        /// <param name="certificate">The certificate.</param>
        public CmsProcessableCmpCertificate(X509Certificate certificate)
            : this(new CmpCertificate(certificate.CertificateStructure))
        {
        }

        /// <summary>Wrap a CMP certificate.</summary>
        /// <param name="cmpCertificate">The certificate.</param>
        /// <exception cref="ArgumentNullException"><paramref name="cmpCertificate"/> is null.</exception>
        public CmsProcessableCmpCertificate(CmpCertificate cmpCertificate)
        {
            m_cmpCertificate = cmpCertificate ?? throw new ArgumentNullException(nameof(cmpCertificate));
        }

        /// <summary>Write the encoded certificate to the stream.</summary>
        /// <param name="outStream">The stream to write to.</param>
        public void Write(Stream outStream)
        {
            m_cmpCertificate.EncodeTo(outStream);
        }

        /// <summary>Gets the content type, which is always <c>data</c>.</summary>
        public DerObjectIdentifier ContentType => PkcsObjectIdentifiers.Data;
    }
}
